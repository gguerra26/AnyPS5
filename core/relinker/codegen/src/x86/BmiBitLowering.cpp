#include <codegen/x86/BmiBitLowering.hpp>
#include <codegen/CodegenException.hpp>
#include <algorithm>
#include <array>
#include <limits>

namespace Codegen {

namespace {

constexpr std::int32_t kFrameSize = 160;
constexpr std::uint8_t kStack = 4;

bool _prefix(std::uint8_t value) {
    return value == 0x2E || value == 0x36 || value == 0x3E || value == 0x26 || value == 0x64 || value == 0x65 || value == 0x67;
}

void _append32(std::vector<std::uint8_t>& bytes, std::int32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8)
        bytes.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(value) >> shift));
}

std::uint8_t _rex(bool wide, std::uint8_t reg, std::uint8_t rm) {
    return static_cast<std::uint8_t>(0x40 | (wide ? 8 : 0) | ((reg & 8) >> 1) | ((rm & 8) >> 3));
}

void _register(StubBodyBuilder& body, std::uint8_t opcode, bool wide, std::uint8_t reg, std::uint8_t rm) {
    const std::array bytes{_rex(wide, reg, rm), opcode, static_cast<std::uint8_t>(0xC0 | ((reg & 7) << 3) | (rm & 7))};
    body.Raw(bytes);
}

void _stack(StubBodyBuilder& body, std::uint8_t opcode, bool wide, std::uint8_t reg, std::int32_t displacement) {
    std::vector<std::uint8_t> bytes{_rex(wide, reg, kStack), opcode, static_cast<std::uint8_t>(0x84 | ((reg & 7) << 3)), 0x24};
    _append32(bytes, displacement);
    body.Raw(bytes);
}

void _memory(StubBodyBuilder& body, const BmiBitOperands& operands, std::uint8_t destination) {
    const auto& memory = *operands.Memory;
    auto displacement = static_cast<std::int64_t>(memory.Displacement);
    if (memory.StackBase) displacement += kFrameSize;
    const bool address32 = std::find(memory.Prefixes.begin(), memory.Prefixes.end(), 0x67) != memory.Prefixes.end();
    if (!address32 && displacement > std::numeric_limits<std::int32_t>::max())
        throw CodegenException("BMI bit operation stack displacement does not fit after spilling");
    const auto mod = memory.StackBase ? 2 : memory.Mod;
    auto bytes = memory.Prefixes;
    bytes.push_back(static_cast<std::uint8_t>(_rex(operands.Wide, destination, 0) | memory.RexIndexBase));
    bytes.push_back(0x8B);
    bytes.push_back(static_cast<std::uint8_t>((mod << 6) | ((destination & 7) << 3) | memory.Rm));
    if (memory.Rm == 4) bytes.push_back(memory.Sib);
    const auto offset = bytes.size();
    if (mod == 1) bytes.push_back(static_cast<std::uint8_t>(displacement));
    if (mod == 2 || (mod == 0 && (memory.RipRelative || (memory.Rm == 4 && (memory.Sib & 7) == 5))))
        _append32(bytes, static_cast<std::int32_t>(displacement));
    if (memory.RipRelative)
        body.RipRelative(bytes, offset, static_cast<std::int64_t>(memory.InstructionLength) + memory.Displacement);
    else
        body.Raw(bytes);
}

std::size_t _branch(std::vector<std::uint8_t>& bytes, std::uint8_t opcode) {
    bytes.insert(bytes.end(), {opcode, 0});
    return bytes.size() - 1;
}

void _bind(std::vector<std::uint8_t>& bytes, std::size_t displacement) {
    const auto distance = bytes.size() - displacement - 1;
    if (distance > 127) throw CodegenException("BMI bit operation branch exceeds rel8");
    bytes[displacement] = static_cast<std::uint8_t>(distance);
}

void _mask(std::vector<std::uint8_t>& bytes, std::uint8_t rex) {
    bytes.insert(bytes.end(), {rex, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF,
        rex, 0xD3, 0xE2, rex, 0xF7, 0xD2, rex, 0x21, 0xD0});
}

std::vector<std::uint8_t> _operation(BmiBitKind kind, bool wide) {
    const auto rex = static_cast<std::uint8_t>(wide ? 0x48 : 0x40);
    const auto width = static_cast<std::uint8_t>(wide ? 64 : 32);
    std::vector<std::uint8_t> bytes;
    if (kind == BmiBitKind::Bextr) {
        bytes = {0x89, 0xCA, 0xC1, 0xEA, 8, 0x81, 0xE2, 0xFF, 0, 0, 0,
            0x0F, 0xB6, 0xC9, 0x83, 0xF9, width};
        const auto zero = _branch(bytes, 0x73);
        bytes.insert(bytes.end(), {rex, 0xD3, 0xE8, 0x83, 0xFA, width});
        const auto unmasked = _branch(bytes, 0x73);
        bytes.insert(bytes.end(), {0x89, 0xD1});
        _mask(bytes, rex);
        const auto done = _branch(bytes, 0xEB);
        _bind(bytes, zero);
        bytes.insert(bytes.end(), {0x31, 0xC0});
        _bind(bytes, done);
        _bind(bytes, unmasked);
        bytes.insert(bytes.end(), {rex, 0x85, 0xC0});
    } else if (kind == BmiBitKind::Bzhi) {
        bytes = {0x0F, 0xB6, 0xC9, 0x83, 0xF9, width};
        const auto unmasked = _branch(bytes, 0x73);
        _mask(bytes, rex);
        const auto done = _branch(bytes, 0xEB);
        _bind(bytes, unmasked);
        bytes.insert(bytes.end(), {rex, 0x85, 0xC0, 0xF9});
        _bind(bytes, done);
    } else if (kind == BmiBitKind::Blsr) {
        bytes = {rex, 0x85, 0xC0};
        const auto zero = _branch(bytes, 0x74);
        bytes.insert(bytes.end(), {rex, 0x8D, 0x50, 0xFF, rex, 0x21, 0xD0});
        const auto done = _branch(bytes, 0xEB);
        _bind(bytes, zero);
        bytes.push_back(0xF9);
        _bind(bytes, done);
    } else {
        throw CodegenException("Unknown BMI bit operation");
    }
    return bytes;
}

}

std::optional<BmiBitOperands> DecodeBmiBit(const std::uint8_t* data, const std::size_t length) {
    std::size_t vex = 0;
    while (vex < length && _prefix(data[vex])) ++vex;
    if (vex + 5 > length || data[vex] != 0xC4 || (data[vex + 1] & 0x1F) != 2 || (data[vex + 2] & 3) != 0)
        return std::nullopt;
    const auto opcode = data[vex + 3];
    const auto modrm = data[vex + 4];
    const bool blsr = opcode == 0xF3 && ((modrm >> 3) & 7) == 1;
    if (!blsr && opcode != 0xF7 && opcode != 0xF5) return std::nullopt;
    if ((data[vex + 2] & 4) != 0)
        throw CodegenException("BMI bit operation requires VEX.L=0");
    const auto extensions = static_cast<std::uint8_t>(~data[vex + 1]);
    const auto control = static_cast<std::uint8_t>((~data[vex + 2] >> 3) & 15);
    BmiBitOperands operands{
        blsr ? BmiBitKind::Blsr : opcode == 0xF7 ? BmiBitKind::Bextr : BmiBitKind::Bzhi,
        blsr ? control : static_cast<std::uint8_t>(((modrm >> 3) & 7) | ((extensions & 0x80) >> 4)),
        static_cast<std::uint8_t>((modrm & 7) | ((extensions & 0x20) >> 2)), control,
        (data[vex + 2] & 0x80) != 0, std::nullopt};
    if ((modrm >> 6) == 3) {
        if (vex + 5 != length) throw CodegenException("BMI bit register operand has trailing bytes");
    } else {
        const auto rex = static_cast<std::uint8_t>(((extensions & 0x20) >> 5) | ((extensions & 0x40) >> 5));
        operands.Memory = DecodeMemoryOperand(data, length, vex + 4, rex, {data, data + vex});
        if (vex + 4 + operands.Memory->EncodedSize != length)
            throw CodegenException("BMI bit memory operand has trailing bytes");
    }
    return operands;
}

const char* BmiBitName(BmiBitKind kind) {
    switch (kind) {
        case BmiBitKind::Bextr: return "BEXTR";
        case BmiBitKind::Bzhi: return "BZHI";
        case BmiBitKind::Blsr: return "BLSR";
    }
    throw CodegenException("Unknown BMI bit operation");
}

void EmitBmiBit(StubBodyBuilder& body, const BmiBitOperands& operands) {
    _stack(body, 0x8D, true, kStack, -kFrameSize);
    for (std::uint8_t reg = 0; reg < 3; ++reg) _stack(body, 0x89, true, reg, reg * 8);
    if (operands.Memory)
        _memory(body, operands, 0);
    else if (operands.Source == kStack)
        _stack(body, 0x8D, operands.Wide, 0, kFrameSize);
    else
        _register(body, 0x8B, operands.Wide, 0, operands.Source);
    if (operands.Kind != BmiBitKind::Blsr) {
        if (operands.Control < 3)
            _stack(body, 0x8B, false, 1, operands.Control * 8);
        else if (operands.Control == kStack)
            _stack(body, 0x8D, false, 1, kFrameSize);
        else
            _register(body, 0x8B, false, 1, operands.Control);
    }
    body.Raw(_operation(operands.Kind, operands.Wide));
    _stack(body, 0x89, true, 0, 24);
    for (std::uint8_t reg = 0; reg < 3; ++reg) _stack(body, 0x8B, true, reg, reg * 8);
    if (operands.Destination != kStack)
        _stack(body, 0x8B, operands.Wide, operands.Destination, 24);
    _stack(body, 0x8D, true, kStack, kFrameSize);
    if (operands.Destination == kStack)
        _stack(body, 0x8B, operands.Wide, kStack, 24 - kFrameSize);
}

}
