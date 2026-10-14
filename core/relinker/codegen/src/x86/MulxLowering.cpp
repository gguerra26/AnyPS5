#include <codegen/x86/MulxLowering.hpp>
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

void _memory(StubBodyBuilder& body, const MulxOperands& operands, std::uint8_t destination) {
    const auto& memory = *operands.Memory;
    auto displacement = static_cast<std::int64_t>(memory.Displacement);
    if (memory.StackBase) displacement += kFrameSize;
    const bool address32 = std::find(memory.Prefixes.begin(), memory.Prefixes.end(), 0x67) != memory.Prefixes.end();
    if (!address32 && displacement > std::numeric_limits<std::int32_t>::max())
        throw CodegenException("MULX stack displacement does not fit after spilling");
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

}

std::optional<MulxOperands> DecodeMulx(const std::uint8_t* data, const std::size_t length) {
    std::size_t vex = 0;
    while (vex < length && _prefix(data[vex])) ++vex;
    if (vex + 5 > length || data[vex] != 0xC4 || (data[vex + 1] & 0x1F) != 2 || data[vex + 3] != 0xF6 || (data[vex + 2] & 3) != 3)
        return std::nullopt;
    if ((data[vex + 2] & 4) != 0)
        throw CodegenException("MULX requires VEX.L=0");
    const auto extensions = static_cast<std::uint8_t>(~data[vex + 1]);
    const auto modrm = data[vex + 4];
    MulxOperands operands{
        static_cast<std::uint8_t>(((modrm >> 3) & 7) | ((extensions & 0x80) >> 4)),
        static_cast<std::uint8_t>((~data[vex + 2] >> 3) & 15),
        static_cast<std::uint8_t>((modrm & 7) | ((extensions & 0x20) >> 2)),
        (data[vex + 2] & 0x80) != 0, std::nullopt};
    if ((modrm >> 6) == 3) {
        if (vex + 5 != length) throw CodegenException("MULX register operand has trailing bytes");
    } else {
        const auto rex = static_cast<std::uint8_t>(((extensions & 0x20) >> 5) | ((extensions & 0x40) >> 5));
        operands.Memory = DecodeMemoryOperand(data, length, vex + 4, rex, {data, data + vex});
        if (vex + 4 + operands.Memory->EncodedSize != length)
            throw CodegenException("MULX memory operand has trailing bytes");
    }
    return operands;
}

void EmitMulx(StubBodyBuilder& body, const MulxOperands& operands) {
    _stack(body, 0x8D, true, kStack, -kFrameSize);
    _stack(body, 0x89, true, 0, 0);
    _stack(body, 0x89, true, 2, 8);
    if (operands.Memory)
        _memory(body, operands, 0);
    else if (operands.Source == kStack)
        _stack(body, 0x8D, operands.Wide, 0, kFrameSize);
    else
        _register(body, 0x8B, operands.Wide, 0, operands.Source);
    body.Raw(std::array<std::uint8_t, 1>{0x9C});
    _register(body, 0xF7, operands.Wide, 4, 2);
    body.Raw(std::array<std::uint8_t, 1>{0x9D});
    _stack(body, 0x89, true, 0, 16);
    _stack(body, 0x89, true, 2, 24);
    _stack(body, 0x8B, true, 0, 0);
    _stack(body, 0x8B, true, 2, 8);
    if (operands.Low != kStack)
        _stack(body, 0x8B, operands.Wide, operands.Low, 16);
    if (operands.High != kStack)
        _stack(body, 0x8B, operands.Wide, operands.High, 24);
    _stack(body, 0x8D, true, kStack, kFrameSize);
    if (operands.High == kStack || operands.Low == kStack)
        _stack(body, 0x8B, operands.Wide, kStack, (operands.High == kStack ? 24 : 16) - kFrameSize);
}

}
