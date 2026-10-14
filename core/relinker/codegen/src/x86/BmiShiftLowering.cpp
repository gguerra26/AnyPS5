#include <codegen/x86/BmiShiftLowering.hpp>
#include <codegen/CodegenException.hpp>
#include <algorithm>
#include <array>
#include <limits>

namespace Codegen {

namespace {

constexpr std::int32_t kFrameSize = 160;
constexpr std::uint8_t kStack = 4;
constexpr std::uint8_t kCount = 1;

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

std::uint8_t _scratch(const BmiShiftOperands& operands) {
    std::array<bool, 16> used{};
    used[kStack] = used[kCount] = used[operands.Destination] = true;
    if (operands.Kind != BmiShiftKind::Rorx) used[operands.Count] = true;
    if (!operands.Memory) {
        used[operands.Source] = true;
    } else {
        const auto& memory = *operands.Memory;
        if (memory.Rm == 4) {
            const auto base = static_cast<std::uint8_t>((memory.Sib & 7) | ((memory.RexIndexBase & 1) << 3));
            const auto index = static_cast<std::uint8_t>(((memory.Sib >> 3) & 7) | ((memory.RexIndexBase & 2) << 2));
            if (memory.Mod != 0 || (memory.Sib & 7) != 5) used[base] = true;
            if (index != kStack) used[index] = true;
        } else if (!memory.RipRelative) {
            used[memory.Rm | ((memory.RexIndexBase & 1) << 3)] = true;
        }
    }
    for (const auto reg : {11, 10, 9, 8, 0, 2, 3, 5, 6, 7, 12, 13, 14, 15})
        if (!used[reg]) return static_cast<std::uint8_t>(reg);
    throw CodegenException("BMI2 shift has no scratch register");
}

void _memory(StubBodyBuilder& body, const BmiShiftOperands& operands, std::uint8_t scratch) {
    const auto& memory = *operands.Memory;
    auto displacement = static_cast<std::int64_t>(memory.Displacement);
    if (memory.StackBase) displacement += kFrameSize;
    const bool address32 = std::find(memory.Prefixes.begin(), memory.Prefixes.end(), 0x67) != memory.Prefixes.end();
    if (!address32 && displacement > std::numeric_limits<std::int32_t>::max())
        throw CodegenException("BMI2 shift stack displacement does not fit after spilling");
    const auto mod = memory.StackBase ? 2 : memory.Mod;
    auto bytes = memory.Prefixes;
    bytes.push_back(static_cast<std::uint8_t>(_rex(operands.Wide, scratch, 0) | memory.RexIndexBase));
    bytes.push_back(0x8B);
    bytes.push_back(static_cast<std::uint8_t>((mod << 6) | ((scratch & 7) << 3) | memory.Rm));
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

std::optional<BmiShiftOperands> DecodeBmiShift(const std::uint8_t* data, const std::size_t length) {
    std::size_t vex = 0;
    while (vex < length && _prefix(data[vex])) ++vex;
    if (vex + 5 > length || data[vex] != 0xC4)
        return std::nullopt;
    const auto map = data[vex + 1] & 0x1F;
    const auto prefix = data[vex + 2] & 3;
    const bool rotate = map == 3 && data[vex + 3] == 0xF0 && prefix == 3;
    if (!rotate && !(map == 2 && data[vex + 3] == 0xF7 && prefix != 0))
        return std::nullopt;
    if ((data[vex + 2] & 4) != 0)
        throw CodegenException("BMI2 shift requires VEX.L=0");
    if (rotate && ((data[vex + 2] & 0x78) != 0x78 || vex + 6 > length))
        throw CodegenException("RORX requires reserved VEX.vvvv=1111 and an immediate");
    const auto extensions = static_cast<std::uint8_t>(~data[vex + 1]);
    const auto modrm = data[vex + 4];
    BmiShiftOperands operands{
        rotate ? BmiShiftKind::Rorx : prefix == 1 ? BmiShiftKind::Shlx : prefix == 2 ? BmiShiftKind::Sarx : BmiShiftKind::Shrx,
        static_cast<std::uint8_t>(((modrm >> 3) & 7) | ((extensions & 0x80) >> 4)),
        static_cast<std::uint8_t>((modrm & 7) | ((extensions & 0x20) >> 2)),
        rotate ? data[length - 1] : static_cast<std::uint8_t>((~data[vex + 2] >> 3) & 15),
        (data[vex + 2] & 0x80) != 0, std::nullopt};
    if ((modrm >> 6) == 3) {
        if (vex + 5 + rotate != length) throw CodegenException("BMI2 shift register operand has trailing bytes");
    } else {
        const auto rex = static_cast<std::uint8_t>(((extensions & 0x20) >> 5) | ((extensions & 0x40) >> 5));
        operands.Memory = DecodeMemoryOperand(data, length, vex + 4, rex, {data, data + vex});
        if (vex + 4 + operands.Memory->EncodedSize + rotate != length)
            throw CodegenException("BMI2 shift memory operand has trailing bytes");
    }
    return operands;
}

const char* BmiShiftName(const BmiShiftKind kind) {
    switch (kind) {
        case BmiShiftKind::Shlx: return "SHLX";
        case BmiShiftKind::Shrx: return "SHRX";
        case BmiShiftKind::Sarx: return "SARX";
        case BmiShiftKind::Rorx: return "RORX";
    }
    throw CodegenException("Unknown BMI2 shift");
}

void EmitBmiShift(StubBodyBuilder& body, const BmiShiftOperands& operands) {
    const auto scratch = _scratch(operands);
    _stack(body, 0x8D, true, kStack, -kFrameSize);
    _stack(body, 0x89, true, scratch, 0);
    _stack(body, 0x89, true, kCount, 8);
    if (operands.Memory)
        _memory(body, operands, scratch);
    else if (operands.Source == kStack)
        _stack(body, 0x8D, operands.Wide, scratch, kFrameSize);
    else
        _register(body, 0x8B, operands.Wide, scratch, operands.Source);
    if (operands.Kind != BmiShiftKind::Rorx) {
        if (operands.Count == kStack)
            _stack(body, 0x8D, true, kCount, kFrameSize);
        else
            _register(body, 0x8B, true, kCount, operands.Count);
    }
    body.Raw(std::array<std::uint8_t, 1>{0x9C});
    if (operands.Kind == BmiShiftKind::Rorx) {
        _register(body, 0xC1, operands.Wide, 1, scratch);
        body.Raw(std::array{operands.Count});
    } else {
        const std::uint8_t extension = operands.Kind == BmiShiftKind::Shlx ? 4 : operands.Kind == BmiShiftKind::Shrx ? 5 : 7;
        _register(body, 0xD3, operands.Wide, extension, scratch);
    }
    body.Raw(std::array<std::uint8_t, 1>{0x9D});
    _stack(body, 0x8B, true, kCount, 8);
    if (operands.Destination == kStack)
        _stack(body, 0x89, operands.Wide, scratch, 16);
    else
        _register(body, 0x8B, operands.Wide, operands.Destination, scratch);
    _stack(body, 0x8B, true, scratch, 0);
    _stack(body, 0x8D, true, kStack, kFrameSize);
    if (operands.Destination == kStack)
        _stack(body, 0x8B, operands.Wide, kStack, 16 - kFrameSize);
}

}
