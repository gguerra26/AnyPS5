#ifndef CODEGEN_X86_BMISHIFTLOWERING_HPP
#define CODEGEN_X86_BMISHIFTLOWERING_HPP

#include <codegen/x86/StubBodyBuilder.hpp>
#include <optional>

namespace Codegen {

enum class BmiShiftKind { Shlx, Shrx, Sarx };

struct BmiShiftOperands {
    BmiShiftKind Kind;
    std::uint8_t Destination;
    std::uint8_t Source;
    std::uint8_t Count;
    bool Wide;
    std::optional<MemoryOperand> Memory;
};

[[nodiscard]] std::optional<BmiShiftOperands> DecodeBmiShift(const std::uint8_t* data, std::size_t length);
[[nodiscard]] const char* BmiShiftName(BmiShiftKind kind);
void EmitBmiShift(StubBodyBuilder& body, const BmiShiftOperands& operands);

}

#endif
