#ifndef CODEGEN_X86_BMIBITLOWERING_HPP
#define CODEGEN_X86_BMIBITLOWERING_HPP

#include <codegen/x86/StubBodyBuilder.hpp>
#include <optional>

namespace Codegen {

enum class BmiBitKind { Bextr, Bzhi, Blsr };

struct BmiBitOperands {
    BmiBitKind Kind;
    std::uint8_t Destination;
    std::uint8_t Source;
    std::uint8_t Control;
    bool Wide;
    std::optional<MemoryOperand> Memory;
};

[[nodiscard]] std::optional<BmiBitOperands> DecodeBmiBit(const std::uint8_t* data, std::size_t length);
[[nodiscard]] const char* BmiBitName(BmiBitKind kind);
void EmitBmiBit(StubBodyBuilder& body, const BmiBitOperands& operands);

}

#endif
