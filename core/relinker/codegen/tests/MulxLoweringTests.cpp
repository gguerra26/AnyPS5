#include <codegen/x86/MulxLowering.hpp>
#include <codegen/x86/IAmd64OnlyInstructionMatcher.hpp>
#include <codegen/CodegenException.hpp>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>
#if (defined(__linux__) || defined(__APPLE__)) && defined(__x86_64__)
#include <sys/mman.h>
#endif

namespace {

using Bytes = std::vector<std::uint8_t>;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Bytes instruction(bool wide, std::uint8_t high, std::uint8_t low, std::uint8_t source) {
    return {0xC4, static_cast<std::uint8_t>(0xE2 ^ ((high & 8) << 4) ^ ((source & 8) << 2)),
        static_cast<std::uint8_t>((wide ? 0x80 : 0) | ((~low & 15) << 3) | 3), 0xF6,
        static_cast<std::uint8_t>(0xC0 | ((high & 7) << 3) | (source & 7))};
}

void decoding() {
    for (bool wide : {false, true}) {
        for (std::uint8_t high = 0; high < 16; ++high) {
            for (std::uint8_t low = 0; low < 16; ++low) {
                for (std::uint8_t source = 0; source < 16; ++source) {
                    const auto bytes = instruction(wide, high, low, source);
                    const auto operands = Codegen::DecodeMulx(bytes.data(), bytes.size());
                    require(operands && operands->Wide == wide && operands->High == high && operands->Low == low && operands->Source == source && !operands->Memory, "MULX register decoding changed an operand");
                }
            }
        }
    }
    const Bytes memory{0x64, 0x67, 0xC4, 0x02, 0xAB, 0xF6, 0x8C, 0xAC, 0x10, 0, 0, 0};
    const auto operands = Codegen::DecodeMulx(memory.data(), memory.size());
    require(operands && operands->High == 9 && operands->Low == 10 && operands->Memory && operands->Memory->RexIndexBase == 3 && operands->Memory->Prefixes == Bytes{0x64, 0x67}, "MULX memory extensions or prefixes were lost");
    for (const Bytes bytes : {Bytes{0x90}, Bytes{0xC4, 0xE2, 0xF3}, Bytes{0xC4, 0xE1, 0xF3, 0xF6, 0xC0}, Bytes{0xC4, 0xE2, 0xF0, 0xF6, 0xC0}})
        require(!Codegen::DecodeMulx(bytes.data(), bytes.size()), "Unrelated or truncated opcode matched MULX");
    for (const Bytes bytes : {Bytes{0xC4, 0xE2, 0xF7, 0xF6, 0xC0}, Bytes{0xC4, 0xE2, 0xF3, 0xF6, 0x84}, Bytes{0xC4, 0xE2, 0xF3, 0xF6, 0xC0, 0x90}, Bytes{0xC4, 0xE2, 0xF3, 0xF6, 0x06, 0x90}}) {
        bool rejected = false;
        try { (void)Codegen::DecodeMulx(bytes.data(), bytes.size()); }
        catch (const Codegen::CodegenException&) { rejected = true; }
        require(rejected, "Malformed MULX was accepted");
    }
    const Bytes overflow{0xC4, 0xE2, 0xF3, 0xF6, 0x84, 0x24, 0xFF, 0xFF, 0xFF, 0x7F};
    bool rejected = false;
    try {
        Codegen::StubBodyBuilder body;
        Codegen::EmitMulx(body, *Codegen::DecodeMulx(overflow.data(), overflow.size()));
    } catch (const Codegen::CodegenException&) { rejected = true; }
    require(rejected, "An overflowing stack displacement was silently wrapped");
}

void matching() {
    const auto bytes = instruction(true, 6, 6, 6);
    const auto intel = Codegen::MakeAmd64OnlyInstructionMatcher();
    const auto rosetta = Codegen::MakeAmd64OnlyInstructionMatcher(Codegen::Amd64OnlyTarget::Rosetta);
    require(!intel->Match(bytes.data(), bytes.size()), "Intel mode rewrote MULX");
    const auto match = rosetta->Match(bytes.data(), bytes.size());
    require(match && match->InstructionName == "MULX" && match->Lowering == Codegen::Amd64OnlyLowering::Trampoline && !match->Optional, "Rosetta mode did not require a MULX trampoline");
    const std::array<std::span<const std::uint8_t>, 2> sequence{bytes, bytes};
    require(rosetta->MatchSequence(sequence, {}).has_value(), "A MULX sequence could not move out of line");
}

#if (defined(__linux__) || defined(__APPLE__)) && defined(__x86_64__)

struct State {
    std::array<std::uint64_t, 16> Input{};
    std::array<std::uint64_t, 16> Output{};
    std::uint64_t Flags = 0;
    std::array<std::uint64_t, 16> RedZone{};
    std::uint64_t InputFlags = 0x202;
};

class Execution {
public:
    Execution(const Bytes& site, std::uint64_t memoryValue) {
        auto operands = Codegen::DecodeMulx(site.data(), site.size());
        require(operands.has_value(), "Execution site was not MULX");
        for (auto reg : {3, 5, 12, 13, 14, 15}) push(static_cast<std::uint8_t>(reg));
        memory(0x8D, 4, 4, -128);
        rip({0x48, 0x89, 0x3D}, 0);
        rip({0x48, 0x89, 0x25}, 8);
        memory(0x89, 4, 7, 32);
        bytes.insert(bytes.end(), {0x48, 0xB8});
        append64(kSentinel);
        for (int displacement = -128; displacement < 0; displacement += 8)
            memory(0x89, 0, 4, displacement);
        memory(0x8B, 0, 7, 16 * 8);
        memory(0x89, 0, 4, 64);
        memory(0x8D, 4, 4, -144);
        memory(0xFF, 6, 7, 49 * 8);
        bytes.push_back(0x9D);
        memory(0x8D, 4, 4, 144);
        for (std::uint8_t reg = 0; reg < 16; ++reg)
            if (reg != 4 && reg != 7) memory(0x8B, reg, 7, reg * 8);
        memory(0x8B, 7, 7, 7 * 8);
        const auto siteOffset = bytes.size();
        if (operands->Memory && operands->Memory->RipRelative) {
            auto relocated = site;
            const auto displacement = static_cast<std::int32_t>(4096 + 24 - (siteOffset + site.size()));
            std::memcpy(relocated.data() + relocated.size() - 4, &displacement, sizeof(displacement));
            operands = Codegen::DecodeMulx(relocated.data(), relocated.size());
        }
        Codegen::StubBodyBuilder builder;
        Codegen::EmitMulx(builder, *operands);
        auto body = builder.Finish();
        const auto stubOffset = bytes.size();
        Codegen::ApplyStubRelocations(body.Bytes, body.Relocations, siteOffset, stubOffset, 0);
        bytes.insert(bytes.end(), body.Bytes.begin(), body.Bytes.begin() + static_cast<std::ptrdiff_t>(body.ReturnBranchOffset));
        rip({0x48, 0x89, 0x25}, 16);
        rip({0x48, 0x8B, 0x25}, 8);
        memory(0x8D, 4, 4, -256);
        for (std::uint8_t reg = 0; reg < 16; ++reg) if (reg != 4) push(reg);
        bytes.push_back(0x9C);
        bytes.push_back(0xFC);
        rip({0x48, 0x8B, 0x3D}, 0);
        memory(0x8B, 0, 4, 0);
        memory(0x89, 0, 7, 32 * 8);
        int offset = 8;
        for (int reg = 15; reg >= 0; --reg) {
            if (reg == 4) continue;
            memory(0x8B, 0, 4, offset);
            memory(0x89, 0, 7, (16 + reg) * 8);
            offset += 8;
        }
        rip({0x48, 0x8B, 0x05}, 16);
        memory(0x89, 0, 7, 20 * 8);
        for (int slot = 0; slot < 16; ++slot) {
            memory(0x8B, 0, 4, 256 + 128 - 128 + slot * 8);
            memory(0x89, 0, 7, (33 + slot) * 8);
        }
        rip({0x48, 0x8B, 0x25}, 8);
        memory(0x8D, 4, 4, 128);
        for (auto reg : {15, 14, 13, 12, 5, 3}) pop(static_cast<std::uint8_t>(reg));
        bytes.push_back(0xC3);
        require(bytes.size() < 4096, "Execution wrapper exceeded its code page");
        code = static_cast<std::uint8_t*>(mmap(nullptr, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        require(code != MAP_FAILED, "Cannot allocate execution test pages");
        std::memcpy(code, bytes.data(), bytes.size());
        std::memcpy(code + 4096 + 24, &memoryValue, sizeof(memoryValue));
        require(mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0, "Cannot make MULX test code executable");
    }

    ~Execution() { if (code != MAP_FAILED) munmap(code, 8192); }

    void Run(State& state) const { reinterpret_cast<void (*)(State*)>(code)(&state); }
    const void* Memory() const { return code + 4096 + 24; }
    static constexpr std::uint64_t kSentinel = 0xBADC0FFEE0DDF00Dull;

private:
    Bytes bytes;
    std::uint8_t* code = reinterpret_cast<std::uint8_t*>(MAP_FAILED);

    void append32(std::int32_t value) {
        for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(static_cast<std::uint8_t>(static_cast<std::uint32_t>(value) >> shift));
    }
    void append64(std::uint64_t value) {
        for (unsigned shift = 0; shift < 64; shift += 8) bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
    void rip(std::initializer_list<std::uint8_t> opcode, int slot) {
        bytes.insert(bytes.end(), opcode);
        append32(static_cast<std::int32_t>(4096 + slot - (bytes.size() + 4)));
    }
    void push(std::uint8_t reg) {
        if (reg >= 8) bytes.push_back(0x41);
        bytes.push_back(static_cast<std::uint8_t>(0x50 | (reg & 7)));
    }
    void pop(std::uint8_t reg) {
        if (reg >= 8) bytes.push_back(0x41);
        bytes.push_back(static_cast<std::uint8_t>(0x58 | (reg & 7)));
    }
    void memory(std::uint8_t opcode, std::uint8_t reg, std::uint8_t base, int displacement) {
        bytes.insert(bytes.end(), {static_cast<std::uint8_t>(0x48 | ((reg & 8) >> 1) | ((base & 8) >> 3)), opcode,
            static_cast<std::uint8_t>(0x80 | ((reg & 7) << 3) | (base & 7))});
        if ((base & 7) == 4) bytes.push_back(0x24);
        append32(displacement);
    }
};

std::pair<std::uint64_t, std::uint64_t> product(std::uint64_t first, std::uint64_t second, bool wide) {
    constexpr std::uint64_t mask = 0xFFFFFFFF;
    if (!wide) {
        const auto value = (first & mask) * (second & mask);
        return {value & mask, value >> 32};
    }
    const auto bottom = (first & mask) * (second & mask);
    const auto left = (first >> 32) * (second & mask);
    const auto right = (first & mask) * (second >> 32);
    const auto middle = (bottom >> 32) + (left & mask) + (right & mask);
    return {(middle << 32) | (bottom & mask), (first >> 32) * (second >> 32) + (left >> 32) + (right >> 32) + (middle >> 32)};
}

void check(const State& state, const Codegen::MulxOperands& operands, std::uint64_t source) {
    const auto [low, high] = product(state.Input[2], source, operands.Wide);
    for (std::size_t reg = 0; reg < 16; ++reg) {
        const auto expected = reg == operands.High ? high : reg == operands.Low ? low : state.Input[reg];
        require(state.Output[reg] == expected, "MULX changed a source/scratch register or produced an incorrect result");
    }
    require((state.Flags & 0xCD5u) == (state.InputFlags & 0xCD5u), "MULX changed status flags or the direction flag");
    for (const auto value : state.RedZone) require(value == Execution::kSentinel, "MULX overwrote the caller's red zone");
}

State initialState(std::uint64_t flags) {
    State state;
    for (std::size_t reg = 0; reg < 16; ++reg) state.Input[reg] = 0xABCD123456789000ull + reg * 0x1234567ull;
    state.InputFlags = flags | 0x202;
    return state;
}

void execution() {
    for (bool wide : {false, true}) {
        for (std::uint8_t high = 0; high < 16; ++high) {
            for (std::uint8_t low = 0; low < 16; ++low) {
                for (const auto source : {std::uint8_t{0}, std::uint8_t{2}, std::uint8_t{4}, std::uint8_t{15}, high, low}) {
                    const auto site = instruction(wide, high, low, source);
                    Execution executable(site, 0);
                    for (const auto pair : {std::pair<std::uint64_t, std::uint64_t>{0, ~0ull}, {1, ~0ull}, {~0ull, ~0ull}, {0x8000000080000000ull, 1}, {0x100000001ull, 0x100000001ull}, {0xABCD123456789012ull, 0xFEDCBA9876543210ull}}) {
                        for (const auto flags : {0u, 0xCD5u}) {
                            auto state = initialState(flags);
                            state.Input[source] = pair.first;
                            state.Input[2] = pair.second;
                            executable.Run(state);
                            check(state, *Codegen::DecodeMulx(site.data(), site.size()), state.Input[source]);
                        }
                    }
                }
            }
        }
        for (const Bytes tail : {Bytes{0x06}, Bytes{0x46, 0x10}, Bytes{0x84, 0x24, 0x40, 0, 0, 0}, Bytes{0x44, 0x24, 0xC0}, Bytes{0x04, 0xCA}, Bytes{0x85, 0x10, 0, 0, 0}, Bytes{0x05, 0, 0, 0, 0}, Bytes{0x00}, Bytes{0x02}}) {
            auto site = instruction(wide, 0, 2, 0);
            site.resize(4);
            site.insert(site.end(), tail.begin(), tail.end());
            constexpr std::uint64_t value = 0xFEDCBA9876543210ull;
            Execution executable(site, value);
            for (const auto flags : {0u, 1u, 4u, 0x10u, 0x40u, 0x80u, 0x400u, 0x800u, 0xCD5u}) {
                auto state = initialState(flags);
                const auto pointer = reinterpret_cast<std::uint64_t>(executable.Memory());
                state.Input[0] = pointer;
                state.Input[6] = pointer - (tail[0] == 0x46 ? 16 : 0);
                state.Input[2] = pointer - (tail[0] == 0x02 ? 0 : 3 * 8);
                state.Input[1] = 3;
                state.Input[5] = pointer - 16;
                state.Output[0] = value;
                executable.Run(state);
                check(state, *Codegen::DecodeMulx(site.data(), site.size()), tail.back() == 0xC0 ? Execution::kSentinel : value);
            }
        }
        auto site = instruction(wide, 9, 10, 12);
        site[1] ^= 0x40;
        site.resize(4);
        site.insert(site.end(), {0x4C, 0x5C, 0x10});
        constexpr std::uint64_t value = 0x8000000080000001ull;
        Execution executable(site, value);
        auto state = initialState(0xCD5);
        state.Input[12] = reinterpret_cast<std::uint64_t>(executable.Memory()) - 16 - 3 * 2;
        state.Input[11] = 3;
        executable.Run(state);
        check(state, *Codegen::DecodeMulx(site.data(), site.size()), value);
    }
}
#else
void execution() { std::cout << "MULX execution checks require a Linux/macOS x86-64 build\n"; }
#endif

}

int main() {
    try {
        decoding();
        matching();
        execution();
        std::cout << "MULX lowering checks passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
