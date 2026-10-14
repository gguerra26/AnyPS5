#include <codegen/x86/BmiShiftLowering.hpp>
#include <codegen/x86/IAmd64OnlyInstructionMatcher.hpp>
#include <codegen/CodegenException.hpp>
#include <array>
#include <bit>
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
using Kind = Codegen::BmiShiftKind;
constexpr std::array kKinds{Kind::Shlx, Kind::Shrx, Kind::Sarx, Kind::Rorx};

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Bytes instruction(Kind kind, bool wide, std::uint8_t dst, std::uint8_t source, std::uint8_t count) {
    if (kind == Kind::Rorx)
        return {0xC4, static_cast<std::uint8_t>(0xE3 ^ ((dst & 8) << 4) ^ ((source & 8) << 2)),
            static_cast<std::uint8_t>(wide ? 0xFB : 0x7B), 0xF0,
            static_cast<std::uint8_t>(0xC0 | ((dst & 7) << 3) | (source & 7)), count};
    const auto prefix = kind == Kind::Shlx ? 1 : kind == Kind::Shrx ? 3 : 2;
    return {0xC4, static_cast<std::uint8_t>(0xE2 ^ ((dst & 8) << 4) ^ ((source & 8) << 2)),
        static_cast<std::uint8_t>((wide ? 0x80 : 0) | ((~count & 15) << 3) | prefix), 0xF7,
        static_cast<std::uint8_t>(0xC0 | ((dst & 7) << 3) | (source & 7))};
}

void decoding() {
    for (const auto kind : kKinds) {
        for (bool wide : {false, true}) {
            for (std::uint8_t dst = 0; dst < 16; ++dst) {
                for (std::uint8_t source = 0; source < 16; ++source) {
                    for (std::uint8_t count = 0; count < 16; ++count) {
                        const auto bytes = instruction(kind, wide, dst, source, count);
                        const auto operands = Codegen::DecodeBmiShift(bytes.data(), bytes.size());
                        require(operands && operands->Kind == kind && operands->Wide == wide && operands->Destination == dst && operands->Source == source && operands->Count == count && !operands->Memory, "BMI2 shift register decoding changed an operand");
                    }
                }
            }
        }
    }
    const Bytes memory{0x64, 0x67, 0xC4, 0x02, 0xA9, 0xF7, 0x8C, 0xAC, 0x10, 0, 0, 0};
    const auto operands = Codegen::DecodeBmiShift(memory.data(), memory.size());
    require(operands && operands->Destination == 9 && operands->Count == 10 && operands->Memory && operands->Memory->RexIndexBase == 3 && operands->Memory->Prefixes == Bytes{0x64, 0x67}, "BMI2 shift memory extensions or prefixes were lost");
    for (const Bytes bytes : {Bytes{0x90}, Bytes{0xC4, 0xE2, 0xF1}, Bytes{0xC4, 0xE1, 0xF1, 0xF7, 0xC0}, Bytes{0xC4, 0xE2, 0xF0, 0xF7, 0xC0}})
        require(!Codegen::DecodeBmiShift(bytes.data(), bytes.size()), "Unrelated opcode, BEXTR or truncated opcode matched a BMI2 shift");
    for (const Bytes bytes : {Bytes{0xC4, 0xE2, 0xF5, 0xF7, 0xC0}, Bytes{0xC4, 0xE2, 0xF1, 0xF7, 0x84}, Bytes{0xC4, 0xE2, 0xF1, 0xF7, 0xC0, 0x90}, Bytes{0xC4, 0xE2, 0xF1, 0xF7, 0x06, 0x90}}) {
        bool rejected = false;
        try { (void)Codegen::DecodeBmiShift(bytes.data(), bytes.size()); }
        catch (const Codegen::CodegenException&) { rejected = true; }
        require(rejected, "Malformed BMI2 shift was accepted");
    }
    const Bytes overflow{0xC4, 0xE2, 0xF1, 0xF7, 0x84, 0x24, 0xFF, 0xFF, 0xFF, 0x7F};
    bool rejected = false;
    try {
        Codegen::StubBodyBuilder body;
        Codegen::EmitBmiShift(body, *Codegen::DecodeBmiShift(overflow.data(), overflow.size()));
    } catch (const Codegen::CodegenException&) { rejected = true; }
    require(rejected, "An overflowing stack displacement was silently wrapped");
}

void matching() {
    const auto intel = Codegen::MakeAmd64OnlyInstructionMatcher();
    const auto rosetta = Codegen::MakeAmd64OnlyInstructionMatcher(Codegen::Amd64OnlyTarget::Rosetta);
    for (const auto kind : kKinds) {
        const auto bytes = instruction(kind, true, 8, 2, 0);
        require(!intel->Match(bytes.data(), bytes.size()), "Intel mode rewrote a BMI2 shift");
        const auto match = rosetta->Match(bytes.data(), bytes.size());
        require(match && match->InstructionName == Codegen::BmiShiftName(kind) && match->Lowering == Codegen::Amd64OnlyLowering::Trampoline && !match->Optional, "Rosetta mode did not require a BMI2 shift trampoline");
        const std::array<std::span<const std::uint8_t>, 2> sequence{bytes, bytes};
        require(rosetta->MatchSequence(sequence, {}).has_value(), "A BMI2 shift sequence could not move out of line");
    }
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
        auto operands = Codegen::DecodeBmiShift(site.data(), site.size());
        require(operands.has_value(), "Execution site was not BMI2 shift");
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
            std::memcpy(relocated.data() + relocated.size() - 4 - (operands->Kind == Kind::Rorx), &displacement, sizeof(displacement));
            operands = Codegen::DecodeBmiShift(relocated.data(), relocated.size());
        }
        Codegen::StubBodyBuilder builder;
        Codegen::EmitBmiShift(builder, *operands);
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
        require(mprotect(code, 4096, PROT_READ | PROT_EXEC) == 0, "Cannot make BMI2 shift test code executable");
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

void check(const State& state, const Codegen::BmiShiftOperands& operands, std::uint64_t source) {
    const auto bits = operands.Wide ? 64u : 32u;
    const auto mask = operands.Wide ? ~std::uint64_t{0} : 0xFFFFFFFFull;
    const auto count = static_cast<unsigned>((operands.Kind == Kind::Rorx ? operands.Count : state.Input[operands.Count]) & (bits - 1));
    const auto value = source & mask;
    auto expected = operands.Kind == Kind::Shlx ? value << count : value >> count;
    if (operands.Kind == Kind::Sarx && count && (value >> (bits - 1)))
        expected |= mask << (bits - count);
    if (operands.Kind == Kind::Rorx)
        expected = operands.Wide ? std::rotr(value, static_cast<int>(count)) : std::rotr(static_cast<std::uint32_t>(value), static_cast<int>(count));
    expected &= mask;
    for (std::size_t reg = 0; reg < 16; ++reg)
        require(state.Output[reg] == (reg == operands.Destination ? expected : state.Input[reg]), "BMI2 shift changed a source/scratch register or produced an incorrect result");
    require((state.Flags & 0xCD5u) == (state.InputFlags & 0xCD5u), "BMI2 shift changed status flags or the direction flag");
    for (const auto value : state.RedZone) require(value == Execution::kSentinel, "BMI2 shift overwrote the caller's red zone");
}

State initialState(std::uint64_t flags) {
    State state;
    for (std::size_t reg = 0; reg < 16; ++reg) state.Input[reg] = 0xABCD123456789000ull + reg * 0x1234567ull;
    state.InputFlags = flags | 0x202;
    return state;
}

void execution() {
    for (const auto kind : {Kind::Shlx, Kind::Shrx, Kind::Sarx}) {
        for (bool wide : {false, true}) {
            for (std::uint8_t dst = 0; dst < 16; ++dst) {
                for (const auto pair : {std::pair<std::uint8_t, std::uint8_t>{1, 6}, {dst, 10}, {11, dst}, {dst, dst}, {4, 9}, {9, 4}, {1, 1}, {1, dst}, {dst, 1}, {4, 4}, {12, 13}, {13, 12}, {15, 14}}) {
                    const auto site = instruction(kind, wide, dst, pair.first, pair.second);
                    Execution executable(site, 0);
                    for (const auto count : {0ull, 1ull, 31ull, 32ull, 63ull, 64ull, 65ull, 255ull, 0xFEDCBA9876543241ull}) {
                        for (const auto value : {0ull, 1ull, 0x8000000080000000ull, ~0ull}) {
                            auto state = initialState((count & 1) ? 0xCD5 : 0);
                            state.Input[pair.first] = value;
                            state.Input[pair.second] = count;
                            executable.Run(state);
                            check(state, *Codegen::DecodeBmiShift(site.data(), site.size()), state.Input[pair.first]);
                        }
                    }
                }
            }
            for (const Bytes tail : {Bytes{0x06}, Bytes{0x46, 0x10}, Bytes{0x84, 0x24, 0x40, 0, 0, 0}, Bytes{0x44, 0x24, 0x40}, Bytes{0x44, 0x24, 0xC0}, Bytes{0x04, 0xCA}, Bytes{0x85, 0x10, 0, 0, 0}, Bytes{0x05, 0, 0, 0, 0}, Bytes{0x01}, Bytes{0x04, 0x0A}}) {
                auto site = instruction(kind, wide, 0, 0, 1);
                site.resize(4);
                site.insert(site.end(), tail.begin(), tail.end());
                constexpr std::uint64_t value = 0xFEDCBA9876543210ull;
                Execution executable(site, value);
                for (const auto flags : {0u, 1u, 4u, 0x10u, 0x40u, 0x80u, 0x400u, 0x800u, 0xCD5u}) {
                    auto state = initialState(flags);
                    const auto pointer = reinterpret_cast<std::uint64_t>(executable.Memory());
                    state.Input[6] = pointer - (tail[0] == 0x46 ? 16 : 0);
                    state.Input[2] = pointer - (tail.size() == 2 && tail[1] == 0x0A ? 3 : 3 * 8);
                    state.Input[1] = tail[0] == 0x01 ? pointer : 3;
                    state.Input[5] = pointer - 16;
                    state.Output[0] = value;
                    executable.Run(state);
                    check(state, *Codegen::DecodeBmiShift(site.data(), site.size()), tail.back() == 0xC0 ? Execution::kSentinel : value);
                }
            }
            auto site = instruction(kind, wide, 9, 12, 10);
            site[1] ^= 0x40;
            site.resize(4);
            site.insert(site.end(), {0x4C, 0x5C, 0x10});
            constexpr std::uint64_t value = 0x8000000080000001ull;
            Execution executable(site, value);
            auto state = initialState(0xCD5);
            state.Input[12] = reinterpret_cast<std::uint64_t>(executable.Memory()) - 16 - 3 * 2;
            state.Input[11] = 3;
            state.Input[10] = 31;
            executable.Run(state);
            check(state, *Codegen::DecodeBmiShift(site.data(), site.size()), value);
        }
    }
    for (bool wide : {false, true}) {
        for (std::uint8_t dst = 0; dst < 16; ++dst) {
            for (const auto src : {std::uint8_t{0}, std::uint8_t{1}, std::uint8_t{4}, std::uint8_t{11}, dst}) {
                for (const auto count : {0, 1, 31, 32, 63, 64, 65, 255}) {
                    const auto site = instruction(Kind::Rorx, wide, dst, src, static_cast<std::uint8_t>(count));
                    Execution executable(site, 0);
                    for (const auto value : {0ull, 1ull, 0x8000000080000000ull, ~0ull}) {
                        auto state = initialState((count & 1) ? 0xCD5 : 0);
                        state.Input[src] = value;
                        executable.Run(state);
                        check(state, *Codegen::DecodeBmiShift(site.data(), site.size()), state.Input[src]);
                    }
                }
            }
        }
        for (const Bytes tail : {Bytes{0x06}, Bytes{0x46, 0x10}, Bytes{0x84, 0x24, 0x40, 0, 0, 0}, Bytes{0x04, 0xCA}, Bytes{0x05, 0, 0, 0, 0}}) {
            auto site = instruction(Kind::Rorx, wide, 0, 0, 0);
            site.resize(4);
            site.insert(site.end(), tail.begin(), tail.end());
            site.push_back(18);
            constexpr std::uint64_t value = 0xFEDCBA9876543210ull;
            Execution executable(site, value);
            auto state = initialState(0xCD5);
            state.Input[6] = reinterpret_cast<std::uint64_t>(executable.Memory()) - (tail[0] == 0x46 ? 16 : 0);
            state.Input[2] = reinterpret_cast<std::uint64_t>(executable.Memory()) - 3 * 8;
            state.Input[1] = 3;
            state.Output[0] = value;
            executable.Run(state);
            check(state, *Codegen::DecodeBmiShift(site.data(), site.size()), value);
        }
    }
}
#else
void execution() { std::cout << "BMI2 shift execution checks require a Linux/macOS x86-64 build\n"; }
#endif

}

int main() {
    try {
        decoding();
        matching();
        execution();
        std::cout << "BMI2 shift lowering checks passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
