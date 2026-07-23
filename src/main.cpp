//
// Usage:
//   ./x2r <path-to-x86-64-binary>
//
// Pipeline used (matches the current API surface):
//
//   ElfLoad::loadElfFile()      — static ELFIO-based reader, produces
//                                  ElfLoadResult (raw .text/.data bytes,
//                                  entry point, symbol-relevant metadata)
//         │
//         ▼
//   X2R_IR::liftX86ToIR()       — the full lifter pipeline: symbol
//                                  reading, disassembly (Zydis),
//                                  CFG construction, per-function
//                                  lifting (non-SSA, lazy flags)
//         │
//         ▼
//   X2R_IR::printIRProgram()    — LLVM-flavored textual IR printer
//
// This file intentionally does NOT touch GuestMemory / ELFMapper —
// those are the RUNTIME loader (mmap-based, for actually executing
// translated code). This driver only exercises the STATIC analysis
// path: ELFLoader -> X86Lifter -> IR printer.

#include "frontend/ElfLoader.hpp"
#include "frontend/x86/X86Lifter.hpp"
#include "ir/IR.hpp"

#include <iostream>
#include <filesystem>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <path-to-x86-64-elf-binary>\n";
        return 1;
    }

    std::filesystem::path binaryPath(argv[1]);

    if (!std::filesystem::exists(binaryPath)) {
        std::cerr << "Error: file does not exist: " << binaryPath << "\n";
        return 1;
    }

    std::optional<ElfLoad::ElfLoadResult> elfResult =
        ElfLoad::loadElfFile(binaryPath);

    if (!elfResult.has_value()) {
        std::cerr << "Error: failed to load ELF file: " << binaryPath << "\n";
        return 1;
    }

    const ElfLoad::ElfLoadResult& elf = *elfResult;

    if (!elf.hasText()) {
        std::cerr << "Error: ELF has no executable .text segment: "
                  << binaryPath << "\n";
        return 1;
    }

    std::cerr << "Loaded ELF: " << binaryPath << "\n"
              << "  entry:     0x" << std::hex << elf.entry << std::dec << "\n"
              << "  text addr: 0x" << std::hex << elf.textAddr << std::dec
              << "  size: " << elf.textSize << " bytes\n"
              << "  data addr: 0x" << std::hex << elf.dataAddr << std::dec
              << "  size: " << elf.dataSize << " bytes\n"
              << "  class:     " << (elf.is64Bit ? "64-bit" : "32-bit") << "\n"
              << "  endian:    " << (elf.littleEndian ? "little" : "big") << "\n\n";

    X2R_IR::IRProgram program;
    try {
        program = X2R_IR::liftX86ToIR(elf);
    } catch (const std::exception& e) {
        std::cerr << "Error: lifting failed: " << e.what() << "\n";
        return 1;
    }

    std::cerr << "Lifted " << program.functions().size() << " function(s), "
              << program.globals().size() << " global(s).\n\n";

    X2R_IR::printIRProgram(program);

    return 0;
}
