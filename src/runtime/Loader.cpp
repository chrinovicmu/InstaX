//===----------------------------------------------------------------------===//
//  Loader.cpp — assembling a complete guest process image
//===----------------------------------------------------------------------===//

#include "runtime/Loader.hpp"

#include <iomanip>
#include <ostream>
#include <sstream>
#include <stdexcept>

namespace Runtime {

GuestProcess GuestProcess::load(const std::string& path,
                                const std::vector<std::string>& argv,
                                const std::vector<std::string>& envp,
                                const LoadOptions& options) {

    GuestProcess process;
    process.m_file = readElfFile(path);

    uint64_t spanLow = 0, spanHigh = 0;
    computeLoadSpan(process.m_file, spanLow, spanHigh);

    const uint64_t bias = chooseLoadBias(process.m_file, options.pieBase);

    const uint64_t imageLow  = spanLow  + bias;
    const uint64_t imageHigh = spanHigh + bias;

    process.m_memory = std::make_unique<GuestMemory>(
        imageLow, imageHigh, options.fallbackWindowSize);

    GuestMemory& mem = *process.m_memory;
    process.m_image = mapImage(process.m_file, mem, bias);
    applyRelocations(process.m_file, mem, process.m_image);
    applyRelro(process.m_file, mem, process.m_image);

    uint64_t stackTop = options.stackTop;

    if (!mem.isIdentity()) {
        const uint64_t guardGap = 16ull * 1024 * 1024;   // 16 MiB
        stackTop = mem.reservationHigh() - guardGap;
    }

    if (stackTop - options.stackSize < process.m_image.loadHigh &&
        stackTop > process.m_image.loadLow) {
        std::ostringstream o;
        o << "Loader: the stack at 0x" << std::hex << stackTop
          << " would overlap the image at [0x" << process.m_image.loadLow
          << ", 0x" << process.m_image.loadHigh << ")";
        throw std::runtime_error(o.str());
    }

    process.m_stack = buildInitialStack(mem, process.m_image,
                                        argv, envp,
                                        stackTop, options.stackSize);

    process.m_cpu.rip = process.m_image.entry;
    process.m_cpu.rsp = process.m_stack.rsp;
    process.m_cpu.rdx = 0;   // no atexit handler from an interpreter

    return process;
}

std::vector<uint8_t> GuestProcess::readCode(uint64_t guestAddr,
                                            size_t length) const {
    std::vector<uint8_t> bytes(length);
    m_memory->read(guestAddr, bytes.data(), length);
    return bytes;
}


void GuestProcess::describe(std::ostream& os) const {
    describeElfFile(m_file, os);
    describeImage(m_image, os);
    m_memory->dump(os);
    os << "\n";
    describeStack(m_stack, *m_memory, os);

    os << "initial guest CPU state\n"
       << "  rip : 0x" << std::hex << m_cpu.rip << std::dec
       << "   (translation starts here)\n"
       << "  rsp : 0x" << std::hex << m_cpu.rsp << std::dec
       << "   (points at argc)\n"
       << "  rdx : 0x" << std::hex << m_cpu.rdx << std::dec
       << "   (atexit handler; none)\n\n";

    try {
        const std::vector<uint8_t> firstBytes = readCode(m_cpu.rip, 16);
        os << "first 16 bytes at the entry point (guest 0x"
           << std::hex << m_cpu.rip << std::dec << "):\n  ";
        for (uint8_t b : firstBytes)
            os << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<unsigned>(b) << ' ';
        os << std::dec << std::setfill(' ') << "\n"
           << "  these are the x86-64 instruction bytes the lifter will "
              "decode first\n\n";
    } catch (const std::exception& e) {
        os << "could not read guest code at the entry point: "
           << e.what() << "\n\n";
    }

    if (m_image.needsInterp) {
        os << "NOTE: this binary is dynamically linked and names\n"
           << "      " << m_image.interpPath << "\n"
           << "      as its interpreter. That interpreter has NOT been "
              "loaded, so the\n"
           << "      relocations that need symbol resolution are still "
              "outstanding and\n"
           << "      calls into shared libraries would not resolve. "
              "Statically linked\n"
           << "      binaries load completely. See docs/RUNTIME_LOADING.md.\n\n";
    }
}

} // namespace Runtime
