#include "runtime/GuestStack.hpp"

#include <algorithm>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <stdexcept>

namespace Runtime {

namespace {

// Round down to a multiple of `alignment` (a power of two).
inline uint64_t alignDown(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1);
}

// The x86-64 System V ABI requires 16-byte stack alignment at entry.
constexpr uint64_t kStackAlign = 16;

// AT_RANDOM must point at 16 bytes the program treats as unpredictable.
constexpr size_t kRandomBytes = 16;

} // namespace


GuestStackImage buildInitialStack(GuestMemory& mem,
                                  const GuestElfImage& image,
                                  const std::vector<std::string>& argv,
                                  const std::vector<std::string>& envp,
                                  uint64_t stackTop,
                                  uint64_t stackSize) {

    GuestStackImage stack;

    stackTop  = GuestMemory::guestPageAlignUp(stackTop);
    stackSize = GuestMemory::guestPageAlignUp(stackSize);

    stack.top  = stackTop;
    stack.low  = stackTop - stackSize;
    stack.size = stackSize;

    mem.map(stack.low, stackSize, kProtRead | kProtWrite, "stack");

    uint64_t cursor = stackTop;

    auto pushString = [&](const std::string& s) -> uint64_t {
        const size_t bytes = s.size() + 1;          
        cursor -= bytes;
        mem.write(cursor, s.c_str(), bytes);
        return cursor;
    };

    const uint64_t execfnAddr = pushString(image.path);

    const uint64_t platformAddr = pushString("x86_64");

    std::vector<uint64_t> envAddrs;
    envAddrs.reserve(envp.size());
    for (auto it = envp.rbegin(); it != envp.rend(); ++it)
        envAddrs.push_back(pushString(*it));
    std::reverse(envAddrs.begin(), envAddrs.end());

    std::vector<uint64_t> argAddrs;
    argAddrs.reserve(argv.size());
    for (auto it = argv.rbegin(); it != argv.rend(); ++it)
        argAddrs.push_back(pushString(*it));
    std::reverse(argAddrs.begin(), argAddrs.end());

    cursor = alignDown(cursor, kStackAlign);
    cursor -= kRandomBytes;
    const uint64_t randomAddr = cursor;
    {
        uint8_t bytes[kRandomBytes];
        for (size_t i = 0; i < kRandomBytes; ++i)
            bytes[i] = static_cast<uint8_t>(0xA5 ^ (i * 31));
        mem.write(randomAddr, bytes, kRandomBytes);
    }

    std::vector<std::pair<uint64_t, uint64_t>> auxv;

    auxv.push_back({Elf::AT_PHDR,   image.phdrAddr});
    auxv.push_back({Elf::AT_PHENT,  image.phEntSize});
    auxv.push_back({Elf::AT_PHNUM,  image.phNum});

    auxv.push_back({Elf::AT_PAGESZ, Elf::GUEST_PAGE_SIZE});

    auxv.push_back({Elf::AT_BASE,   0});

    auxv.push_back({Elf::AT_FLAGS,  0});

    auxv.push_back({Elf::AT_ENTRY,  image.entry});

    auxv.push_back({Elf::AT_UID,    1000});
    auxv.push_back({Elf::AT_EUID,   1000});
    auxv.push_back({Elf::AT_GID,    1000});
    auxv.push_back({Elf::AT_EGID,   1000});

    auxv.push_back({Elf::AT_SECURE, 0});

    auxv.push_back({Elf::AT_CLKTCK, 100});

    auxv.push_back({Elf::AT_HWCAP,  0});
    auxv.push_back({Elf::AT_HWCAP2, 0});

    auxv.push_back({Elf::AT_RANDOM,   randomAddr});
    auxv.push_back({Elf::AT_PLATFORM, platformAddr});
    auxv.push_back({Elf::AT_EXECFN,   execfnAddr});

    auxv.push_back({Elf::AT_NULL,   0});

    const uint64_t slotCount = 1
                             + argv.size() + 1
                             + envp.size() + 1
                             + auxv.size() * 2;
    const uint64_t blockSize = slotCount * sizeof(uint64_t);

    uint64_t rsp = alignDown(cursor - blockSize, kStackAlign);

    if (rsp < stack.low)
        throw std::runtime_error(
            "GuestStack: argv/envp are too large for the stack size "
            "requested");

    stack.rsp  = rsp;
    stack.argc = argv.size();

    uint64_t p = rsp;

    // argc
    mem.write64(p, argv.size());
    p += 8;

    // argv[] followed by its NULL terminator
    stack.argvAddr = p;
    for (uint64_t addr : argAddrs) {
        mem.write64(p, addr);
        p += 8;
    }
    mem.write64(p, 0);
    p += 8;

    // envp[] followed by its NULL terminator
    stack.envpAddr = p;
    for (uint64_t addr : envAddrs) {
        mem.write64(p, addr);
        p += 8;
    }
    mem.write64(p, 0);
    p += 8;

    // auxv[]: each entry is two words, and AT_NULL is already the last
    // element of the vector so no extra terminator is needed here.
    stack.auxvAddr = p;
    for (const auto& [key, value] : auxv) {
        mem.write64(p,     key);
        mem.write64(p + 8, value);
        p += 16;
    }

    return stack;
}

namespace {

const char* auxvName(uint64_t type) {
    switch (type) {
        case Elf::AT_NULL:     return "AT_NULL";
        case Elf::AT_PHDR:     return "AT_PHDR";
        case Elf::AT_PHENT:    return "AT_PHENT";
        case Elf::AT_PHNUM:    return "AT_PHNUM";
        case Elf::AT_PAGESZ:   return "AT_PAGESZ";
        case Elf::AT_BASE:     return "AT_BASE";
        case Elf::AT_FLAGS:    return "AT_FLAGS";
        case Elf::AT_ENTRY:    return "AT_ENTRY";
        case Elf::AT_UID:      return "AT_UID";
        case Elf::AT_EUID:     return "AT_EUID";
        case Elf::AT_GID:      return "AT_GID";
        case Elf::AT_EGID:     return "AT_EGID";
        case Elf::AT_PLATFORM: return "AT_PLATFORM";
        case Elf::AT_HWCAP:    return "AT_HWCAP";
        case Elf::AT_CLKTCK:   return "AT_CLKTCK";
        case Elf::AT_SECURE:   return "AT_SECURE";
        case Elf::AT_RANDOM:   return "AT_RANDOM";
        case Elf::AT_HWCAP2:   return "AT_HWCAP2";
        case Elf::AT_EXECFN:   return "AT_EXECFN";
        default:               return "AT_<unknown>";
    }
}

std::string readGuestString(const GuestMemory& mem, uint64_t addr,
                            size_t limit = 128) {
    std::string s;
    for (size_t i = 0; i < limit; ++i) {
        if (!mem.isMapped(addr + i, 1)) break;
        char c = 0;
        mem.read(addr + i, &c, 1);
        if (c == '\0') break;
        s += c;
    }
    return s;
}

} // namespace

void describeStack(const GuestStackImage& stack, const GuestMemory& mem,
                   std::ostream& os) {

    os << "guest stack\n"
       << "  mapped      : 0x" << std::hex << stack.low
       << " - 0x" << stack.top << std::dec
       << "   (" << (stack.size / 1024) << " KiB)\n"
       << "  initial rsp : 0x" << std::hex << stack.rsp << std::dec
       << "   (16-byte aligned: "
       << ((stack.rsp % 16 == 0) ? "yes" : "NO — THIS IS A BUG") << ")\n";

    const uint64_t argc = mem.read64(stack.rsp);
    os << "  argc        : " << argc << "\n";

    for (uint64_t i = 0; i < argc && i < 8; ++i) {
        const uint64_t ptr = mem.read64(stack.argvAddr + i * 8);
        os << "    argv[" << i << "]   : 0x" << std::hex << ptr << std::dec
           << "  \"" << readGuestString(mem, ptr) << "\"\n";
    }

    uint64_t envCount = 0;
    while (mem.read64(stack.envpAddr + envCount * 8) != 0)
        ++envCount;
    os << "  envp        : " << envCount << " entries\n";
    for (uint64_t i = 0; i < envCount && i < 3; ++i) {
        const uint64_t ptr = mem.read64(stack.envpAddr + i * 8);
        os << "    envp[" << i << "]   : \"" << readGuestString(mem, ptr) << "\"\n";
    }

    os << "  auxv        :\n";
    for (uint64_t i = 0; ; ++i) {
        const uint64_t key   = mem.read64(stack.auxvAddr + i * 16);
        const uint64_t value = mem.read64(stack.auxvAddr + i * 16 + 8);

        os << "    " << std::left << std::setw(12) << auxvName(key)
           << " = 0x" << std::hex << value << std::dec;

        // Annotate the entries whose values point at something.
        if (key == Elf::AT_EXECFN || key == Elf::AT_PLATFORM)
            os << "  \"" << readGuestString(mem, value) << "\"";
        else if (key == Elf::AT_PAGESZ)
            os << "  (" << value << " bytes)";

        os << "\n";

        if (key == Elf::AT_NULL)
            break;
    }
    os << "\n";
}

} // namespace Runtime
