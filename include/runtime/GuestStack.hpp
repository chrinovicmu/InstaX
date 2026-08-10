#include "runtime/ElfMapper.hpp"
#include "runtime/GuestMemory.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <iosfwd>

namespace Runtime {

struct GuestStackImage {
    uint64_t low  = 0;    // lowest mapped stack address (the guard end)
    uint64_t top  = 0;    // one past the highest mapped address
    uint64_t size = 0;

    // The value to put in the guest's RSP when execution begins. Points at
    // argc, and is 16-byte aligned.
    uint64_t rsp  = 0;

    // Guest addresses of the three arrays, for inspection and debugging.
    uint64_t argvAddr = 0;
    uint64_t envpAddr = 0;
    uint64_t auxvAddr = 0;

    uint64_t argc = 0;
};

// stackTop is the highest guest address the stack occupies (it grows down
// from there), and must be page aligned. On real x86-64 Linux this sits
// just below the top of user space, around 0x7ffffffff000; the caller
// chooses, because in a biased mapping the address has to land inside the
// reserved window.
//
// argv[0] conventionally repeats the program path, and the caller is
// responsible for that convention — this function stores exactly the
// strings it is given.
GuestStackImage buildInitialStack(GuestMemory& mem,
                                  const GuestElfImage& image,
                                  const std::vector<std::string>& argv,
                                  const std::vector<std::string>& envp,
                                  uint64_t stackTop,
                                  uint64_t stackSize);

void stackInfo(const GuestStackImage& stack, const GuestMemory& mem,
                   std::ostream& os);
} 

