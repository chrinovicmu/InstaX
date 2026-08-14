#include "runtime/GuestMemory.hpp"

#include <sys/mman.h>     
#include <unistd.h>       

#include <algorithm>      
#include <cstring>      
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <iomanip>

namespace Runtime {

#ifndef MAP_ANONYMOUS
#  ifdef MAP_ANON
#    define MAP_ANONYMOUS MAP_ANON
#  else
#    error "no anonymous mmap flag available on this platform"
#  endif
#endif

#ifndef MAP_FIXED_NOREPLACE
#  define MAP_FIXED_NOREPLACE 0
#endif

namespace{

// Round `value` down to a multiple of `alignment` (a power of two).
inline uint64_t alignDown(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1);
}

// Round `value` up to a multiple of `alignment` (a power of two).
inline uint64_t alignUp(uint64_t value, uint64_t alignment) {
    return alignDown(value + alignment - 1, alignment);
}
}

// Translate ELF program-header flags into our guest permission bitmask.
// A straight bit-for-bit remap; it exists so that no other file has to know
// the PF_* encoding.
int protFromPhdrFlags(uint32_t pFlags) {
    int prot = kProtNone;
    if (pFlags & Elf::PF_R) prot |= kProtRead;
    if (pFlags & Elf::PF_W) prot |= kProtWrite;
    if (pFlags & Elf::PF_X) prot |= kProtExec;
    return prot;
}

// "rwx" style rendering for the memory map dump.
std::string protToString(int guestProt) {
    std::string s;
    s += (guestProt & kProtRead)  ? 'r' : '-';
    s += (guestProt & kProtWrite) ? 'w' : '-';
    s += (guestProt & kProtExec)  ? 'x' : '-';
    return s;
}

namespace{

int hostProtFor(int guestProt) {
    if (guestProt == kProtNone)
        return PROT_NONE;

    int hostProt = PROT_READ;                        // always readable
    if (guestProt & kProtWrite) hostProt |= PROT_WRITE;
    // Intentionally no PROT_EXEC, for any guest permission combination.
    return hostProt;
}

}

uint64_t GuestMemory::guestPageAlignDown(uint64_t addr) {
    return alignDown(addr, Elf::GUEST_PAGE_SIZE);
}

uint64_t GuestMemory::guestPageAlignUp(uint64_t addr) {
    return alignUp(addr, Elf::GUEST_PAGE_SIZE);
}

uint64_t GuestMemory::hostPageSize() {
    static const uint64_t cached = []() -> uint64_t {
        long v = ::sysconf(_SC_PAGESIZE);
        return v > 0 ? static_cast<uint64_t>(v) : 4096;
    }();
    return cached;
}

GuestMemory::GuestMemory(uint64_t imageLow, 
                         uint64_t imageHgh, 
                         uint64_t fallBackWindowSize){

    const uint64_t hostPage = hostPageSize();
    const uint64_t probeLow = alignDown(imageLow, hostPage);
    const uint64_t probeHigh = alignUp(imageHgh, hostPage); 
    const uint64_t probeSize = probeHigh - probeLow; 

    if (probeSize == 0)
        throw std::invalid_argument("GuestMemory: empty image span");

    void* identity = ::mmap(reinterpret_cast<void*>(probeLow), 
                            probeSize, 
                            PROT_NONE, 
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 
                            -1, 0); 
    if(identity != MAP_FAILED && 
       reinterpret_cast<uint64_t>(identity) == probeLow){

        m_hostOffset = 0; 
        m_windowBase = identity; 
        m_windowSize = probeSize; 
        m_reservedLow = probeLow; 
        m_reservedHigh = probeHigh; 
        return; 
    }

    //if mmap succeded but a different address
    if(identity != MAP_FAILED)
        ::munmap(identity, probeSize); 

    
    //falledback: bais mapping 

    uint64_t windowSize = alignUp(fallBackWindowSize, hostPage); 
    if(windowSize < probeSize)
        windowSize = alignUp(probeSize * 2, hostPage); 
        
    void* window = ::mmap(nullptr,
                          windowSize, 
                          PROT_NONE, 
                          MAP_PRIVATE | MAP_ANONYMOUS, 
                          -1, 0); 

    if (window == MAP_FAILED)
        throw std::runtime_error(
            "GuestMemory: could not reserve a guest address window "
            "(identity mapping was refused and the fallback reservation "
            "failed too)");

    m_windowBase = window;
    m_windowSize = windowSize;

    m_hostOffset = reinterpret_cast<uint64_t>(window) - probeLow;
    m_reservedLow = probeLow;
    m_reservedHigh = probeLow + windowSize;
}

bool GuestMemory::isAddressable(uint64_t guestAddr, uint64_t length) const{
    //indenty mode: the uest address is a host address, so 
    //anythin the host can map is addressable 
    if(isIdenity())
        return true; 

    if(guestAddr < m_reservedLow) 
        return false; 
    const uint64_t end = guestAddr + length; 
    if(end < guestAddr)
        return false; 
    return end <= m_reservedHigh; 
}

GuestMemory::~GuestMemory(){
    if(m_windowBase != nullptr)
        ::munmap(m_windowBase, m_windowSize); 
}

//address translation 
void* GuestMemory::toHost(uint64_t guestAddr){
    if(!isMapped(guestAddr, 1))
        throw std::out_of_range(
            "GuestMemory::toHost: unmapped guest address 0x" +
            [&]{ std::ostringstream o; o << std::hex << guestAddr; return o.str(); }());

    return reinterpret_cast<void*>(guestAddr + m_hostOffset);
}

const void* GuestMemory::toHost(uint64_t guestAddr) const{
    return const_cast<GuestMemory*>(this)->toHost(guestAddr); 
}

uint64_t GuestMemory::toGuest(const void* hostptr) const{
    return reinterpret_cast<uint64_t>(hostptr) - m_hostOffset; 
}


void GuestMemory::map(uint64_t guestAddr, uint64_t length, int guestProt, 
                      std::string name){

    if(length == 0)
        return; 


}
const GuestRegion* GuestMemory::findRegion(uint64_t guestAddr){
    for(const auto& region: m_regions){
        if(guestAddr >= region.guestAddr && 
           guestAddr < region.guestAddr + region.length)
            return &region; 
    }
    return nullptr; 
}

bool GuestMemory::isMapped(uint64_t guestAddr, uint64_t length) const{
    if(length == 0)
        return true; 

    const uint64_t first = guestPageAlignDown(guestAddr); 
    const uint64_t last = guestPageAlignUp(guestAddr + length -1); 

    for(uint64_t page = first; page <= last; page += Elf::GUEST_PAGE_SIZE){
        if(findRegion(page) == nullptr)
            return flase; 

        //guard against wrap around 
        if(page + Elf::GUEST_PAGE_SIZE < page)
            break
    }

    return true; 
}

void GuestMemory::dump(std::ostream& os) const {
    os << "guest address space  ("
       << (isIdentity() ? "IDENTITY mapped — guest address == host address"
                        : "BIASED mapping")
       << ")\n";

    if (!isIdentity()) {
        os << "  host offset : 0x" << std::hex << m_hostOffset << std::dec
           << "   (host = guest + offset)\n";
    }
    os << "  host page   : " << hostPageSize() << " bytes"
       << "   guest page : " << Elf::GUEST_PAGE_SIZE << " bytes\n\n";

    os << "  " << std::left
       << std::setw(26) << "guest range"
       << std::setw(12) << "size"
       << std::setw(7)  << "perms"
       << "name\n";

    for (const auto& region : m_regions) {
        std::ostringstream range;
        range << std::hex << "0x" << region.guestAddr
              << "-0x" << (region.guestAddr + region.length);

        std::ostringstream size;
        size << std::dec << region.length;

        os << "  " << std::left
           << std::setw(26) << range.str()
           << std::setw(12) << size.str()
           << std::setw(7)  << protToString(region.prot)
           << region.name << "\n";
    }
}
}
