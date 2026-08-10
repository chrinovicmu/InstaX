#include "runtime/ElfTypes.hpp"

#include <cstdint> 
#include <cstddef> 
#include <string> 
#include <vector> 
#include <iosfwd> 

namespace Runtime {

enum GuestProt : int{
    kProtNone = 0, 
    kProtRead = 1 << 0, 
    kProtWrite = 1 << 1, 
    kProtExec = 1 << 2, 
}; 

int protFromPhdrFlags(uint32_t pFlags); 

std::string protToString(int guestProt); 

struct GuestRegion{
    uint64_t guestAddr; 
    uint64_t length; 
    int prot; 
    std::string name; 
}; 

class GuestMemory{
public: 

    GuestMemory(uint64_t imageLow, 
                uint64_t imageHigh,

                //if identity mapping fails 
                uint64_t fallbackWindowSize = (4ull << 30)); 4 GiB 
    
    ~GuestMemory(); 

    GuestMemory(const GuestMemory&) = delete; 
    GuestMemory& operator = (const GuestMemory&) = delete; 

    bool isIdentity() const { return m_hostOffset = 0; }
    uint64_t hostOffset() const { return m_hostOffset; }

    void* toHost(uint64_t guestAddr); 
    const void* toHost(uint64_t guestAddr) const; 

    uint64_t toGuest(const void* hostPtr) const;

    //commit anonymous, zero-filled memory at guestAddr, guestAddr+length
    void map(uint64_t guestAddr, uint64_t length, int guestProt, 
             std::string name); 

    //Change the recordded guest permissions 
    void protect(uint64_t guestAddr, uint64_t length, int guestProt,
                 const std::string& name = "");

    void write(uint64_t guestAddr, const void* src, size_t n);
    void read(uint64_t guestAddr, void* dst, size_t n) const;
    void zero(uint64_t guestAddr, size_t n);

    void write64(uint64_t guestAddr, uint64_t value);
    uint64_t read64(uint64_t guestAddr) const;

 // Is every byte of [guestAddr, guestAddr+length) mapped?
    bool isMapped(uint64_t guestAddr, uint64_t length = 1) const;

    // The guest permissions in force at an address, or kProtNone if
    // unmapped. This is what a guest-visible permission check consults.
    int protAt(uint64_t guestAddr) const;

    const std::vector<GuestRegion>& regions() const { return m_regions; }

    // The guest address range covered by our up-front reservation.
    //
    // In biased mode this is a hard boundary: a single offset translates
    // every guest address, so anything outside this window has no host
    // address at all and cannot be mapped. Callers that get to choose an
    // address — the stack, most obviously — must consult this.
    //
    // In identity mode the reservation only covers the executable image;
    // addresses outside it are still mappable, they just have to be claimed
    // from the host rather than carved out of what we already hold.
    uint64_t reservationLow()  const { return m_reservedLow;  }
    uint64_t reservationHigh() const { return m_reservedHigh; }

    // Can this range be given a host address at all under the current
    // mapping mode? Always true in identity mode (the whole 64-bit space is
    // in principle available); bounded by the window in biased mode.
    bool isAddressable(uint64_t guestAddr, uint64_t length) const;

    void dump(std::ostream& os) const;

    static uint64_t guestPageAlignDown(uint64_t addr);
    static uint64_t guestPageAlignUp(uint64_t addr);

    static uint64_t hostPageSize();

private:
    // Apply the host-level protection implied by a guest permission set to
    // an already-mapped range. Separated out because the guest->host
    // permission policy (notably: never PROT_EXEC) lives in one place.
    void applyHostProtection(uint64_t guestAddr, uint64_t length, int guestProt);

    // Find the region containing an address, or nullptr.
    const GuestRegion* findRegion(uint64_t guestAddr) const;

    uint64_t m_hostOffset = 0;      // host = guest + this

    // In biased mode we hold one big PROT_NONE reservation and carve
    // mappings out of it, so that no unrelated allocation can land in the
    // middle of the guest's address space. Unused in identity mode.
    void*    m_windowBase = nullptr;
    uint64_t m_windowSize = 0;

    // The reservation expressed in GUEST coordinates, so callers can ask
    // about it without knowing the host offset.
    uint64_t m_reservedLow  = 0;
    uint64_t m_reservedHigh = 0;

    std::vector<GuestRegion> m_regions;
}; 

}
