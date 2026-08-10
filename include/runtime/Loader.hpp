#pragma once

namespace Runtime{

struct LoadOptions{

    //ignored for ET_EXEC
    uint64_t pieBase = 0x400000;

    //only usable when identity mapping succeeds: 
    uint64_t stackTop = 0x7ffffffff000ull;

    //8 MiB
    uint64_t stackSize = 8ull * 1024 * 1024;  

    uint64_t fallbackWindowSize = 4ull << 30; //4GB 
};

//Initial uest CPU state*/ 
struct GuestCpuState{
    uint64_t rip = 0; 
    uint64_t rsp = 0; 
    uint64_t rdx = 0; 
};

class GuestProcess{
public: 

    static GuestProcess load(const std::string& path, 
                             const std::vector<std::string>& argv, 
                             const std::vector<std::string>& envp, 
                             const LoadOptions& option = {}); 
    
    // Movable, not copyable: it owns a GuestMemory, which owns mappings.
    GuestProcess(GuestProcess&&)            = default;
    GuestProcess& operator=(GuestProcess&&) = default;

    GuestMemory&       memory()       { return *m_memory; }
    const GuestMemory& memory() const { return *m_memory; }

    const ElfFile&        file()  const { return m_file;  }
    const GuestElfImage&  image() const { return m_image; }
    const GuestStackImage& stack() const { return m_stack; }
    const GuestCpuState&  cpu()   const { return m_cpu;   }

    uint64_t entry()      const { return m_cpu.rip; }
    uint64_t initialRsp() const { return m_cpu.rsp; }

  // Read guest code bytes for translation. This is the bridge from the
    // loader to the lifter: give it a guest address and a length, get the
    // x86-64 bytes that live there.
    //
    // Throws if the range is not mapped, which is the correct response to
    // the translator following a bad jump target.
    std::vector<uint8_t> readCode(uint64_t guestAddr, size_t length) const;


    void guestProcessInfo(std::ostream& os) const;

private: 

    GuestProcess() = default; 

    std::unique_ptr<GuestMemory> m_memory; 

    ElfFile m_file; 
    GuestElfImage m_image; 
    GuestStackImage m_stack; 
    GuestCpuState m_cpu; 
};
}
