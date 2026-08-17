#include "runtime/ElfMapper.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <stdexcept>

namespace Runtime{

namespace{

template <tyename T> 
T readStruct(const std::vector<uint8_t>& bytes, uint64_t offset, 
             const char* what){
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        std::ostringstream o;
        o << "ELF: truncated file — cannot read " << what
          << " at offset 0x" << std::hex << offset;
        throw std::runtime_error(o.str());
    }
    T value;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

// Read a NUL-terminated string out of the file buffer, refusing to run off
// the end if the terminator is missing.
std::string readCString(const std::vector<uint8_t>& bytes, uint64_t offset,
                        const char* what) {
    if (offset >= bytes.size()) {
        std::ostringstream o;
        o << "ELF: " << what << " offset 0x" << std::hex << offset
          << " lies past the end of the file";
        throw std::runtime_error(o.str());
    }
    const char* start = reinterpret_cast<const char*>(bytes.data() + offset);
    const size_t maxLen = bytes.size() - offset;
    const size_t len = ::strnlen(start, maxLen);
    return std::string(start, len);
}

}

ElfFile readElfFile(const std::string& path){
    ElfFile file; 
    file.path = path; 

    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in)
        throw std::runtime_error("ELF: cannot open '" + path + "'");

    const std::streamsize size = in.tellg();
    if (size <= 0)
        throw std::runtime_error("ELF: '" + path + "' is empty");

    in.seekg(0, std::ios::beg);
    file.bytes.resize(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char*>(file.bytes.data()), size))
        throw std::runtime_error("ELF: short read on '" + path + "'");

    file.ehdr = readStruct<Elf::Elf64_Ehdr>(file.bytes, 0, "ELF header");
    const Elf::Elf64_Ehdr& eh = file.ehdr; 

    //Tmagic bytes. Anything else is not an ELF file at all.
    if (eh.e_ident[Elf::EI_MAG0] != Elf::ELFMAG0 ||
        eh.e_ident[Elf::EI_MAG1] != Elf::ELFMAG1 ||
        eh.e_ident[Elf::EI_MAG2] != Elf::ELFMAG2 ||
        eh.e_ident[Elf::EI_MAG3] != Elf::ELFMAG3)
        throw std::runtime_error("ELF: '" + path + "' is not an ELF file "
                                 "(bad magic)");

    if (eh.e_ident[Elf::EI_CLASS] != Elf::ELFCLASS64)
        throw std::runtime_error("ELF: '" + path + "' is 32-bit; "
                                 "only ELF64 is supported");

    if (eh.e_ident[Elf::EI_DATA] != Elf::ELFDATA2LSB)
        throw std::runtime_error("ELF: '" + path + "' is big-endian; "
                                 "only little-endian is supported");

    if (eh.e_machine != Elf::EM_X86_64) {
        std::ostringstream o;
        o << "ELF: '" << path << "' targets e_machine=" << eh.e_machine
          << ", but this translator only accepts x86-64 (" << Elf::EM_X86_64 << ")";
        throw std::runtime_error(o.str());
    }

    // ET_REL (a .o) has no program headers and cannot be run; ET_CORE is a
    // dump. Only ET_EXEC and ET_DYN are loadable.
    if (eh.e_type != Elf::ET_EXEC && eh.e_type != Elf::ET_DYN)
        throw std::runtime_error("ELF: '" + path + "' is not an executable "
                                 "or shared object (e_type is neither "
                                 "ET_EXEC nor ET_DYN)");

    if (eh.e_phnum > 0) {
        if (eh.e_phentsize != sizeof(Elf::Elf64_Phdr)) {
            std::ostringstream o;
            o << "ELF: e_phentsize is " << eh.e_phentsize << ", expected "
              << sizeof(Elf::Elf64_Phdr);
            throw std::runtime_error(o.str());
        }
        file.phdrs.reserve(eh.e_phnum); 
        for (uint64_t i = 0; i < eh.e_phnum; ++i) {
            const uint64_t offset = eh.e_phoff + i * eh.e_phentsize;
            file.phdrs.push_back(readStruct<Elf::Elf64_Phdr>(
                file.bytes, offset, "program header"));
        }
    }

    if (eh.e_shoff != 0 && eh.e_shnum > 0 &&
        eh.e_shentsize == sizeof(Elf::Elf64_Shdr)) {
        file.shdrs.reserve(eh.e_shnum);
        for (uint64_t i = 0; i < eh.e_shnum; ++i) {
            const uint64_t offset = eh.e_shoff + i * eh.e_shentsize;
            if (offset + sizeof(Elf::Elf64_Shdr) > file.bytes.size())
                break;                     // truncated table: keep what we got
            file.shdrs.push_back(readStruct<Elf::Elf64_Shdr>(
                file.bytes, offset, "section header"));
        }
    }

    return file; 
}

void computeLoadSpan(const ElfFile& file, uint64_t& low, uint64_t& high){
    bool found = false; 
    uint64_t minAddr = UINT64_MAX; 
    uint64_t maxAddr = 0; 

    for(const auto& ph : file.phdrs){
        if(ph.p_type != Elf::PT_LOAD)
            continue; 

        const uint64_t segLow  = ph.p_vaddr;
        const uint64_t segHigh = ph.p_vaddr + ph.p_memsz;

        minAddr = std::min(minAddr, segLow);
        maxAddr = std::max(maxAddr, segHigh);
        found = true;
    }

    if (!found)
        throw std::runtime_error(
            "ELF: '" + file.path + "' has no PT_LOAD segments — "
            "there is nothing to map");

    low  = GuestMemory::guestPageAlignDown(minAddr);
    high = GuestMemory::guestPageAlignUp(maxAddr);
}

uint64_t chooseLoadBias(const ElfFile& file, uint64_t preferredBase) {
    if (file.isFixedExe())
        return 0;

    return preferredBase;
}

GuestElfImage mapImage(const ElfFile& file, GuestMemory& mem, uint64_t loadBias){
    GuestElfImage image;
    image.path      = file.path;
    image.isPie     = file.isPie();
    image.loadBias  = loadBias;
    image.entry     = file.ehdr.e_entry + loadBias;
    image.phEntSize = file.ehdr.e_phentsize;
    image.phNum     = file.ehdr.e_phnum;

    uint64_t spanLow = 0, spanHigh = 0;
    computeLoadSpan(file, spanLow, spanHigh);

    image.loadLow  = spanLow  + loadBias;
    image.loadHigh = spanHigh + loadBias;

    //map entire image 
    mem.map(image.loadLow, image.loadHigh - image.loadLow, 
            kProtRead | kProtWrite, "iamge");

    //copy each segment's content

    for(const auto& ph : file.phdrs){
        if(ph.p_type != Elf::PT_LOAD || ph.p_memsz == 0) 
            continue; 

        const uint64_t guestAddr = ph.p_vaddr + loadBias;

        // Bounds-check the file range before reading it. A corrupt or
        // hostile p_offset/p_filesz would otherwise read past our buffer.
        if (ph.p_filesz > 0) {
            if (ph.p_offset > file.bytes.size() ||
                file.bytes.size() - ph.p_offset < ph.p_filesz) {
                std::ostringstream o;
                o << "ELF: PT_LOAD claims " << ph.p_filesz
                  << " bytes at file offset 0x" << std::hex << ph.p_offset
                  << ", which runs past the end of the file";
                throw std::runtime_error(o.str());
            }

            mem.write(guestAddr, 
                      file.bytes() + ph.p_offset, 
                      static_cast<size_t>(ph.p_filesz)); 
        }

        //for .bss 
        if(ph.p_memsz > ph.p_filesz){
            mem.zero(guestAddr + ph.p_filesz, 
                     static_cast<size_t>(ph.p_memsz - ph.p_filesz)); 
        }
    }

    //apply per-segment permisson 
    for (const auto& ph : file.phdrs) {
        if (ph.p_type != Elf::PT_LOAD || ph.p_memsz == 0)
            continue;

        const uint64_t guestAddr = ph.p_vaddr + loadBias;
        const int prot = protFromPhdrFlags(ph.p_flags);

        // Label the region by what it actually is, which makes the memory
        // dump readable: "r-x" is the text segment, "rw-" the data segment.
        std::string label = "image ";
        label += protToString(prot);

        if (ph.p_flags & Elf::PF_X){
            label += " (text)";
        }else if (ph.p_flags & Elf::PF_W){
            label += " (data/bss)";
        }else{
            label += " (rodata)";
        }

        mem.protect(guestAddr, ph.p_memsz, prot, label);
    }

    //other program header we casr about 
    for(const auto& ph : file.phdrs){
        switch(ph.p_type){

            case Elf::PT_INTERP: 
                
                image.needsInterp = true; 
                image.interpPath = readCString(file.bytes, ph.p_offset, "PT_INTERP path"); 
                break
            
            case Elf::PT_DYNAMIC: 
        }
    }




}
}
}

