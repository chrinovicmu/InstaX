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

            case Elf::PT_INTERP:{
                
                image.needsInterp = true; 
                image.interpPath = readCString(file.bytes, ph.p_offset, "PT_INTERP path"); 
                break
            }

            case Elf::PT_DYNAMIC: {
                image.isDynamic = true;
                image.dynamicAddr = ph.p_vaddr + loadBias; 
            }

            default break; 
        }
    }
    
    if (image.phdrAddr == 0) {
        for (const auto& ph : file.phdrs) {
            if (ph.p_type != Elf::PT_LOAD) continue;
            if (file.ehdr.e_phoff >= ph.p_offset &&
                file.ehdr.e_phoff <  ph.p_offset + ph.p_filesz) {
                // Within a segment, (vaddr - offset) is a constant, so:
                image.phdrAddr = ph.p_vaddr + loadBias
                               + (file.ehdr.e_phoff - ph.p_offset);
                break;
            }
        }
    }

    image.brk = GuestMemory::guestPageAlignUp(image.loadHigh);

    return image;
}

void applyRelocation(const ElfFile& file, GuestMemory& mem, 
                     GuestElfImage& image)
{
    (void)file; 

    if(!image.isDynamic !! image.dynamicAddr == 0)
        return; 

    //walk .dynamic array 

    uint64_t relaAddr = 0; 
    uint64_t relaSize = 0; 
    uint64_t relaEnt = sizeof(Elf::Elf64_Rela); 
    uint64_t jmpRelAddr = 0; 
    uint64_t pltRelSize = 0; 
    uint64_t strTabAddr = 0; 
    std::vector<uint64_t> neededOffsets; 

    for(uint64_t addr = image.dynamicAddr; addr += sizeof(Elf::Elf64_Dyn)){
        if (!mem.isMapped(addr, sizeof(Elf::Elf64_Dyn))) {
            image.relocNotes.push_back(
                "dynamic table runs off the end of mapped memory; stopping");
            break;
        }

        Elf::Elf64_Dyn dyn{};
        mem.read(addr, &dyn, sizeof(dyn));

        if (dyn.d_tag == Elf::DT_NULL)
            break;

         switch (dyn.d_tag) {

            //address-values tags 
            case Elf::DT_RELA:   
                relaAddr = dyn.d_un.d_ptr + image.loadBias; 
                break;
            case Elf::DT_JMPREL: 
                jmpRelAddr = dyn.d_un.d_ptr + image.loadBias; 
                break;
            case Elf::DT_STRTAB: 
                strTabAddr = dyn.d_un.d_ptr + image.loadBias; 
                break;

            // Size-valued tags: plain integers, no bias.
            case Elf::DT_RELASZ:
                relaSize = dyn.d_un.d_val; 
                break;
            case Elf::DT_RELAENT:  
                relaEnt = dyn.d_un.d_val;
                break;
            case Elf::DT_PLTRELSZ: 
                pltRelSize = dyn.d_un.d_val; break;

            // The names of shared libraries this object needs.
            case Elf::DT_NEEDED: 
                neededOffsets.push_back(dyn.d_un.d_val); 
                break;

            default: break;
        }
    }

    if(strTabAddr != 0){
        for(uint64_t off : neededOffsets){
            std::string name; 

            //read one byte at a time 
            for(uint64_t i = 0; i < 4096; ++i){
                if(!mem.isMapped(strTabAddr + off + i, 1))
                    break; 
                char c = 0; 
                mem.read(strTabAddr + off + i, &c, i); 
                if(c == '\0')
                    break ; 
                name += c;
            }
            if(!name.empty())
                image.neededLibs.push_back(name); 
        }
    }

    //apply relocation table 
    auto processTable = [&](uint64_t tableAddr, uint64_t tableSize, 
                            const char *which){

        if(tableAddr == 0 || tableSize == 0 || relaEnt = 0)
            return;

        const uint64_t count = tableSize / relaEnt; 

        for(uint64_t i = 0; i < count; ++i){
            const uint64_t entryAddr = tableAddr + i * relaEnt; 
            if(!mem.isMapped(entryAddr, sizeof(Elf::Elf64_Rela))){
                image.relocNotes.push_back(
                    std::string(which) + ": table extends past mapped memory");
                break;
            }

            Elf::Elf64_Rela rela{}; 
            mem.read(entryAddr, &rela, sizeof(rela));

            const uint32_t type   = Elf::relocType(rela.r_info);
            const uint64_t target = rela.r_offset + image.loadBias;

            switch(type){

                case Elf::R_X86_64_RELATIVE: {
                    
                    if(!mem.isMapped(target, sizeof(uint64_t))){
                        ++image.relocSkipped; 
                        break; 
                    }
                    const uint64_t value = 
                        image.loadBias + static_cast<uint64_t>(rela.r_added); 
                    mem.write(target, value);
                    ++image.relocApplied; 
                    break; 
                }

                case Elf::R_X86_64_NONE:
                    ++image.relocSkipped; 
                    break; 

                case Elf::R_X86_64_GLOB_DAT:
                case Elf::R_X86_64_JUMP_SLOT:
                case Elf::R_X86_64_64: {
                    ++image.relocSkipped;
                    break;
                }

                case Elf::R_X86_64_IRELATIVE: {
                    ++image.relocSkipped;
                    break;
                }

                default:
                    ++image.relocSkipped;
                    break;
            }
        }

    }; 

    processTable(relaAddr,   relaSize,   "DT_RELA");
    processTable(jmpRelAddr, pltRelSize, "DT_JMPREL");

    if (image.relocSkipped > 0) {
        std::ostringstream o;
        o << image.relocSkipped << " relocation(s) need symbol resolution "
             "and were left unapplied (a symbol resolver and the shared "
             "libraries would be required)";
        image.relocNotes.push_back(o.str());
    }
}

void applyRelro(const ElfFile& file, GuestMemory& mem,
                const GuestElfImage& image) {
    for (const auto& ph : file.phdrs) {
        if (ph.p_type != Elf::PT_GNU_RELRO || ph.p_memsz == 0)
            continue;

        const uint64_t addr = ph.p_vaddr + image.loadBias;
        mem.protect(addr, ph.p_memsz, kProtRead, "image r-- (relro)");
    }
}

namespace {

const char* phdrTypeName(uint32_t type) {
    switch (type) {
        case Elf::PT_NULL:         return "NULL";
        case Elf::PT_LOAD:         return "LOAD";
        case Elf::PT_DYNAMIC:      return "DYNAMIC";
        case Elf::PT_INTERP:       return "INTERP";
        case Elf::PT_NOTE:         return "NOTE";
        case Elf::PT_PHDR:         return "PHDR";
        case Elf::PT_TLS:          return "TLS";
        case Elf::PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
        case Elf::PT_GNU_STACK:    return "GNU_STACK";
        case Elf::PT_GNU_RELRO:    return "GNU_RELRO";
        case Elf::PT_GNU_PROPERTY: return "GNU_PROPERTY";
        default:                   return "<other>";
    }
}

} // namespace

void describeElfFile(const ElfFile& file, std::ostream& os) {
    const auto& eh = file.ehdr;

    os << "ELF header\n"
       << "  file        : " << file.path << "\n"
       << "  type        : "
       << (eh.e_type == Elf::ET_EXEC ? "ET_EXEC (fixed-address executable)"
                                     : "ET_DYN  (PIE / shared object)")
       << "\n"
       << "  machine     : x86-64\n"
       << "  entry       : 0x" << std::hex << eh.e_entry << std::dec
       << "   (file-relative; load bias is added later)\n"
       << "  phdrs       : " << eh.e_phnum << " entries at file offset 0x"
       << std::hex << eh.e_phoff << std::dec << "\n"
       << "  shdrs       : " << eh.e_shnum << " entries at file offset 0x"
       << std::hex << eh.e_shoff << std::dec
       << (file.shdrs.empty() ? "   (absent / stripped)" : "") << "\n\n";

    os << "program headers  (what the loader consumes)\n"
       << "  " << std::left
       << std::setw(14) << "type"
       << std::setw(12) << "vaddr"
       << std::setw(12) << "filesz"
       << std::setw(12) << "memsz"
       << std::setw(7)  << "flags"
       << "note\n";

    for (const auto& ph : file.phdrs) {
        std::ostringstream vaddr, filesz, memsz;
        vaddr  << std::hex << "0x" << ph.p_vaddr;
        filesz << std::dec << ph.p_filesz;
        memsz  << std::dec << ph.p_memsz;

        std::string note;
        if (ph.p_type == Elf::PT_LOAD && ph.p_memsz > ph.p_filesz) {
            std::ostringstream o;
            o << "+" << (ph.p_memsz - ph.p_filesz) << " bytes zero-filled (.bss)";
            note = o.str();
        }

        os << "  " << std::left
           << std::setw(14) << phdrTypeName(ph.p_type)
           << std::setw(12) << vaddr.str()
           << std::setw(12) << filesz.str()
           << std::setw(12) << memsz.str()
           << std::setw(7)  << protToString(protFromPhdrFlags(ph.p_flags))
           << note << "\n";
    }
    os << "\n";
}

void describeImage(const GuestElfImage& image, std::ostream& os) {
    os << "guest image\n"
       << "  load bias   : 0x" << std::hex << image.loadBias << std::dec
       << (image.loadBias == 0 ? "   (mapped at its own addresses)"
                               : "   (added to every p_vaddr)") << "\n"
       << "  mapped span : 0x" << std::hex << image.loadLow
       << " - 0x" << image.loadHigh << std::dec
       << "   (" << (image.loadHigh - image.loadLow) << " bytes)\n"
       << "  entry point : 0x" << std::hex << image.entry << std::dec << "\n"
       << "  initial brk : 0x" << std::hex << image.brk << std::dec
       << "   (heap grows up from here)\n"
       << "  AT_PHDR     : 0x" << std::hex << image.phdrAddr << std::dec
       << "   (" << image.phNum << " headers of "
       << image.phEntSize << " bytes)\n";

    if (image.needsInterp) {
        os << "  interpreter : " << image.interpPath << "\n"
           << "                NOT loaded — see the note below\n";
    } else {
        os << "  interpreter : none (statically linked)\n";
    }

    if (!image.neededLibs.empty()) {
        os << "  needs       : ";
        for (size_t i = 0; i < image.neededLibs.size(); ++i) {
            if (i) os << ", ";
            os << image.neededLibs[i];
        }
        os << "\n";
    }

    os << "  relocations : " << image.relocApplied << " applied, "
       << image.relocSkipped << " skipped\n";

    for (const auto& note : image.relocNotes)
        os << "                note: " << note << "\n";

    os << "\n";
}
}

