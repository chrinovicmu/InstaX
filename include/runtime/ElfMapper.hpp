#include "runtime/ElfTypes.hpp"
#include "runtime/GuestMemory.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <iosfwd>

namespace Runtime{

//Parsed ELF file 
stuct ElfFile{
    std::string path; 
    std::vector<uint8_t> bytes; 
    Elf::Elf64_Ehdr  ehdr{}; 
    std::vector<Elf::Elf64_Phdr> phdrs; 
    std::vector<Elf::Elf64_Shdr> shdrs; 

    bool isPie() const { return ehdr.e_type == Elf::ET_DYN; } 
    bool isFixedExe() const { return ehdr.e_type == Elf::ET_EXEC; }
};


struct GuestElfImage{
    std::string path; 
    bool isPie = false; 
    bool isDynamic = false; 
    bool needsInterp = false; 

    uint64_t loadBias = 0; 
    uint64_t entry = 0;     //e_entry + loadBias: where execution starts 
    uint64_t loadLow = 0;   //lowest mapped addrress 
    uint64_t loadBHigh = 0; //one past highest mapped addrress
    uint64_t brk;           //initial program break(heap start) 

    //auxilary vector 

}; 

//read path and decode it;s header tables 

ElfFile readElfFile(const std::string& path); 

//the address span the image occupies(before bias) 
void computeLoadSpan(const ElfFile& file, uint64_t& low, uint64_t& high); 

//pick load bias
//ET_EXEC : always 0: the addrresses in the file are absolute and 
//program wil not work anywhere else 
//
//ET_DYN: prefferedBase. PIE's p_addr values are offset 
//from a base the loader chooses

uint64_t choooseBias(const ElfFile& file, uint64_t prefferedBase); 

//mapping 
//place PT_LOAD segments itno memory at (p_addr + loadBias)
//zero filee .bss 
//set permissons 
GuestElfImage mapImage(const ElfFile& file, GuestMemory& mem, uint64_t loadBias); 

void applyRelocations(const ElfFile& FILE, GuestMemory& mem, GuestElfImage& image); 

void applyRelro(const ElfFile& file, GuestMemory& mem, const GuestElfImage& image); 

void elfFileInfo(const ElfFile& file, std::ostream& os);

// Print the summary of what was placed where.
void imageInfo(const GuestElfImage& image, std::ostream& os);
}
