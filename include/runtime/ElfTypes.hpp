#pragma once 

#include <cstdint>
#include <cstddef> 

namespace Elf{

using Elf64_Addr = uint64_t;   
using Elf64_Off  = uint64_t;
using Elf64_Half = uint16_t;
using Elf64_Word = uint32_t;
using Elf64_Sword = int32_t;    
using Elf64_Xword = uint64_t;   
using Elf64_Sxword = int64_t;    
    
constexpr size_t EI_NIDENT = 16; 

// Indices into e_ident. Each names one byte of that 16-byte array.
constexpr size_t EI_MAG0 = 0;   // 0x7F
constexpr size_t EI_MAG1 = 1;   // 'E'
constexpr size_t EI_MAG2 = 2;   // 'L'
constexpr size_t EI_MAG3 = 3;   // 'F'
constexpr size_t EI_CLASS = 4;   // 32- or 64-bit
constexpr size_t EI_DATA = 5;   // endianness
constexpr size_t EI_VERSION = 6;   // always 1
constexpr size_t EI_OSABI = 7;   // target OS ABI
constexpr size_t EI_ABIVERSION = 8;

constexpr uint8_t ELFMAG0 = 0x7F;
constexpr uint8_t ELFMAG1 = 'E';
constexpr uint8_t ELFMAG2 = 'L';
constexpr uint8_t ELFMAG3 = 'F';

// e_ident[EI_CLASS] — pointer width of the target.
constexpr uint8_t ELFCLASSNONE = 0;
constexpr uint8_t ELFCLASS32   = 1;
constexpr uint8_t ELFCLASS64   = 2;

// e_ident[EI_DATA] — byte order of all multi-byte fields in the file.
constexpr uint8_t ELFDATANONE = 0;
constexpr uint8_t ELFDATA2LSB = 1;
constexpr uint8_t ELFDATA2MSB = 2;

// e_ident[EI_OSABI] — which OS's extensions the file may use.
constexpr uint8_t ELFOSABI_SYSV  = 0;
constexpr uint8_t ELFOSABI_LINUX = 3;

//etype 
constexpr Elf64_Half ET_NONE = 0;
constexpr Elf64_Half ET_REL  = 1;   
constexpr Elf64_Half ET_EXEC = 2;   
constexpr Elf64_Half ET_DYN  = 3;   

constexpr Elf64_Half ET_CORE = 4;

//e_machine 
constexpr Elf64_Half EM_NONE   = 0;
constexpr Elf64_Half EM_386    = 3;
constexpr Elf64_Half EM_X86_64 = 62;
constexpr Elf64_Half EM_AARCH64 = 183;
constexpr Elf64_Half EM_RISCV  = 243; 


struct Elf64_Ehdr{
    unsigned char e_ident[EI_NIDENT]; 
    Elf64_Half e_type; 
    Elf64_Half e_machine; 
    Elf64_Word e_version; 
    Elf64_Addr e_entry; 
    Elf64_Off e_phoff;
    Elf64_Off e_shoff; 
    Elf64_Word e_flags;
    Elf64_Half e_ehsize; 
    Elf64_Half e_phnum; 
    Elf64_Half e_shnum; 
    Elf64_Half e_shstrndx; 
};

//program header 

// p_type values.
constexpr Elf64_Word PT_NULL = 0;  
constexpr Elf64_Word PT_LOAD = 1;  
constexpr Elf64_Word PT_DYNAMIC = 2;  
constexpr Elf64_Word PT_INTERP = 3;  
constexpr Elf64_Word PT_NOTE = 4;  
constexpr Elf64_Word PT_SHLIB = 5;
constexpr Elf64_Word PT_PHDR = 6;
                                      
constexpr Elf64_Word PT_TLS = 7; 


// GNU extensions, seen in essentially every Linux binary.
constexpr Elf64_Word PT_GNU_EH_FRAME = 0x6474e550; // exception unwind index
constexpr Elf64_Word PT_GNU_STACK    = 0x6474e551; // p_flags says whether
                                                   // the stack is executable
constexpr Elf64_Word PT_GNU_RELRO    = 0x6474e552; // range to re-protect
                                                   // read-only after
                                                   // relocation
constexpr Elf64_Word PT_GNU_PROPERTY = 0x6474e553;

//p_flags
constexpr Elf64_Word PF_X = 0x1;   
constexpr Elf64_Word PF_W = 0x2;
constexpr Elf64_Word PF_R = 0x4;   

struct Elf64_Phdr{
    Elf64_Word p_type; 
    Elf64_Word p_flags; 
    Elf64_Off p_offset; 
    Elf64_Addr p_vaddr; 
    Elf64_Addr p_paddr; 
    Elf64_Xword p_filesx; 
    Elf64_Xword p_memsz; 
    Elf64_Xword p_align; 
};

// sh_type values.
constexpr Elf64_Word SHT_NULL     = 0;
constexpr Elf64_Word SHT_PROGBITS = 1;   // actual bytes (.text, .data)
constexpr Elf64_Word SHT_SYMTAB   = 2;   // full symbol table
constexpr Elf64_Word SHT_STRTAB   = 3;   // string table
constexpr Elf64_Word SHT_RELA     = 4;   // relocations WITH addends
constexpr Elf64_Word SHT_HASH     = 5;
constexpr Elf64_Word SHT_DYNAMIC  = 6;   // the .dynamic array
constexpr Elf64_Word SHT_NOTE     = 7;
constexpr Elf64_Word SHT_NOBITS   = 8;   // occupies no file space (.bss)
constexpr Elf64_Word SHT_REL      = 9;   // relocations without addends
constexpr Elf64_Word SHT_DYNSYM   = 11;  // symbols needed at run time

// sh_flags values.
constexpr Elf64_Xword SHF_WRITE     = 0x1;
constexpr Elf64_Xword SHF_ALLOC     = 0x2;   // occupies memory at run time
constexpr Elf64_Xword SHF_EXECINSTR = 0x4;

struct Elf64_Shdr{
    Elf64_Word sh_name; 
    Elf64_Word sh_type; 
    Elf64_Xword sh_flags; 
    Elf64_Addr sh_addr; 
    Elf64_Off sh_offset; 
    Elf64_Xword sh_size; 
    Elf64_Word sh_link;  
    Elf64_Word sh_info; 
    Elf64_Xword sh_addralign; 
    Elf64_Xword sh_entsize;
}; 

constexpr Elf64_Sxword DT_NULL     = 0;   // end of the array
constexpr Elf64_Sxword DT_NEEDED   = 1;   // strtab offset of a needed lib
constexpr Elf64_Sxword DT_PLTRELSZ = 2;   // size of the PLT relocations
constexpr Elf64_Sxword DT_PLTGOT   = 3;   // address of the PLT/GOT
constexpr Elf64_Sxword DT_HASH     = 4;
constexpr Elf64_Sxword DT_STRTAB   = 5;   // address of the string table
constexpr Elf64_Sxword DT_SYMTAB   = 6;   // address of the symbol table
constexpr Elf64_Sxword DT_RELA     = 7;   // address of the RELA relocations
constexpr Elf64_Sxword DT_RELASZ   = 8;   // total size of them, in bytes
constexpr Elf64_Sxword DT_RELAENT  = 9;   // size of one RELA entry
constexpr Elf64_Sxword DT_STRSZ    = 10;  // size of the string table
constexpr Elf64_Sxword DT_SYMENT   = 11;  // size of one symbol entry
constexpr Elf64_Sxword DT_INIT     = 12;  // address of the init function
constexpr Elf64_Sxword DT_FINI     = 13;  // address of the fini function
constexpr Elf64_Sxword DT_SONAME   = 14;
constexpr Elf64_Sxword DT_RPATH    = 15;
constexpr Elf64_Sxword DT_REL      = 17;
constexpr Elf64_Sxword DT_RELSZ    = 18;
constexpr Elf64_Sxword DT_RELENT   = 19;
constexpr Elf64_Sxword DT_PLTREL   = 20;  // DT_REL or DT_RELA for the PLT
constexpr Elf64_Sxword DT_JMPREL   = 23;  // address of the PLT relocations
constexpr Elf64_Sxword DT_INIT_ARRAY   = 25;
constexpr Elf64_Sxword DT_FINI_ARRAY   = 26;
constexpr Elf64_Sxword DT_INIT_ARRAYSZ = 27;
constexpr Elf64_Sxword DT_FINI_ARRAYSZ = 28;
constexpr Elf64_Sxword DT_FLAGS        = 30;
constexpr Elf64_Sxword DT_RELACOUNT    = 0x6ffffff9;  // count of RELATIVE
                                                      // relocations (a GNU
                                                      // fast path)

struct Elf64_Dyn {
    Elf64_Sxword d_tag;      
    union {
        Elf64_Xword d_val;   
        Elf64_Addr  d_ptr;   
    } d_un;
};

constexpr unsigned char STT_NOTYPE  = 0;
constexpr unsigned char STT_OBJECT  = 1;   // a data object
constexpr unsigned char STT_FUNC    = 2;   // a function
constexpr unsigned char STT_SECTION = 3;
constexpr unsigned char STT_FILE    = 4;

constexpr unsigned char STB_LOCAL  = 0;
constexpr unsigned char STB_GLOBAL = 1;
constexpr unsigned char STB_WEAK   = 2;


struct Elf64_Sym{
    Elf64_Word st_name; 
    unsigned char st_info; 
    unsigned char st_other; 
    Elf64_Half st_shndx; 
    Elf64_Addr st_value;
    Elf64_Xword st_size; 
}; 

inline unsigned char symbolBinding(unsigned char stInfo) { 
    return stInfo >> 4; 
}
inline unsigned char symbolType(unsigned char stInfo){ 
    return stInfo & 0x0F; 
}
constexpr Elf64_Half SHN_UNDEF = 0;

struct Elf64_Rela{
    Elf64_Addr r_offset; 
    Elf64_Xword r_info; 
    Elf64_Sxword r_addend; 
}; 


inline uint32_t relocSymbolIndex(Elf64_Xword rInfo) {
    return static_cast<uint32_t>(rInfo >> 32);
}
inline uint32_t relocType(Elf64_Xword rInfo) {
    return static_cast<uint32_t>(rInfo & 0xFFFFFFFFu);
}

//x86-64 relocation types 
constexpr uint32_t R_X86_64_NONE      = 0;
constexpr uint32_t R_X86_64_64        = 1;  
constexpr uint32_t R_X86_64_PC32      = 2;   
constexpr uint32_t R_X86_64_GOT32     = 3;
constexpr uint32_t R_X86_64_PLT32     = 4;
constexpr uint32_t R_X86_64_COPY      = 5;
constexpr uint32_t R_X86_64_GLOB_DAT  = 6;  
constexpr uint32_t R_X86_64_JUMP_SLOT = 7;  
constexpr uint32_t R_X86_64_RELATIVE  = 8;   
constexpr uint32_t R_X86_64_GOTPCREL  = 9;
constexpr uint32_t R_X86_64_32        = 10;
constexpr uint32_t R_X86_64_32S       = 11;
constexpr uint32_t R_X86_64_16        = 12;
constexpr uint32_t R_X86_64_PC16      = 13;
constexpr uint32_t R_X86_64_8         = 14;
constexpr uint32_t R_X86_64_PC8       = 15;
constexpr uint32_t R_X86_64_IRELATIVE = 37;  

//  The auxiliary vector — AT_

constexpr uint64_t AT_NULL   = 0;   
constexpr uint64_t AT_IGNORE = 1;
constexpr uint64_t AT_EXECFD = 2;
constexpr uint64_t AT_PHDR   = 3;   
constexpr uint64_t AT_PHENT  = 4;
constexpr uint64_t AT_PHNUM  = 5;   
constexpr uint64_t AT_PAGESZ = 6;   
constexpr uint64_t AT_BASE   = 7;   
constexpr uint64_t AT_FLAGS  = 8;
constexpr uint64_t AT_ENTRY  = 9;   
constexpr uint64_t AT_NOTELF = 10;
constexpr uint64_t AT_UID    = 11;
constexpr uint64_t AT_EUID   = 12;
constexpr uint64_t AT_GID    = 13;
constexpr uint64_t AT_EGID   = 14;
constexpr uint64_t AT_PLATFORM = 15;
constexpr uint64_t AT_HWCAP  = 16;  
constexpr uint64_t AT_CLKTCK = 17;
constexpr uint64_t AT_SECURE = 23;  
constexpr uint64_t AT_RANDOM = 25;
constexpr uint64_t AT_HWCAP2 = 26;
constexpr uint64_t AT_EXECFN = 31;  

static_assert(sizeof(Elf64_Ehdr) == 64, "Elf64_Ehdr must be 64 bytes");
static_assert(sizeof(Elf64_Phdr) == 56, "Elf64_Phdr must be 56 bytes");
static_assert(sizeof(Elf64_Shdr) == 64, "Elf64_Shdr must be 64 bytes");
static_assert(sizeof(Elf64_Dyn)  == 16, "Elf64_Dyn must be 16 bytes");
static_assert(sizeof(Elf64_Sym)  == 24, "Elf64_Sym must be 24 bytes");
static_assert(sizeof(Elf64_Rela) == 24, "Elf64_Rela must be 24 bytes");

constexpr uint64_t GUEST_PAGE_SIZE = 4096;
}


