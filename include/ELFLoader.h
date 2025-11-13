#pragma once 
#include <cstddef>
#include <elfio/elfio.hpp>
#include <optional>
#include <vector>
#include <string>
#include <cstdint>
#include <iostream>
#include <filesystem>

namespace ElfLoad {

struct ElfLoadResultt{
    std::vector<uint8_t> text; 
    Elf64_Addr entry = 0; 
    Elf64_Addr baseAddress = 0; 
    Elf64_Addr textAddr = 0; 
    std::size_t textSize = 0; 
    std::vector<uint8_t> data; 
    Elf64_Addr dataAddr = 0; 
    size_t dataSize = 0; 
    std::vector<Elf64_Addr> phdrAddrs; // Program header addresses
    std::vector<Elf64_Addr> shdrAddrs; // Section header addresses
    std::string path;                
    bool is64Bit = true;             
    bool littleEndian = true;   
    bool loaded = false; 


    bool hasText() const { return !text.empty();}    
}; 

std::optional<ElfLoadResultt> loadElfFile(const std::filesystem::path& path); 

}
