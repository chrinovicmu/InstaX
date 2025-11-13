#include "ElfLoader.h"
#include <iostream>

namespace ElfLoader {

std::optional<ElfLoaderResult> loadELfFile(const std::filesystem::path& path){

    /*elfio reader object */ 
    ELFIO::elfio reader; 

    /*load elf file */ 
    if(!reader.load(path.string())){
        std::cerr << "Failec to load ELF" << path << "\n"; 
        return std::nullopt; 
    }

    ElfLoadResult result; 
    result.path = path.string(); 
    result.entry = reader.get_entry(); 
    result.is64Bit = (reader.get_class() = ELFCLASS64);
    result.littleEndian = (reader.get_encoding() == ELFDATA2LSB); 

    /*interate though all program segments */ 
    for(const auto& seg : reader.segments()){

        /*process only loadable segements */ 
        if(seg->get_type() != PT_LOAD) 
            continue;

        result.phdrAddr.push_back(seg->get_virtual_address()); 

        /*if segment is executbale, treat it as .text sgement */ 
        if(seg->get_flags() & PF_X){
            result.textAddr = seg->get_virtual_address();
            result.textSize = seg->get_file_size(); 

            /*copy raw bytes from elf file into text vector */ 

            result.text.assign(seg->get_data(), 
                               seg->get_data() + seg->get_file_size());
        }

        /*if segment os writable, treat it as .data segment */ 
        if(seg->get_flags() & PF_W){
            result.dataAddr = seg->get_virtual_address();
            result.dataSize = seg->get_file_size(); 

            result.data.assign(seg->get_data(),
                               seg->get_data() + seg->get_file_size());
        }

        /*use lowest virtual address amonf all segemnts to determine ELF's base load address */ 
        if(result.baseAddress == 0 || seg->get_virtual_address() < result.baseAddress)
            result.baseAddress = seg->get_virtual_address(); 
    }

    /* iterate through all sections in the ELF file and store their virtual addresses */ 
    for (const auto& sec : reader.sections())
        result.shdrAddrs.push_back(sec->get_address());

    /* mark the result as successfully loaded if the text segment exists */ 
    result.loaded = !result.text.empty();

    return result.loaded ? std::make_optional(result) : std::nullopt;
}

}
