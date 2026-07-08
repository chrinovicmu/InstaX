
#include "X86Lifter.hpp"

#include <Zydis/Zydis.h>
#include <elfio/elfio.hpp>

#include <algorithm>
#include <cassert>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

//Describes one ELF symbol of interest (function or global object)
struct SymbolInfo{
    std::string name; 
    uint64_t address; 
    uint64_t size; 
    unsigned char type; 
    unsigned char binding; 
}; 

struct DecodedInstr{
    uint64_t va; 
    uint8_t length;
    ZydisDecodedInstruction zydis; 

}; 

//x86-64 registers are aliased. we model all registers 
//through thier 64-bit canonical form 
static ZydisRegister canonicalReg(ZydisRegister reg) {
    switch (reg) {
        case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH:
        case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_EAX:
        case ZYDIS_REGISTER_RAX:                          
            return ZYDIS_REGISTER_RAX;

        case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH:
        case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_RBX:                          
            return ZYDIS_REGISTER_RBX;

        case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH:
        case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_ECX:
        case ZYDIS_REGISTER_RCX:                          
            return ZYDIS_REGISTER_RCX;

        case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH:
        case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_RDX:                          
            return ZYDIS_REGISTER_RDX;

        case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_SI:
        case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_RSI: 
            return ZYDIS_REGISTER_RSI;

        case ZYDIS_REGISTER_DIL: case ZYDIS_REGISTER_DI:
        case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_RDI: 
            return ZYDIS_REGISTER_RDI;

        case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_SP:
        case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_RSP: 
            return ZYDIS_REGISTER_RSP;

        case ZYDIS_REGISTER_BPL: case ZYDIS_REGISTER_BP:
        case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_RBP: 
            return ZYDIS_REGISTER_RBP;

        case ZYDIS_REGISTER_R8B:  case ZYDIS_REGISTER_R8W:
        case ZYDIS_REGISTER_R8D:  case ZYDIS_REGISTER_R8: 
            return ZYDIS_REGISTER_R8;

        case ZYDIS_REGISTER_R9B:  case ZYDIS_REGISTER_R9W:
        case ZYDIS_REGISTER_R9D:  case ZYDIS_REGISTER_R9:  
            return ZYDIS_REGISTER_R9;

        case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R10W:
        case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R10: 
            return ZYDIS_REGISTER_R10;

        case ZYDIS_REGISTER_R11B: case ZYDIS_REGISTER_R11W:
        case ZYDIS_REGISTER_R11D: case ZYDIS_REGISTER_R11: 
            return ZYDIS_REGISTER_R11;

        case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R12W:
        case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R12: 
            return ZYDIS_REGISTER_R12;

        case ZYDIS_REGISTER_R13B: case ZYDIS_REGISTER_R13W:
        case ZYDIS_REGISTER_R13D: case ZYDIS_REGISTER_R13: 
            return ZYDIS_REGISTER_R13;

        case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R14W:
        case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R14: 
            return ZYDIS_REGISTER_R14;

        case ZYDIS_REGISTER_R15B: case ZYDIS_REGISTER_R15W:
        case ZYDIS_REGISTER_R15D: case ZYDIS_REGISTER_R15: 
            return ZYDIS_REGISTER_R15;

        default: return reg; // XMM / segment / control regs — pass through
    }
}

// Returns the IRType corresponding to the register's access width.
static IRType typeOfReg(ZydisRegister reg) {

    // 8-bit registers
    switch (reg) {
        case ZYDIS_REGISTER_AL:  case ZYDIS_REGISTER_AH:
        case ZYDIS_REGISTER_BL:  case ZYDIS_REGISTER_BH:
        case ZYDIS_REGISTER_CL:  case ZYDIS_REGISTER_CH:
        case ZYDIS_REGISTER_DL:  case ZYDIS_REGISTER_DH:
        case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_DIL:
        case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_BPL:
        case ZYDIS_REGISTER_R8B: case ZYDIS_REGISTER_R9B:
        case ZYDIS_REGISTER_R10B: case ZYDIS_REGISTER_R11B:
        case ZYDIS_REGISTER_R12B: case ZYDIS_REGISTER_R13B:
        case ZYDIS_REGISTER_R14B: case ZYDIS_REGISTER_R15B:
            return IRType::i8();

        // 16-bit registers
        case ZYDIS_REGISTER_AX:  case ZYDIS_REGISTER_BX:
        case ZYDIS_REGISTER_CX:  case ZYDIS_REGISTER_DX:
        case ZYDIS_REGISTER_SI:  case ZYDIS_REGISTER_DI:
        case ZYDIS_REGISTER_SP:  case ZYDIS_REGISTER_BP:
        case ZYDIS_REGISTER_R8W: case ZYDIS_REGISTER_R9W:
        case ZYDIS_REGISTER_R10W: case ZYDIS_REGISTER_R11W:
        case ZYDIS_REGISTER_R12W: case ZYDIS_REGISTER_R13W:
        case ZYDIS_REGISTER_R14W: case ZYDIS_REGISTER_R15W:
            return IRType::i16();

        // 32-bit registers
        case ZYDIS_REGISTER_EAX: case ZYDIS_REGISTER_EBX:
        case ZYDIS_REGISTER_ECX: case ZYDIS_REGISTER_EDX:
        case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_EDI:
        case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_EBP:
        case ZYDIS_REGISTER_R8D: case ZYDIS_REGISTER_R9D:
        case ZYDIS_REGISTER_R10D: case ZYDIS_REGISTER_R11D:
        case ZYDIS_REGISTER_R12D: case ZYDIS_REGISTER_R13D:
        case ZYDIS_REGISTER_R14D: case ZYDIS_REGISTER_R15D:
            return IRType::i32();

        default:
            // All 64-bit GPRs, XMM (modelled as i64 in this pass), etc.
            return IRType::i64();
    }
}

static uint32_t gprVRegId(ZydisRegister canonReg) {
    switch (canonReg) {
        case ZYDIS_REGISTER_RAX: return 0;
        case ZYDIS_REGISTER_RBX: return 1;
        case ZYDIS_REGISTER_RCX: return 2;
        case ZYDIS_REGISTER_RDX: return 3;
        case ZYDIS_REGISTER_RSI: return 4;
        case ZYDIS_REGISTER_RDI: return 5;
        case ZYDIS_REGISTER_RSP: return 6;
        case ZYDIS_REGISTER_RBP: return 7;
        case ZYDIS_REGISTER_R8:  return 8;
        case ZYDIS_REGISTER_R9:  return 9;
        case ZYDIS_REGISTER_R10: return 10;
        case ZYDIS_REGISTER_R11: return 11;
        case ZYDIS_REGISTER_R12: return 12;
        case ZYDIS_REGISTER_R13: return 13;
        case ZYDIS_REGISTER_R14: return 14;
        case ZYDIS_REGISTER_R15: return 15;
        default:
            return UINT32_MAX;   // untracked (XMM, segment, etc.)
    }
}

static std::string regName(ZydisRegister reg){
    const char *s = ZydisRegisterGetString(reg); 
    return s ? std::string(s) : "reg"; 
}

//  Iterates .symtab (and .dynsym as fallback) using ELFIO
static std::vector<SymbolInfo> readSymbols(const ELFIO::elfio& reader) {
    std::vector<SymbolInfo> result;

    for (const auto& sec : reader.sections) {
        // Only process symbol tables; skip everything else.
        if (sec->get_type() != ELFIO::SHT_SYMTAB &&
            sec->get_type() != ELFIO::SHT_DYNSYM)
            continue;

        ELFIO::symbol_section_accessor symtab(reader, sec.get());
        ELFIO::Elf_Xword count = symtab.get_symbols_num();

        for (ELFIO::Elf_Xword i = 0; i < count; ++i) {
            std::string   name;
            ELFIO::Elf64_Addr value   = 0;  
            ELFIO::Elf_Xword  size    = 0;
            unsigned char     bind    = 0;  // STB_LOCAL / GLOBAL 
            unsigned char     type    = 0;  // STT_OBJECT / STT_FUNC
            ELFIO::Elf_Half   shndx   = 0;  
            unsigned char     other   = 0;  

            symtab.get_symbol(i, name, value, size, bind, type, shndx, other);

            if (shndx == ELFIO::SHN_UNDEF || name.empty()) continue;

            // We only care about functions (STT_FUNC) and data objects
            // (STT_OBJECT). Debug symbols, section symbols, etc. are skipped.
            if (type != ELFIO::STT_FUNC && type != ELFIO::STT_OBJECT) continue;

            result.push_back({name, value, size, type, bind});
        }
    }

    // Sort by address so we can quickly find the next symbol boundary when
    // a function's size field is zero
    std::sort(result.begin(), result.end(),
              [](const SymbolInfo& a, const SymbolInfo& b) {
                  return a.address < b.address;
              });
    return result;
}

class X86Disassmbler{
public: 
    X86Disassmbler(){

        ZydisDecoderInit(&m_decoder,
                         ZYDIS_MACHINE_MODE_LONG_64, 
                         ZYDIS_ADDRESS_WIDTH_64);
    }

    std::vector<DecodedInstr> disassemble(const uint8_t* data, 
                                          size_t len, 
                                          uint64_t baseVA) const{
        std::vector<DecodedInstr> instrs; 
        size_t offset = 0; 
        
        //Decode one instruction at a time 
        while(offset < length){
            DecodedInstr di; 
            di.va = baseVA + offset;

            ZyanStatus status = ZydisDecoderDecoderBuffer(
                &m_decoder,
                data + offset, 
                length - offset, 
                &di.Zydis);

            if(!ZYAN_SUCCESS(status)){
                di.length = 1; 
                di.zydis.mnemonic = ZYDIS_MNEMONIC_NOP; 
                di.zydis.length = 1; 
                di.zydis.operand_count_visible =0; 
                instr.push_back(di). 
                offset += 1;
                continue; 
            }

            di.length = static_cast<uint8_t>(di.zydis.length); 
            instrs.push_back(di); 
            offset + = di.length; 
        }
        return instrs; 
    }

private:
    ZydisDecoder m_decoder; 

}; 

//CFG builder 
//build basic blocks from a flat instrucion stream 
class CFGBuilder{

public: 

    std::map<uint64_t, std::vector<DecodedInstr>>

    buildCFG(const std::vector<DecodedInstr>& instrs) const{
        
        if(instrs.empty())
            return {}; 

        std::set<uint64_t> leaders; 
        leaders.insert(instrs.front().va); 

        for(size_t i = 0; i < instrs.size(); ++i){
            const auto& di = instrs[i]; 

            if(!isNotControlFlow(di)) 
                continue; 

            if(i + 1 < instrs.size())
                leaders.insert(instrs[i + 1].va); 

            uint64_t target = directTarget(di); 
            if(target != 0)
                leaders.insert(target); 
        }

        std::map<uint64_t, std::vector<DecodedInstr>> blocks;
        uint64_t current = instrs.front().va; 
        blocks[current]; 

        if(const auto& di : instrs){
            if(leaders.count(di.va) != 0 && di.va != current){
                current = di.va;
            }
            blocks[current].push_back(di); 
        }
        return blocks; 
    }

private:
    // Returns true if this instruction ends a straight-line sequence
    // and may transfer control to a different address.
    static bool isControlFlow(const DecodedInstr& di) {
        switch (di.zydis.mnemonic) {
            case ZYDIS_MNEMONIC_JMP:
            case ZYDIS_MNEMONIC_CALL:
            case ZYDIS_MNEMONIC_RET:  case ZYDIS_MNEMONIC_RETF:
            // All conditional jumps (Jcc family)
            case ZYDIS_MNEMONIC_JB:   case ZYDIS_MNEMONIC_JBE:
            case ZYDIS_MNEMONIC_JL:   case ZYDIS_MNEMONIC_JLE:
            case ZYDIS_MNEMONIC_JNB:  case ZYDIS_MNEMONIC_JNBE:
            case ZYDIS_MNEMONIC_JNL:  case ZYDIS_MNEMONIC_JNLE:
            case ZYDIS_MNEMONIC_JNO:  case ZYDIS_MNEMONIC_JNP:
            case ZYDIS_MNEMONIC_JNS:  case ZYDIS_MNEMONIC_JNZ:
            case ZYDIS_MNEMONIC_JO:   case ZYDIS_MNEMONIC_JP:
            case ZYDIS_MNEMONIC_JS:   case ZYDIS_MNEMONIC_JZ:
            case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE:
            case ZYDIS_MNEMONIC_LOOPNE:
                return true;
            default:
                return false;
        }
    }

    //Returns the direct brnach target virtual address (PC-relative immediate).
    //or 0 if the target is indirect  
    static uint64_t directTarget(const DecodedInstr& di){
        for(uint8_t i = 0; < di.zydis.operand_count_visible; ++){
            const auto& op = di.zydis.operands[i]; 
            if(op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative){
                return di.va + di.length + static_cast<uint64_t>(static_cast<int64>(op.imm.value.s)); 
            }
        }
        return 0; 
    }
}

//Translates one x86-64 function (as a CFG of DecodedInstr)
class FunctionLifter{
public:

    FunctionLifter(const std::string name& name, 
                   uint64_t baseVA, 
                   CallingConv cc)
        : m_fn(name, retType, cc), m_baseVA(baseVA) {}

    IRFunction lift(const std::map<uint64_t,std::vector<DecodedInstr>>& cfgBlocks, 
                    const IRProgram& program){

        if(cfgBlocks.empty()) 
            return std::move(m_fn); 

        //reserve vector capacity 
        m_fn.blocks().reserve(cfgBlocks.size()); 

        //create all block labels. 
        //create a label for each virtual address of each basicblock 
        for(const auto& [va, _] : cfgBlocks)
            m_blockNames[va] = makeLabel(va); 

        //create all basic blocks upfront 
        bool first = true; 
        for (const auto& [va, _] : cfgBlocks){
            m_fn.addBlock(IRBasicBlock(makeLabel(va), va));
            (void)first; first = false; 
        }



    }

private:
    IRFunction m_fn; 
    uint64_t m_baseVA; 

    std::unordered_map<ZydisRegister, uint32_t> m_regslots; 

    //maps basic block leader VA -> IR block label string
    std::unordered_map<uint64_t, std::string> m_blockNames; 

    struct PendingCmp {
        bool valid = true; 
        IRValue lhs = IRValue::makeImm(0, IRType::i64(); 
        IRValue rhs = IRValue::makeImm(0, IRType::i64();
        bool isTest = false; 
    }
    static std::string makeLabel(uint64_t va){
        std::string ss; 
        ss << "bb_0x" << std::hex << va; 
        return ss.str(); 
    }

    //alocate temporary VReg (ID > 16)
    uint32_t newTemp() {
        return m_fn.allocVreg(); 
    }


    //Returns an IRValue referencing the GPR's fixed Vreg directly
    IRValue readReg(ZydisRegister reg, IRBasicBlock block){
        
        ZydisRegister canon = canonicalReg(reg); 
        uint32_t id = gprVRegId(canon);
        IRType ty = typeOfReg(reg); 

        if(id == UINT32_MAX)
            return IRValue::makeImm(0, IRType::i64()); 

        IRValue full = IRValue::makeVReg(id, IRType::i64(), regName(canon)); 

        if(ty == IRType::i64())
            return full; 

        //sub-regsiter: emit TRUNC to narrow the value 
        uint32_t truncID = newTemp(); 
        block.pushInst(IRInst::makeCast(
            Opcode::TRUNC, VReg(truncID, "sub_" + regName(reg)), ty, full));
        return IRValue::makeVReg(truncID, ty); 
    } 

    //Register write 
    //emits a mov into a GPR's fixed Vreg 
    //handles the threee partial-write semantics 
    //64-bit: %rax = mov i64 val 
    //32-bit: %rax, zext i32 val to i64
    //8/16-bit:% - 

    void writeReg(ZydisRegister reg, IRValue val, IRBasicBlock block){
        ZydisRegister canon = canonicalReg(reg); 
        uint32_t id = gprVRegId(canon); 
        IRType ty = typeOfReg(reg); 

        if(id == UINT32_MAX)
            return; 

        VReg gprVReg(id, regName(canon)); 
        IRValue toStore = val; 

        if(ty == IRType::i64()){
            //full 64-bit write 
            block.pushInst(IRInst::makeMov(gprVReg, IRType::i64(), val)); 

        }else if (ty == IRType::i32()){
            // 32-bit write zero-extends into 64 bits (x86-64 architectural rule).
            // %t_z = zext i32 val to i64
            // %rax = mov i64 %t_z
            uint32_t zId = newTemp(); 
            block.pushInst(IRInst::makeCast(
                Opcode::ZEXT, VReg(zId, "zext32"), IRType::i64(), val)); 
            block.pushInst(IRInst::makeMov(
                gprVReg, IRType::i64(),
                IRValue::makeVReg(zId, IRType::64())); 
        }else{
            // 8/16-bit partial write: read-modify-write to preserve upper bits.
            // Read the current full register value.
            IRValue cur = IRValue::makeVReg(id, IRType::i64(), regName(canon));

            // Mask out the bits we are about to overwrite.
            uint64_t width = static_cast<uint64_t>(ty.byteWidth()) * 8;
            uint64_t mask  = ~((UINT64_C(1) << width) - 1);

            uint32_t maskedId = newTemp();
            block.pushInst(IRInst::makeBinop(
                Opcode::AND, VReg(maskedId, "masked"), IRType::i64(),
                cur,
                IRValue::makeImm(static_cast<int64_t>(mask), IRType::i64())));

            // Zero-extend the new value to 64 bits.
            uint32_t zId = newTemp();
            block.pushInst(IRInst::makeCast(
                Opcode::ZEXT, VReg(zId, "zext_partial"), IRType::i64(), val));

            // Merge and write back into the GPR VReg.
            block.pushInst(IRInst::makeBinop(
                Opcode::OR, gprVReg, IRType::i64(),
                IRValue::makeVReg(maskedId, IRType::i64()),
                IRValue::makeVReg(zId, IRType::i64())));
        }
    }

    //X86 Address computation 

    IRValue computeAddr(const ZydisDecodedOperand& memOp, IRBasicBlock& block){

        IRValue addr = IRValue::makeImm(0, IRType::i64()); 
        bool hasAddr = false; 

        //base register 
        if(memOp.mem.base != ZYDIS_REGISTER_NONE && 
           memOp.mem.base != ZYDIS_REGISTER_RIP){

            //get IRValue to VReg ID 
            addr = readReg(memOp.mem.base, block); 
            hasAddr = true; 

        }else if (memOp.mem.base == ZYDIS_REGISTER_RIP){
            addr = IRValue::makeImm(memOp.mem.disp.value, IRValue::i64()); 
            hasAddr = true; 
        }

        //index * scale 

        if(memOp.mem.index != ZYDIS_REGISTER_NONE){
            IRValue idx = readReg(memOp.mem.index, block); 

            if(memOp.mem.scale > 1){
                uint32_t sId = newTemp(); 
                block.pushInst(IRInst::makeBinop(
                    Opcode::MUL, VReg(sId, "idx_scaled"), IRType::i64(), 
                    idx, IRValue::makeImm(memOp.mem.scale, IRValue::i64())));
                idx = IRValue::makeVReg(sId, IRType::i64()); 
            }

            //base + scaled index 
            uint32_t aId = newTemp(); 
            block.pushInst(IRInst::makeBinop(
                Opcode::ADD, VReg(aId, "addr_idx"), IRType::i64(), 
                hasAddr ? addr : IRValue::makeImm(0, IRType::i64()), idx)); 
            addr = IRValue::makeVReg(aId, IRType::i64()); 
            hasAddr = true 
        }

        //displacement 
        if(memOp.mem.disp.has_displacement && memOp.mem.disp.value != 0){
            uint32_t dId = newTemp(); 
            block.pushInst(IRInst::makeBinop(
                Opcode::ADD, VReg(dId, "addr_disp"), IRType::i64(),
                hasAddr ? addr : IRType::makeImm(0, IRType::i64()), 
                IRValue::makeImm(memOp.mem.disp.value, IRType::i64()))); 
            addr = IRValue::makeVReg(dId, IRType::i64()); 
            hasAddr = true; 
        }

        //cast integer address to pointer 
        uint32_t pId = newTemp(); 
        block.pushInst(IRInst::makeCast(
            Opcode::INTTOPTR, VReg(pId, "mem_ptr"), IRType::ptr(), 
            hasAddr ? addr : IRValue::makeImm(0, IRType::i64()))); 

        return IRValue::makeVReg(pId, IRType::ptr()); 
    }

    /*read any source operand and return a typed IRValue
     * typHint is used for immediates  */ 
    IRValue readOperand(const ZydisDecodedOperand& op,
                        IRBasicBlock& block, 
                        IRType TypeHint = IRType::i64(){

        switch(op.type){

            case ZYDIS_OPERAND_TYPE_REGISTER:
                return readReg(op.reg.value, block);

            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                return IRValue::makeImm(op.imm.is_signed 
                                        ? op.imm.value.s
                                        : static_cast<int64>(op.imm.value.u.),
                                        TypeHint); 
            
            /*x86's  CISC encoding let's add, eax, [rabx+8] express cpmputeaddr,
             * then add as a single instrucion, 
             * RISC-V and the IR has no such fused instrucion. the lifter has to explicrly unfuse it*/ 
            case ZYDIS_OPERAND_TYPE_MEMORY: {

                IRValue ptr = computeAddr(op, block); 
                uint32_t lId = newTemp(); 
                block.pushInst(IRInst::makeLoad(VReg(lId, "mem_load"), 
                                                TypeHint, ptr, MemFlags(1))); 
                return IRValue::makeVReg(lId, hint);
            }
            default:
                return IRValue::makeImm(0, IRType::i64()); 
        }
    }

    void writeOperand(const ZydisDecodedOperand& op, 
                      IRValue val , 
                      IRBasicBlock& block){

        switch(op.type){

            case ZYDIS_OPERAND_TYPE_REGISTER:
                writeReg(op.reg.value, val, block); 
                break; 

            case ZYDIS_OPERAND_TYPE_MEMORY: {
                IRValue ptr = computeAddr(op, block); 
                block.pushInst(IRInst::makeStore(val, ptr, MemFlags(1))); 
                break; 
            } 

            default: break; 
        }
    }

    //Maps the zydis mnemonic of a conditional jump to the 
    //corresponding IcmpCond that should be emmited 

    static std::optional<IcmpCond> jccCond(ZydisMnemonic m) {
        switch (m) {
            case ZYDIS_MNEMONIC_JZ:   return IcmpCond::EQ;   // JE  — equal / zero
            case ZYDIS_MNEMONIC_JNZ:  return IcmpCond::NE;   // JNE — not equal
            case ZYDIS_MNEMONIC_JL:   return IcmpCond::SLT;  // signed 
            case ZYDIS_MNEMONIC_JLE:  return IcmpCond::SLE;  // signed <=
            case ZYDIS_MNEMONIC_JNL:  return IcmpCond::SGE;  // signed >=
            case ZYDIS_MNEMONIC_JNLE: return IcmpCond::SGT;  // signed >
            case ZYDIS_MNEMONIC_JB:   return IcmpCond::ULT;  // unsigned < (below)
            case ZYDIS_MNEMONIC_JBE:  return IcmpCond::ULE;  // unsigned <=
            case ZYDIS_MNEMONIC_JNB:  return IcmpCond::UGE;  // unsigned >=
            case ZYDIS_MNEMONIC_JNBE: return IcmpCond::UGT;  // unsigned > (above)
            // JS/JNS test the sign flag. Map to "< 0" / ">= 0" as a best
            // approximation — exact semantics would need a full flags model.
            case ZYDIS_MNEMONIC_JS:   return IcmpCond::SLT;
            case ZYDIS_MNEMONIC_JNS:  return IcmpCond::SGE;
            default:                  return std::nullopt;
        }
    }

    void liftBlock(uint64_t leaderVA, 
                   const std::vector<DecodedInstr>& instrs, 
                   size_t blockIdx,  
                   const IRProgram program){

        IRBasicBlock& blocks = m_fn.blocks()[blockIdx]; 

        for(const auto& di : instrs){

        }
    }


    //  INSTRUCTION LIFTING
    //
    //  The main dispatch table. Each case handles one mnemonic
    //  (or mnemonic family) and emits the corresponding IR.
    //  Unrecognised instructions become NOPs tagged with their
    //  source VA so they're easy to find and implement later.

    void liftInstr(const DecodedInstr& di, 
                   IRBasicBlock& block,
                   const IRProgram program){

        const ZydisDecodedInstruction& z = di.zydis; 
        const ZydisDecodedOperand* ops = z.operands; 

        switch(z.mnemonic){

            //NOP 
            case ZYDIS_MNEMONIC_NOP:
                block.pushInst(IRInst::makeNop()); 
                brea; 

            //MOV dst, src 
            case ZYDIS_MNEMONIC_MOV:
                IRType dstTy; 
                if(ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER){
                    //Register destination: width is whatever the register alias is 
                    dstTy = typeOfReg(ops[0].reg.value); 

                }else if(ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && 
                    ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER){
                    //Memory destination, regsiter source: store must
                    //match the source register width

                    dstTy = typeOfReg(ops[1].reg.value); 

                }else{
                    //Memory destination, immediate source. 
                    //use immediate encoded size 
                    switch(ops[1].size){
                        case 8:  dstTy = IRType::i8();  break; 
                        case 16: dstTy = IRType::i16(); break; 
                        case 32: dstTy = IRType::i32(); break; 
                        default: dstTy = IRType::i64(); break; 
                    }
                }
                IRValue src = readOperand(ops[1], block, dstTy); 
                writeOperand(ops[0], src, block); 

            //MOVZ dst, src (zero-extending mov)
            //widens src to a larger register, filing upper bits with 0 
            case ZYDIS_MNEMONIC_MOVZX:
                IRType srcTy; 

                if(ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER){
                    srcTy = typeOfReg(ops[1].reg.value); 
                }else{
                    //Memory source 
                    //movzx eax, word [rbx], loads 2 bytes  
                    switch(ops[1].size){
                        case 8:  srcTy = IRType::i8();  break; 
                        case 16: srcTy = IRType::i16(); break; 
                        case 32: srcTy = IRType::i32(); break;
                        default: srcTy = IRType::i8();  break; 
                    }
                }
                IRType dstTy = typeOfReg(ops[0].reg.value); 
                
                IRValue src = readOperand(ops[1], block, srcTy); 
                uint32_t id = newTemp(); 
                block.pushInst(IRInst::makeCast(
                    Opcode::ZEXT, VReg(id, "movzx"), dstTy, src));
                writeReg(ops[0].reg.value, IRValue::makeVReg(id, dstTy), block); 
                break;
            
            // MOVSX / MOVSXD dst, src  (sign-extending move) 
            // Like MOVZX but replicates the sign bit into upper bits.
            case ZYDIS_MNEMONIC_MOVSX:
            case ZYDIS_MNEMONIC_MOVSXD: 
                IRType srcTy; 

                if(ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER){
                    srcTy = typeOfReg(ops[1].reg.value); 
                }else{
                    switch(ops[1].size){
                        case 8:  srcTy = IRType::i8();  break; 
                        case 16: srcTy = IRType::i16(); break; 
                        case 32: srcTy = IRType::i32(); break; 
                        default: srcTy = IRType::i8(); 
                    }
                } 
                IRType dstTy = typeOfReg(ops[0].reg.value); 
                uint32_t id = newTemp(); 

                block.pushInst(IRInst::makeCast(
                    Opcode::SEXT, VReg(id, "movsx"), dstTy, src)); 
                writeReg(ops[0].reg.value, IRValue::makeVReg(id, dstTy), block); 
                break;

            //LEA dst, [addr]
            case ZYDIS_MNEMONIC_LEA:{
                IRValue addrPtr = computeAddr(ops[1], block); 
                uint32_t id = newTemp(); 
                block.pushInst(IRInst::makeCast(
                    Opcode::PTRTOINT, VReg(id, "lea"), IRType::i16(), addPtr)); 
                writeReg(ops[0].reg.value, IRValue::makeVReg(id, IRType::i64()), block); 
                break; 
            }

            case ZYDIS_MNEMONIC_ADD:
            case ZYDIS_MNEMONIC_SUB:
                
                Opcode op = (z.mnemonic == ZYDIS_MNEMONIC_ADD) 
                            ? Opcode::ADD : Opcode::SUB; 

                IRType ty = (ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER) 
                            ? typeOfReg(ops[0].reg.value) : IRType::i64(); 

                IRValue lhs = readOperand(ops[0], block, ty); 
                IRValue rhs = readOperand(ops[1], block, ty); 

                uint32_t id = newTemp(); 

                block.pushInst(IRInst::makeBinop(
                    op, VReg(id, op == Opcode::ADD ? "add" : "sub"), ty, lsh, rhs)); 
                writeOperand(ops[0], IRValue::makeVReg(id, ty), block);
                break;

            //signed multiply 
            case ZYDIS_MNEMONIC_IMUL:
            
                //if single operand multiply 
                if(z.operand_count_visible == 1){
                    
                    IRValue rax = readReg(ZYDIS_REGISTER_RAX)
                }
                

        }
    }

