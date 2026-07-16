#include "IR.hpp"

namespace XTOR_IR{

IRInst IRInst::makeCast(Opcode, castOp, VReg dst, IRType dstTy, IRValue src){
    IRInst inst;
    inst.m_opcode     = castOp;     //  TRUNC, ZEXT, SEXT, BITCAST...
    inst.m_dst        = dst;
    inst.m_resultType = dstTy;      // the type AFTER the cast 
    inst.m_operands.push_back(std::move(src));  // operands[0] = value BEFORE the cast
    return inst;
}

IRInst IRInst::makeMov(VReg dst, IRType ty, IRValue src) {
    IRInst inst;
    inst.m_opcode     = Opcode::MOV;
    inst.m_dst        = dst;
    inst.m_resultType = ty;
    inst.m_operands.push_back(std::move(src));
    return inst;
}

IRInst IRInst::makeBinop(Opcode op, VReg dst, IRType ty, IRValue lhs, IRValue rhs) {
    IRInst inst;
    inst.m_opcode     = op;
    inst.m_dst        = dst;
    inst.m_resultType = ty;
    inst.m_operands.push_back(std::move(lhs));  // operands[0]
    inst.m_operands.push_back(std::move(rhs));  // operands[1]
    return inst;
}

IRInst IRInst::makeIcmp(IcmpCond cond, VReg dst, IRValue lhs, IRValue rhs) {
    IRInst inst;
    inst.m_opcode     = Opcode::ICMP;
    inst.m_dst        = dst;
    inst.m_resultType = IRType::i1();   // comparisons always produce i1
    inst.m_icmpCond   = cond;
    inst.m_operands.push_back(std::move(lhs));
    inst.m_operands.push_back(std::move(rhs));
    return inst;
}

IRInst IRInst::makeFcmp(FcmpCond cond, VReg dst, IRValue lhs, IRValue rhs) {
    IRInst inst;
    inst.m_opcode     = Opcode::FCMP;
    inst.m_dst        = dst;
    inst.m_resultType = IRType::i1();
    inst.m_fcmpCond   = cond;
    inst.m_operands.push_back(std::move(lhs));
    inst.m_operands.push_back(std::move(rhs));
    return inst;
}

IRInst IRInst::makeLoad(VReg dst, IRType loadTy, IRValue ptr, MemFlags flags) {
    IRInst inst;
    inst.m_opcode     = Opcode::LOAD;
    inst.m_dst        = dst;
    inst.m_resultType = loadTy;
    inst.m_memFlags   = flags;
    inst.m_operands.push_back(std::move(ptr));   // operands[0] = address
    return inst;
}

IRInst IRInst::makeStore(IRValue val, IRValue ptr, MemFlags flags) {
    IRInst inst;
    inst.m_opcode     = Opcode::STORE;
    inst.m_resultType = IRType::void_();   // STORE produces no value
    inst.m_memFlags   = flags;
    // dst is left empty (std::nullopt) — STORE has no result VReg.
    inst.m_operands.push_back(std::move(val));   // operands[0] = value to store
    inst.m_operands.push_back(std::move(ptr));   // operands[1] = address
    return inst;
}

IRInst IRInst::makeAlloca(VReg dst, uint64_t bytes, uint32_t alignment) {
    IRInst inst;
    inst.m_opcode      = Opcode::ALLOCA;
    inst.m_dst         = dst;
    inst.m_resultType  = IRType::ptr();   // alloca always produces a pointer
    inst.m_allocaBytes = bytes;
    inst.m_memFlags    = MemFlags(alignment);
    return inst;
}

IRInst IRInst::makeJmp(std::string targetBlock) {
    IRInst inst;
    inst.m_opcode      = Opcode::JMP;
    inst.m_resultType  = IRType::void_();
    inst.m_branchTrue  = std::move(targetBlock);
    return inst;
}

IRInst IRInst::makeCjmp(IRValue cond, std::string trueBlock, std::string falseBlock) {
    IRInst inst;
    inst.m_opcode      = Opcode::CJMP;
    inst.m_resultType  = IRType::void_();
    inst.m_branchTrue  = std::move(trueBlock);
    inst.m_branchFalse = std::move(falseBlock);
    inst.m_operands.push_back(std::move(cond));   // operands[0] = i1 condition
    return inst;
}

IRInst IRInst::makeRet(std::optional<IRValue> retVal) {
    IRInst inst;
    inst.m_opcode     = Opcode::RET;
    inst.m_resultType = IRType::void_();
    if (retVal.has_value())
        inst.m_operands.push_back(std::move(*retVal));   // operands[0] = return value
    return inst;
}

IRInst IRInst::makeCall(std::optional<VReg> dst, IRType retTy, IRValue callee,
                        std::vector<IRValue> args, CallingConv cc, bool tailCall) {
    IRInst inst;
    inst.m_opcode     = Opcode::CALL;
    inst.m_dst        = dst;          // empty for void-returning calls
    inst.m_resultType = retTy;
    inst.m_callConv   = cc;
    inst.m_isTailCall = tailCall;
    inst.m_operands.push_back(std::move(callee));   // operands[0] = callee
    for (auto& a : args)
        inst.m_operands.push_back(std::move(a));     // operands[1..N] = arguments
    return inst;
}

IRInst IRInst::makeSelect(VReg dst, IRType ty, IRValue cond,
                          IRValue trueVal, IRValue falseVal) {
    IRInst inst;
    inst.m_opcode     = Opcode::SELECT;
    inst.m_dst        = dst;
    inst.m_resultType = ty;
    inst.m_operands.push_back(std::move(cond));     // operands[0]
    inst.m_operands.push_back(std::move(trueVal));  // operands[1]
    inst.m_operands.push_back(std::move(falseVal)); // operands[2]
    return inst;
}

IRInst IRInst::makeNop() {
    IRInst inst;
    inst.m_opcode     = Opcode::NOP;
    inst.m_resultType = IRType::void_();
    return inst;
}

//  IRInst observer methods


const VReg& IRInst::dst() const {
    if (!m_dst.has_value())
        throw std::logic_error("IRInst::dst() called on instruction with no result");
    return *m_dst;
}

const IRValue& IRInst::operand(size_t i) const {
    if (i >= m_operands.size())
        throw std::out_of_range("IRInst::operand() index out of range");
    return m_operands[i];
}

const IcmpCond& IRInst::icmpCond() const {
    if (!m_icmpCond.has_value())
        throw std::logic_error("IRInst::icmpCond() called on non-ICMP instruction");
    return *m_icmpCond;
}

const FcmpCond& IRInst::fcmpCond() const {
    if (!m_fcmpCond.has_value())
        throw std::logic_error("IRInst::fcmpCond() called on non-FCMP instruction");
    return *m_fcmpCond;
}

const std::string& IRInst::branchTrue() const {
    if (m_branchTrue.empty())
        throw std::logic_error("IRInst::branchTrue() called on non-branch instruction");
    return m_branchTrue;
}

const std::string& IRInst::branchFalse() const {
    if (m_branchFalse.empty())
        throw std::logic_error("IRInst::branchFalse() called on non-CJMP instruction");
    return m_branchFalse;
}

CallingConv IRInst::callConv() const {
    if (!m_callConv.has_value())
        throw std::logic_error("IRInst::callConv() called on non-CALL instruction");
    return *m_callConv;
}

bool IRInst::isTailCall() const { return m_isTailCall; }

const MemFlags& IRInst::memFlags() const {
    if (!m_memFlags.has_value())
        throw std::logic_error("IRInst::memFlags() called on non-memory instruction");
    return *m_memFlags;
}

uint64_t IRInst::allocaBytes() const {
    if (!m_allocaBytes.has_value())
        throw std::logic_error("IRInst::allocaBytes() called on non-ALLOCA instruction");
    return *m_allocaBytes;
}

std::string toString(IRTypeKind k) {
    switch (k) {
        case IRTypeKind::Void: return "void";
        case IRTypeKind::I1:   return "i1";
        case IRTypeKind::I8:   return "i8";
        case IRTypeKind::I16:  return "i16";
        case IRTypeKind::I32:  return "i32";
        case IRTypeKind::I64:  return "i64";
        case IRTypeKind::F32:  return "f32";
        case IRTypeKind::F64:  return "f64";
        case IRTypeKind::Ptr:  return "ptr";
    }
    return "<bad-type>";
}

std::string toString(Opcode op) {
    // Lowercase mnemonics, LLVM-style (LLVM uses "add", "icmp", "br" etc.
    // rather than the all-caps C++ enum names).
    switch (op) {
        case Opcode::MOV:      return "mov";
        case Opcode::ADD:      return "add";
        case Opcode::SUB:      return "sub";
        case Opcode::MUL:      return "mul";
        case Opcode::SDIV:     return "sdiv";
        case Opcode::UDIV:     return "udiv";
        case Opcode::SREM:     return "srem";
        case Opcode::UREM:     return "urem";
        case Opcode::NEG:      return "neg";
        case Opcode::AND:      return "and";
        case Opcode::OR:       return "or";
        case Opcode::XOR:      return "xor";
        case Opcode::NOT:      return "not";
        case Opcode::SHL:      return "shl";
        case Opcode::LSHR:     return "lshr";
        case Opcode::ASHR:     return "ashr";
        case Opcode::FADD:     return "fadd";
        case Opcode::FSUB:     return "fsub";
        case Opcode::FMUL:     return "fmul";
        case Opcode::FDIV:     return "fdiv";
        case Opcode::FNEG:     return "fneg";
        case Opcode::ZEXT:     return "zext";
        case Opcode::SEXT:     return "sext";
        case Opcode::TRUNC:    return "trunc";
        case Opcode::FPEXT:    return "fpext";
        case Opcode::FPTRUNC:  return "fptrunc";
        case Opcode::FPTOSI:   return "fptosi";
        case Opcode::FPTOUI:   return "fptoui";
        case Opcode::SITOFP:   return "sitofp";
        case Opcode::UITOFP:   return "uitofp";
        case Opcode::INTTOPTR: return "inttoptr";
        case Opcode::PTRTOINT: return "ptrtoint";
        case Opcode::BITCAST:  return "bitcast";
        case Opcode::LOAD:     return "load";
        case Opcode::STORE:    return "store";
        case Opcode::ALLOCA:   return "alloca";
        case Opcode::ICMP:     return "icmp";
        case Opcode::FCMP:     return "fcmp";
        case Opcode::SELECT:   return "select";
        case Opcode::JMP:      return "jmp";
        case Opcode::CJMP:     return "cjmp";
        case Opcode::RET:      return "ret";
        case Opcode::CALL:     return "call";
        case Opcode::NOP:      return "nop";
    }
    return "<bad-opcode>";
}

std::string toString(IcmpCond c) {
    switch (c) {
        case IcmpCond::EQ:  return "eq";
        case IcmpCond::NE:  return "ne";
        case IcmpCond::SLT: return "slt";
        case IcmpCond::SLE: return "sle";
        case IcmpCond::SGT: return "sgt";
        case IcmpCond::SGE: return "sge";
        case IcmpCond::ULT: return "ult";
        case IcmpCond::ULE: return "ule";
        case IcmpCond::UGT: return "ugt";
        case IcmpCond::UGE: return "uge";
    }
    return "<bad-icmp-cond>";
}

std::string toString(FcmpCond c) {
    switch (c) {
        case FcmpCond::OEQ: return "oeq";
        case FcmpCond::ONE: return "one";
        case FcmpCond::OLT: return "olt";
        case FcmpCond::OLE: return "ole";
        case FcmpCond::OGT: return "ogt";
        case FcmpCond::OGE: return "oge";
        case FcmpCond::UNO: return "uno";
        case FcmpCond::ORD: return "ord";
    }
    return "<bad-fcmp-cond>";
}

std::string toString(CallingConv cc) {
    switch (cc) {
        case CallingConv::C:     return "ccc";      
        case CallingConv::Win64: return "win64cc";
        case CallingConv::Fast:  return "fastcc";
        case CallingConv::Naked: return "nakedcc";
    }
    return "<bad-cc>";
}

std::string IRType::toString() const {
    return X2R_IR::toString(m_kind);
}

std::string IRValue::toString() const {
    if (isVReg())   return asVReg().toString();      // "%rax" or "%t17"
    if (isImm())    return asImm().toString();        // "42"
    if (isGlobal()) return asGlobal().toString();      // "@printf"
    return "<bad-value>";
}

//  IRInst::toString
//
//  This is the core formatter. It switches on opcode FAMILY (not
//  individual opcode) because most opcodes within a family share an
//  identical print layout — e.g. every binary arithmetic/bitwise op
//  prints as:   %dst = <mnemonic> <type> <lhs>, <rhs>
//
//    %dst = opcode type operand1, operand2, ...
//  Instructions with no result (STORE, JMP, CJMP, RET-void) omit the
//  "%dst = " prefix entirely.


std::string IRInst::toString() const {
    std::ostringstream ss;

    switch (m_opcode) {

        // Simple register copy
        // %rcx = mov i64 %rax
        // %rcx = mov i64 42
        case Opcode::MOV: {
            ss << dst().toString() << " = mov "
               << m_resultType.toString() << " "
               << m_operands[0].toString();
            break;
        }

        // Binary integer / float arithmetic and bitwise ops 
        // %t0 = add i64 %rax, %rbx
        case Opcode::ADD:  case Opcode::SUB:  case Opcode::MUL:
        case Opcode::SDIV: case Opcode::UDIV: case Opcode::SREM: case Opcode::UREM:
        case Opcode::AND:  case Opcode::OR:   case Opcode::XOR:
        case Opcode::SHL:  case Opcode::LSHR: case Opcode::ASHR:
        case Opcode::FADD: case Opcode::FSUB: case Opcode::FMUL: case Opcode::FDIV: {
            ss << dst().toString() << " = " << toString(m_opcode) << " "
               << m_resultType.toString() << " "
               << m_operands[0].toString() << ", "
               << m_operands[1].toString();
            break;
        }

        // Unary ops
        // %t0 = neg i64 %rax
        case Opcode::NEG: case Opcode::NOT: case Opcode::FNEG: {
            ss << dst().toString() << " = " << toString(m_opcode) << " "
               << m_resultType.toString() << " "
               << m_operands[0].toString();
            break;
        }

        // Type conversions 
        // %t17 = trunc i64 %rax to i32
        case Opcode::ZEXT: case Opcode::SEXT: case Opcode::TRUNC:
        case Opcode::FPEXT: case Opcode::FPTRUNC:
        case Opcode::FPTOSI: case Opcode::FPTOUI:
        case Opcode::SITOFP: case Opcode::UITOFP:
        case Opcode::INTTOPTR: case Opcode::PTRTOINT: case Opcode::BITCAST: {
            ss << dst().toString() << " = " << toString(m_opcode) << " "
               << m_operands[0].type().toString() << " "
               << m_operands[0].toString() << " to "
               << m_resultType.toString();
            break;
        }

        // Memory 
        // %t4 = load i64, ptr %t3, align 8
        case Opcode::LOAD: {
            ss << dst().toString() << " = load "
               << m_resultType.toString() << ", "
               << m_operands[0].type().toString() << " "
               << m_operands[0].toString()
               << ", align " << memFlags().alignment();
            break;
        }
        // store i64 %val, ptr %addr, align 8
        case Opcode::STORE: {
            ss << "store "
               << m_operands[0].type().toString() << " "
               << m_operands[0].toString() << ", "
               << m_operands[1].type().toString() << " "
               << m_operands[1].toString()
               << ", align " << memFlags().alignment();
            break;
        }
        // %t0 = alloca i8, i64 16, align 8   (16 bytes, 8-byte aligned)
        case Opcode::ALLOCA: {
            ss << dst().toString() << " = alloca i8, i64 "
               << allocaBytes()
               << ", align " << memFlags().alignment();
            break;
        }

        // Comparisons 
        // %cond = icmp slt i64 %rax, %rbx
        case Opcode::ICMP: {
            ss << dst().toString() << " = icmp " << toString(icmpCond()) << " "
               << m_operands[0].type().toString() << " "
               << m_operands[0].toString() << ", "
               << m_operands[1].toString();
            break;
        }
        // %cond = fcmp oeq f64 %a, %b
        case Opcode::FCMP: {
            ss << dst().toString() << " = fcmp " << toString(fcmpCond()) << " "
               << m_operands[0].type().toString() << " "
               << m_operands[0].toString() << ", "
               << m_operands[1].toString();
            break;
        }

        //  Branchless select 
        // %t0 = select i1 %cond, i64 %a, i64 %b
        case Opcode::SELECT: {
            ss << dst().toString() << " = select "
               << m_operands[0].type().toString() << " " << m_operands[0].toString() << ", "
               << m_resultType.toString() << " " << m_operands[1].toString() << ", "
               << m_resultType.toString() << " " << m_operands[2].toString();
            break;
        }

        // Control flow 
        // jmp bb_label
        case Opcode::JMP: {
            ss << "jmp " << m_branchTrue;
            break;
        }
        // cjmp i1 %cond, bb_true, bb_false
        case Opcode::CJMP: {
            ss << "cjmp " << m_operands[0].type().toString() << " "
               << m_operands[0].toString() << ", "
               << m_branchTrue << ", " << m_branchFalse;
            break;
        }
        // ret i64 %rax        (with value)
        // ret void            (no value)
        case Opcode::RET: {
            if (m_operands.empty()) {
                ss << "ret void";
            } else {
                ss << "ret " << m_operands[0].type().toString() << " "
                   << m_operands[0].toString();
            }
            break;
        }

        // Call 
        // %retval = call ccc i64 @printf(ptr %fmt, i64 %arg1)
        // call ccc void @puts(ptr %str)               (void-returning)
        case Opcode::CALL: {
            if (hasResult())
                ss << dst().toString() << " = ";
            ss << "call " << toString(callConv()) << " "
               << m_resultType.toString() << " "
               << m_operands[0].toString() << "(";
            for (size_t i = 1; i < m_operands.size(); ++i) {
                if (i > 1) ss << ", ";
                ss << m_operands[i].type().toString() << " "
                   << m_operands[i].toString();
            }
            ss << ")";
            if (m_isTailCall) ss << "  ; tail call";
            break;
        }

        case Opcode::NOP: {
            ss << "nop";
            break;
        }
    }

    return ss.str();
}

void printIRInst(const IRInst& inst, int indent) {
    std::cout << std::string(indent, ' ') << inst.toString();
    if (inst.sourceAddr() != 0) {
        std::cout << "  ; 0x" << std::hex << inst.sourceAddr() << std::dec;
    }
    std::cout << "\n";
}

void printIRBlock(const IRBasicBlock& block) {
    std::cout << block.name() << ":";

    if (!block.predecessors().empty()) {
        std::cout << "    ; preds = ";
        for (size_t i = 0; i < block.predecessors().size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << block.predecessors()[i];
        }
    }
    std::cout << "\n";

    for (const auto& inst : block.instructions())
        printIRInst(inst, /*indent=*/2);
}

void printIRFunction(const IRFunction& fn) {
    if (fn.isExternal()) {
        std::cout << "declare " << toString(fn.callingConv()) << " "
                  << fn.returnType().toString() << " @" << fn.name() << "(";
        for (size_t i = 0; i < fn.params().size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << fn.params()[i].type().toString();
        }
        std::cout << ")\n";
        return;
    }

    std::cout << "define " << toString(fn.callingConv()) << " "
              << fn.returnType().toString() << " @" << fn.name() << "(";
    for (size_t i = 0; i < fn.params().size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << fn.params()[i].type().toString() << " %"
                  << fn.params()[i].name();
    }
    std::cout << ") {\n";

    for (const auto& block : fn.blocks())
        printIRBlock(block);

    std::cout << "}\n";
}

void printIRProgram(const IRProgram& program) {
    for (const auto& g : program.globals()) {
        std::cout << "@" << g.name() << " = "
                  << (g.isReadOnly() ? "constant " : "global ")
                  << g.type().toString();

        if (g.isZeroInit()) {
            std::cout << " zeroinitializer";
        } else if (!g.initialBytes().empty()) {
            std::cout << " ; " << g.initialBytes().size() << " bytes from ELF";
        }
        std::cout << "  ; addr=0x" << std::hex << g.address() << std::dec << "\n";
    }
    if (!program.globals().empty())
        std::cout << "\n";

    bool first = true;
    for (const auto& fn : program.functions()) {
        if (!first) std::cout << "\n";   // blank line between functions
        first = false;
        printIRFunction(fn);
    }
}
void printIRProgram(const IRProgram& program) {
    for (const auto& g : program.globals()) {
        std::cout << "@" << g.name() << " = "
                  << (g.isReadOnly() ? "constant " : "global ")
                  << g.type().toString();

        if (g.isZeroInit()) {
            std::cout << " zeroinitializer";
        } else if (!g.initialBytes().empty()) {
            std::cout << " ; " << g.initialBytes().size() << " bytes from ELF";
        }
        std::cout << "  ; addr=0x" << std::hex << g.address() << std::dec << "\n";
    }
    if (!program.globals().empty())
        std::cout << "\n";

    bool first = true;
    for (const auto& fn : program.functions()) {
        if (!first) std::cout << "\n";   // blank line between functions
        first = false;
        printIRFunction(fn);
    }
}

}
