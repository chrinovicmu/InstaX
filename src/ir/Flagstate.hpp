#pragma once 

#include "IR.hpp"
#include <functional> 
#include <optional>
#include <string> 

namespace FlagsSate{

///which instruction last wrote the flags 
enum class FlagOp{
    ADD, 
    SUB, 
    INC, 
    DEC, 
    AND, 
    OR, 
    XOR, 
    SHL,
    SHR, 
    SAR, 
    IMUL, 
}; 

//condition the consumming instruction needs  
enum class FlagRequest{
    ZF,     //JZ / JE: 
    NOT_ZF, //JNZ /JNE: 

    SF,     //JS:
    NOT_SF, //JNS 

    CF,     //JB /JC: 
    NOT_CF, //JAE / JNC:

    OF,     //JO: 
    NOT_OF, //JNO:

    CF_OR_ZF //JBE / JNA 
    NOT_CF_AND_NOT_ZF, //JA / JNBE 
    
    SF_XOR_OF,        // JL / JNGE: 
    NOT_SF_XOR_OF,    // JGE / JNL: 
    ZF_OR_SF_XOR_OF,  // JLE / JNG: 
    NOT_ZF_AND_NOT_SF_XOR_OF, // JG / JNLE: 
}; 

//Maps a Zydis mnemonic to the FlagRequest it needs 
std::optional<FlagRequest> flagRequestForJcc(ZydisMnemonic mnemonic); 

class FlagsSate{
public:
    FlagsSate() = default; 

    //called by lifeer after emmitting the arithmetic IR instruction
    void set(FlagOp op, 
             XTOR_IR::IRValue result, 
             XTOR_IR::IRValue lhs, 
             XTOR_IR::IRValue rhs, 
             XTOR_IR::IRType ty);

    //clear the flag state 
    void invalidate(); 

    //emits the IR instructions into block to produce an i1 IRValue 
    //representing the requested condition
    XTOR_IR::IRValue materialise(
        FlagRequest request, 
        XTOR_IR::IRBasicBlock& block, 
        std::function<uint32_t()> allocTemp )const 

    bool valid() const { return m_valid; }
    FlagOp op() const { return m_op; }
    XTOR_IR::IRType ty() const {return m_ty; }

private: 

    //each emit IR for exactly one flag and returns it's 
    //i1 IRValue holding flah's current value

  X2R_IR::IRValue emitZF(X2R_IR::IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const;

    X2R_IR::IRValue emitSF(X2R_IR::IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const;

    X2R_IR::IRValue emitCF(X2R_IR::IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const;

    X2R_IR::IRValue emitOF(X2R_IR::IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const;

    // emits a boolean NOT of an i1 value (XOR with 1).
    X2R_IR::IRValue emitNot(X2R_IR::IRValue val,
                             X2R_IR::IRBasicBlock& block,
                             std::function<uint32_t()>& alloc) const;

    // emits AND of two i1 values.
    X2R_IR::IRValue emitAnd(X2R_IR::IRValue a, X2R_IR::IRValue b,
                             X2R_IR::IRBasicBlock& block,
                             std::function<uint32_t()>& alloc) const;

    // emits OR of two i1 values.
    X2R_IR::IRValue emitOr(X2R_IR::IRValue a, X2R_IR::IRValue b,
                            X2R_IR::IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const;

    // emits XOR of two i1 values.
    X2R_IR::IRValue emitXor(X2R_IR::IRValue a, X2R_IR::IRValue b,
                             X2R_IR::IRBasicBlock& block,
                             std::function<uint32_t()>& alloc) const;

    bool m_valid = false; 
    FlagOp m_op = FlagOp::ADD; 
    XTOR_IR::IRType m_ty = XTOR_IR::IRType::i64(); 
    XTOR_IR::IRValue m_result = XTOR_IR::IRValue::makeImm(0, XTOR_IR::IRType::i64()); 
    XTOR_IR::IRValue m_lhs = XTOR_IR::IRValue::makeImm(0, XTOR_IR::IRType::i64()); 
    XTOR_IR::IRValue m_rhs = XTOR_IR::IRValue::makeImm(0, XTOR_IR::IRType::i64()); 
}; 

}
