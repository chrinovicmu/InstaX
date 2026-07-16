#include "FlagState.hpp"
#include <iostream>
#include <stdexcept>


namespace Flags{

using namespace XTOR_IR; 

void FlagState::set(FlagOp, IRValue result, IRValue, lhs, 
                    IRValue rhs, IRType ty){
    m_valid = true;
    m_op  = op;
    m_result = std::move(result);
    m_lhs = std::move(lhs);
    m_rhs = std::move(rhs);
    m_ty = ty;
}

void FlagState::invalidate() {
    m_valid = false;
}

IRValue FlagState::emitNot(IRValue val, IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const {
    // NOT x  ≡  XOR x, 1
    uint32_t id = alloc();
    block.pushInst(IRInst::makeBinop(
        Opcode::XOR, VReg(id, "not"), IRType::i1(),
        val, IRValue::makeImm(1, IRType::i1())));
    return IRValue::makeVReg(id, IRType::i1());
}

IRValue FlagState::emitAnd(IRValue a, IRValue b,
                            IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const {
    uint32_t id = alloc();
    block.pushInst(IRInst::makeBinop(
        Opcode::AND, VReg(id, "and"), IRType::i1(), a, b));
    return IRValue::makeVReg(id, IRType::i1());
}

IRValue FlagState::emitOr(IRValue a, IRValue b,
                           IRBasicBlock& block,
                           std::function<uint32_t()>& alloc) const {
    uint32_t id = alloc();
    block.pushInst(IRInst::makeBinop(
        Opcode::OR, VReg(id, "or"), IRType::i1(), a, b));
    return IRValue::makeVReg(id, IRType::i1());
}

IRValue FlagState::emitXor(IRValue a, IRValue b,
                            IRBasicBlock& block,
                            std::function<uint32_t()>& alloc) const {
    uint32_t id = alloc();
    block.pushInst(IRInst::makeBinop(
        Opcode::XOR, VReg(id, "xor"), IRType::i1(), a, b));
    return IRValue::makeVReg(id, IRType::i1());
}

//emit zero flag 
IRValue FlagState::emitZF(IRBasicBlock& block,
                           std::function<uint32_t()>& alloc) const {
    uint32_t id = alloc();
    block.pushInst(IRInst::makeIcmp(
        IcmpCond::EQ,
        VReg(id, "zf"),
        m_result,
        IRValue::makeImm(0, m_ty)));
    return IRValue::makeVReg(id, IRType::i1());
}

IRValue FlagState::emitSF(IRBasicBlock& block,
                           std::function<uint32_t()>& alloc) const {
    uint32_t id = alloc();
    block.pushInst(IRInst::makeIcmp(
        IcmpCond::SLT,
        VReg(id, "sf"),
        m_result,
        IRValue::makeImm(0, m_ty)));
    return IRValue::makeVReg(id, IRType::i1());
}

//emit Carry flag 
//CF has different semantics depending on the FlagOp 
//
IRValue FlagState::emitCF(IRBasicBlock& block,
                           std::function<uint32_t()>& alloc) const {
    switch (m_op) {

        case FlagOp::ADD: {
            // result <u lhs  →  unsigned overflow occurred
            uint32_t id = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::ULT,
                VReg(id, "cf_add"),
                m_result, m_lhs));
            return IRValue::makeVReg(id, IRType::i1());
        }

        case FlagOp::SUB: {
            // result >u lhs  →  unsigned borrow occurred
            // Equivalently: lhs <u rhs (but we may not have rhs available
            // in all call sites; result >u lhs is always computable).
            uint32_t id = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::UGT,
                VReg(id, "cf_sub"),
                m_result, m_lhs));
            return IRValue::makeVReg(id, IRType::i1());
        }

        case FlagOp::INC:
        case FlagOp::DEC:
            // INC/DEC do not modify CF — return conservative false.
            // A future implementation could track the "live CF value"
            // from the last ADD/SUB and return that here.
            return IRValue::makeImm(0, IRType::i1());

        case FlagOp::AND:
        case FlagOp::OR:
        case FlagOp::XOR:
            // Always cleared by logical instructions.
            return IRValue::makeImm(0, IRType::i1());

        case FlagOp::SHL:
        case FlagOp::SHR:
        case FlagOp::SAR:
        case FlagOp::IMUL:
            // Approximation — see header comment.
            // TODO: extract the shifted-out bit using LSHR + TRUNC.
            return IRValue::makeImm(0, IRType::i1());
    }
    return IRValue::makeImm(0, IRType::i1());
}

IRValue FlagState::emitOF(IRBasicBlock& block,
                           std::function<uint32_t()>& alloc) const {
    switch (m_op) {

        case FlagOp::ADD:
        case FlagOp::SUB: {
            // pos_overflow = (lhs >= 0) AND (result < 0)
            uint32_t lhsNnId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SGE, VReg(lhsNnId, "lhs_nn"),
                m_lhs, IRValue::makeImm(0, m_ty)));

            uint32_t resNegId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SLT, VReg(resNegId, "res_neg"),
                m_result, IRValue::makeImm(0, m_ty)));

            IRValue posOv = emitAnd(
                IRValue::makeVReg(lhsNnId,  IRType::i1()),
                IRValue::makeVReg(resNegId, IRType::i1()),
                block, alloc);

            // neg_overflow = (lhs < 0) AND (result >= 0)
            uint32_t lhsNegId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SLT, VReg(lhsNegId, "lhs_neg"),
                m_lhs, IRValue::makeImm(0, m_ty)));

            uint32_t resNnId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SGE, VReg(resNnId, "res_nn"),
                m_result, IRValue::makeImm(0, m_ty)));

            IRValue negOv = emitAnd(
                IRValue::makeVReg(lhsNegId, IRType::i1()),
                IRValue::makeVReg(resNnId,  IRType::i1()),
                block, alloc);

            return emitOr(posOv, negOv, block, alloc);
        }

        case FlagOp::INC: {
            // OF = lhs was non-negative AND result went negative
            // (i.e. we wrapped from INT_MAX to INT_MIN)
            uint32_t lhsNnId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SGE, VReg(lhsNnId, "lhs_nn"),
                m_lhs, IRValue::makeImm(0, m_ty)));

            uint32_t resNegId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SLT, VReg(resNegId, "res_neg"),
                m_result, IRValue::makeImm(0, m_ty)));
            
            return emitAnd(
                IRValue::makeVReg(lhsNnId,  IRType::i1()),
                IRValue::makeVReg(resNegId, IRType::i1()),
                block, alloc);
        }

        case FlagOp::DEC: {
            // OF = lhs was negative AND result went non-negative
            // (i.e. we wrapped from INT_MIN to INT_MAX)
            uint32_t lhsNegId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SLT, VReg(lhsNegId, "lhs_neg"),
                m_lhs, IRValue::makeImm(0, m_ty)));

            uint32_t resNnId = alloc();
            block.pushInst(IRInst::makeIcmp(
                IcmpCond::SGE, VReg(resNnId, "res_nn"),
                m_result, IRValue::makeImm(0, m_ty)));
            
            return emitAnd(
                IRValue::makeVReg(lhsNegId, IRType::i1()),
                IRValue::makeVReg(resNnId,  IRType::i1()),
                block, alloc);
        }

        case FlagOp::AND:
        case FlagOp::OR:
        case FlagOp::XOR:
        case FlagOp::SHL:
        case FlagOp::SHR:
        case FlagOp::SAR:
        case FlagOp::IMUL:
            return IRValue::makeImm(0, IRType::i1());
    }
    return IRValue::makeImm(0, IRType::i1());
}

//  FlagState::materialise
//
//  The public entry point. Called by the lifter when it encounters
//  a flag-consuming instruction (Jcc, SETcc, CMOVcc).
//
//  Dispatches to the appropriate combination of emitZF / emitSF /
//  emitCF / emitOF based on the requested condition, combining the
//  individual flag i1 values with AND / OR / XOR as needed.
//
//  Returns an i1 IRValue representing the condition — ready to be
//  passed directly to IRInst::makeCjmp() or IRInst::makeSelect().
IRValue FlagState::materialise(FlagRequest request,
                                IRBasicBlock& block,
                                std::function<uint32_t()> allocTemp) const {

    // If no flag-setting instruction has been seen in this block yet,
    // we have no state to materialise from. This should not happen in
    if (!m_valid) {
        std::cerr << "FlagState::materialise: WARNING — no flag state set "
                     "(Jcc without preceding flag-setting instruction?). "
                     "Returning false (branch will never be taken).\n";
        return IRValue::makeImm(0, IRType::i1());
    }

    std::function<uint32_t()> alloc = std::move(allocTemp);

    switch (request) {

        case FlagRequest::ZF:
            // JZ / JE:  jump if result was zero
            return emitZF(block, alloc);

        case FlagRequest::NOT_ZF:
            // JNZ / JNE:  jump if result was non-zero
            return emitNot(emitZF(block, alloc), block, alloc);

        case FlagRequest::SF:
            // JS:  jump if result was negative (sign bit set)
            return emitSF(block, alloc);

        case FlagRequest::NOT_SF:
            // JNS:  jump if result was non-negative
            return emitNot(emitSF(block, alloc), block, alloc);

        case FlagRequest::CF:
            // JB / JC:  jump if carry (unsigned below)
            return emitCF(block, alloc);

        case FlagRequest::NOT_CF:
            // JAE / JNC:  jump if no carry (unsigned above-or-equal)
            return emitNot(emitCF(block, alloc), block, alloc);

        case FlagRequest::OF:
            // JO:  jump if signed overflow
            return emitOF(block, alloc);

        case FlagRequest::NOT_OF:
            // JNO:  jump if no signed overflow
            return emitNot(emitOF(block, alloc), block, alloc);

        case FlagRequest::CF_OR_ZF: {
            // JBE / JNA:  jump if unsigned below-or-equal  (CF=1 OR ZF=1)
            IRValue cf = emitCF(block, alloc);
            IRValue zf = emitZF(block, alloc);
            return emitOr(cf, zf, block, alloc);
        }

        case FlagRequest::NOT_CF_AND_NOT_ZF: {
            // JA / JNBE:  jump if unsigned above  (CF=0 AND ZF=0)
            IRValue ncf = emitNot(emitCF(block, alloc), block, alloc);
            IRValue nzf = emitNot(emitZF(block, alloc), block, alloc);
            return emitAnd(ncf, nzf, block, alloc);
        }

        case FlagRequest::SF_XOR_OF: {
            // JL / JNGE:  jump if signed less-than  (SF != OF)
            // This is the canonical "signed less-than" condition on x86.
            // It handles the case where signed overflow occurred and
            // flipped the sign of the result: if OF=1 and SF=1, the
            // result looks negative but wasn't really less-than; the
            // XOR detects the mismatch.
            IRValue sf = emitSF(block, alloc);
            IRValue of = emitOF(block, alloc);
            return emitXor(sf, of, block, alloc);
        }

        case FlagRequest::NOT_SF_XOR_OF: {
            // JGE / JNL:  jump if signed greater-or-equal  (SF == OF)
            IRValue sf  = emitSF(block, alloc);
            IRValue of  = emitOF(block, alloc);
            IRValue xorVal = emitXor(sf, of, block, alloc);
            return emitNot(xorVal, block, alloc);
        }

        case FlagRequest::ZF_OR_SF_XOR_OF: {
            // JLE / JNG:  jump if signed less-or-equal  (ZF=1 OR SF!=OF)
            IRValue zf  = emitZF(block, alloc);
            IRValue sf  = emitSF(block, alloc);
            IRValue of  = emitOF(block, alloc);
            IRValue sfXorOf = emitXor(sf, of, block, alloc);
            return emitOr(zf, sfXorOf, block, alloc);
        }

        case FlagRequest::NOT_ZF_AND_NOT_SF_XOR_OF: {
            // JG / JNLE:  jump if signed greater-than  (ZF=0 AND SF==OF)
            IRValue nzf = emitNot(emitZF(block, alloc), block, alloc);
            IRValue sf  = emitSF(block, alloc);
            IRValue of  = emitOF(block, alloc);
            IRValue sfEqOf = emitNot(emitXor(sf, of, block, alloc), block, alloc);
            return emitAnd(nzf, sfEqOf, block, alloc);
        }
    }

    // Should never reach here — all FlagRequest values are handled above.
    return IRValue::makeImm(0, IRType::i1());
}

std::optional<FlagRequest> flagRequestForJcc(ZydisMnemonic m) {
    switch (m) {
        case ZYDIS_MNEMONIC_JZ:    return FlagRequest::ZF;
        case ZYDIS_MNEMONIC_JNZ:   return FlagRequest::NOT_ZF;
        case ZYDIS_MNEMONIC_JS:    return FlagRequest::SF;
        case ZYDIS_MNEMONIC_JNS:   return FlagRequest::NOT_SF;
        case ZYDIS_MNEMONIC_JO:    return FlagRequest::OF;
        case ZYDIS_MNEMONIC_JNO:   return FlagRequest::NOT_OF;
        case ZYDIS_MNEMONIC_JB:    return FlagRequest::CF;
        case ZYDIS_MNEMONIC_JNB:   return FlagRequest::NOT_CF;
        case ZYDIS_MNEMONIC_JBE:   return FlagRequest::CF_OR_ZF;
        case ZYDIS_MNEMONIC_JNBE:  return FlagRequest::NOT_CF_AND_NOT_ZF;
        case ZYDIS_MNEMONIC_JL:    return FlagRequest::SF_XOR_OF;
        case ZYDIS_MNEMONIC_JNL:   return FlagRequest::NOT_SF_XOR_OF;
        case ZYDIS_MNEMONIC_JLE:   return FlagRequest::ZF_OR_SF_XOR_OF;
        case ZYDIS_MNEMONIC_JNLE:  return FlagRequest::NOT_ZF_AND_NOT_SF_XOR_OF;
        default:                   return std::nullopt;
    }
}

    
}
