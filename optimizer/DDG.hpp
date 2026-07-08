// DDG.hpp  — Data Dependency Graph
//
// Models the data and control dependencies between instructions
// within a single basic block. Used by two consumers:
//
//   1. Dependency analysis   — identifies hazards (RAW, WAR, WAW,
//                              memory ordering, control flow).
//   2. Instruction scheduling — a list-scheduler walks the DDG in
//                              topological order, respecting edge
//                              latencies to find a valid cycle
//                              assignment for each instruction.
//
//   Producer  — the instruction that WRITES a value
//   Consumer  — the instruction that READS that value
//   Hazard    — a situation where reordering two instructions would
//               change the program's observable behaviour
//
//   RAW (Read After Write)  — true dependency: consumer must execute
//                             AFTER producer. Most common, always
//                             constrains scheduling.
//   WAR (Write After Read)  — anti-dependency: writer must execute
//                             AFTER the earlier reader, or the reader
//                             would see the new value instead of the
//                             old one. Removable by renaming.
//   WAW (Write After Write) — output dependency: the second write
//                             must win. Also removable by renaming.
//   MEM (memory ordering)   — conservative ordering between a LOAD
//                             and a STORE (or two STOREs) when alias
//                             analysis cannot prove they are to
//                             different addresses.
//   CTRL (control)          — the instruction must not be moved past
//                             a branch (or past an instruction that
//                             a branch must not be moved past).

#pragma once

#include "../IR.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <iosfwd>


namespace Optimizer{

enum class DepType{
    //register dependencies
    RAW, 
    WAR, 
    WAW, 

    //memory dependencies
    MEM_RAW,
    MEM_WAR, 
    MEM_RAW, 

    //instruction must not mov part a branch terminator
    CTRL 
}; 

const char * depTypname(DepType t); 

struct DepEdge{
    struct DDGNode* target = nullptr; 
    DepType type = DepType::RAW;

 // Minimum number of cycles that must elapse between the START of
    // the source instruction and the START of the target instruction.
    //
    // (architecture-specific)
    //   RAW on a simple ALU result:  latency = 1
    //   RAW on a LOAD result:        latency = 3 (cache-hit load-use)
    //   WAR / WAW:                   latency = 1 (structural, not data)
    //   MEM_* conservative:          latency = 1
    //   CTRL:                        latency = 1
    //
    // The scheduler uses this to compute readyCycle for each node:
    //   consumer.readyCycle = max over all predecessors of
    //                         (pred.scheduledCycle + edge.latency)
    uint32_t latency = 1;

    //VRegId involved in this dependency 
    uint32_t vregId = UINT32_MAX; 

    bool operator==(const DepEdge& o)const{
        return target == o.target && type == o.type && vregId == o.vregId; 
    }

};

struct DDGNode{

    //Index of instruction in the IRBasicblock  instruction vector 
    uint32_t instrIndex = 0; 
    //stable pointer into IRBasicblock instruction vector
    const XTOR_IR::IRInst * Inst = nullptr; 
    std::string label ; 
    std::vector<DepEdge> successors; 
    std::vector<DepEdge> predecessors; 

    //Scheduling metadata 
    
    //earliest cycle this instruction si allowd to start 
    uint32_t readyCycle = 0; 
    //cycle this instruction was placed in the scheduler  
    uint32_t scheduledCycle = UINT32_MAX; 
    //length of the longest latency-weigthed path from this node to any leaf instruction 
    uint32_t criticalPathLength = 0; 
    //number of predecessors edges whos source has not yet been scheduled 
    uint32_t inDegree = 0;
    //true if instruction is a block terminator 
    bool isTerminator = false; 
    //true if instruction has a memoru side-effect 
    bool hasSideEffect = false; 

    bool isScheduled() const {
        return scheduledCycle |= UINT32_MAX;
    }
    //Scheduling priority — higher is more urgent.
    // Critical path length is the primary key; instrIndex (lower =
    // earlier in original order) is the tiebreaker to preserve
    // original ordering when two nodes have equal priority.
    uint32_t priority() const {
        return criticalPathLength;
    }
}; 

//Latency table 
//returns the ezxpected hardware latency in cycles 
uint32_t defaultLatency(XTOR_IR::Opcode producerOpcode, DepType dep); 


//DDG- the complete Data Dependency Graph of one basic block 
class DDG{
public: 
    DDG() = default; 
    ~DDG() = default; 

     // non-copyable — nodes hold raw pointers into each other.
    DDG(const DDG&) = delete;
    DDG& operator=(const DDG&) = delete;
    DDG(DDG&&) = default;
    DDG& operator=(DDG&&) = default;

    void build(const XTOR_IR::IRBasicBlock& block); 

    const std::vector<DDGNode>& nodes() const { return m_nodes; }
    std::vector<DDGNode>& nodes() { return m_nodes; }
    size_t size() const { return m_nodes.size(); }
    const DDGNode& node(size_t i) const { return m_nodes[i]; }
    DDGNode& node(size_t i) { return m_nodes[i]; }

    // Returns indices of nodes with inDegree == 0 — the initial ready list
    // for a list-scheduling pass. The scheduler calls this once, then
    // maintains its own ready list dynamically.
    std::vector<uint32_t> rootIndices() const;

    // Total schedule length lower bound: max scheduledCycle + 1
    // across all nodes (only valid after a scheduling pass).
    uint32_t scheduleLength() const;

    void dump() const;
    void emitDOT(std::ostream& out, const std::string& graphName = "DDG") const;

private:

    //register RAW, WAR, WAW dependencies
    void buildRegisterDeps(); 

    //memory MEM_RAW, MEM_WAR, MEM_WAW dependencies
    void buildMemoryDeps(); 

    build buildControlDeps(); 

    void computeInDegress(); 

    void computeCriticalPaths(); 

    void addEdge(uint32_t fromIdx, uint32_t toIdx,
                 DepType type, uint32_t latency,
                 uint32_t vregId = UINT32_MAX);

    static bool isMem(const DDGNode& n);
    static bool isTerminator(const DDGNode& n);

    std::vector<DDGNode> m_nodes;
    const XTOR_IR::IRBasicblock* m_block = nullptr; 
}; 
    
}//namespace Optimizer 
