#include "analyzer.h"
#include "util.h"

#include <llvm/IR/Value.h>
#include <llvm/IR/Use.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Support/Casting.h>

#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/AssumptionCache.h>
#include <llvm/Analysis/PostDominators.h>
#include <llvm/Analysis/DependenceAnalysis.h>
#include <llvm/Analysis/AliasAnalysis.h>
#include <llvm/Analysis/Delinearization.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/Pass.h>

namespace dependent_analyzer
{
    using namespace data_flow_branch_graph;

    bool incoming_info::operator==(const incoming_info &info) const
    {
        // If it serves as an execution flag for Instruction I, check whether I belongs to the same BasicBlock.
        if (incoming_id == -1u || info.incoming_id == -1u)
            return incoming_id == info.incoming_id && I->getParent() == info.I->getParent();

		// In the case of completely identical incoming values
        if (I == info.I && incoming_id == info.incoming_id)
            return true;

        // Even if the same instruction has different incoming values, a switch instruction may result in identical incoming blocks, so we check for that.

        // Treat as the same if they correspond to the same edge.
        if (I->getParent() != info.I->getParent()) return false;
        if (const llvm::PHINode *phi1 = llvm::dyn_cast<llvm::PHINode>(I))
        {
            if (const llvm::PHINode *phi2 = llvm::dyn_cast<llvm::PHINode>(info.I))
                if (phi1->getIncomingBlock(incoming_id) == phi2->getIncomingBlock(info.incoming_id))
                    return true;
        }
        else if (const llvm::SelectInst *select1 = llvm::dyn_cast<llvm::SelectInst>(I))
        {
            if (const llvm::SelectInst *select2 = llvm::dyn_cast<llvm::SelectInst>(info.I))
                if (select1->getCondition() == select2->getCondition() && incoming_id == info.incoming_id)
                    return true;
        }
        return false;
    }

    bool incoming_info::operator<(const incoming_info &info) const
    {
        // Always return false if they match.
        if (*this == info)
            return false;

        // Order of comparison for magnitude
        // 1. If the BasicBlocks are different, order them by the address of the BasicBlock.
        // 2. If only one of the incoming_info is the execution flag for a Instruction I, the BasicBlock flag should be considered smaller.
        // 3. If only one of the incoming_info is a PHINode, the PHINode side should be considered smaller.
        // 4. If referring to the same Select instruction, the side where the condition is true is considered smaller.
        // 5. If both are PHINodes, the side with the smaller incoming block address is considered smaller.
        // 6. If both are Select instructions, the side with the smaller address of the Condition is considered smaller.

        if (I->getParent() != info.I->getParent())
            return I->getParent() < info.I->getParent();
        if (incoming_id == -1u || info.incoming_id == -1u)
        {
            assert(incoming_id != info.incoming_id);
            return incoming_id == -1u;
        }
        if (const llvm::PHINode *phi1 = llvm::dyn_cast<llvm::PHINode>(I))
        {
            if (const llvm::PHINode *phi2 = llvm::dyn_cast<llvm::PHINode>(info.I))
                return phi1->getIncomingBlock(incoming_id) < phi2->getIncomingBlock(info.incoming_id);
            else
                return true;
        }
        else if (const llvm::SelectInst *select1 = llvm::dyn_cast<llvm::SelectInst>(I))
        {
            if (const llvm::SelectInst *select2 = llvm::dyn_cast<llvm::SelectInst>(info.I))
                return select1->getCondition() == select2->getCondition() ? incoming_id < info.incoming_id : select1->getCondition() < select2->getCondition();
            else
                return false;
        }
        assert(false && "Not PHI or select");
    }

    std::list<incoming_result> runOnFunction(llvm::Function &F)
    {
        if (F.empty() || F.size() <= 1)
            return {};

        llvm::DominatorTree DT(F);
        llvm::PostDominatorTree PDT(F);

        std::list<incoming_result> result;

        auto check_branch = graph_class::ir_parser::branch_used_node_root(F);
        for (auto bb : check_branch)
        {
            llvm::Instruction *I = bb.first;
            std::set<incoming_info> elements;
            for (auto &node : bb.second)
            {
                graph_class *graph = graph_class::ir_parser::create_graph(node);
                graph->format_graph();
                elements.merge(graph->filter_target_node(I, DT, PDT));
            }

            if (!elements.empty())
                result.push_back({I, elements});
        }
        return result;
    }
}
