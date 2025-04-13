#include "analyzer.h"
#include <stack>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>

namespace dependent_analyzer::data_flow_branch_graph
{
	const llvm::Instruction *graph_node_inst::ptr() const { return I; }
	const llvm::Value *graph_node_inst::value() const { return I; }

	bool graph_node_inst::is_graph_node_class(const llvm::Instruction *I)
	{
		return llvm::PHINode::classof(I) || llvm::SelectInst::classof(I);
	}

	graph_node_inst::graph_node_inst(const llvm::Instruction *node) : I(node)
	{
		assert(is_graph_node_class(I));
	}

	unsigned graph_node_inst::get_num_incoming() const
	{
		if (const llvm::PHINode *phi = llvm::dyn_cast<llvm::PHINode>(I))
			return phi->getNumIncomingValues();
		if (const llvm::SelectInst *select = llvm::dyn_cast<llvm::SelectInst>(I))
			return 2;
		assert("invalid graph node class");
		return 0;
	}

	const llvm::Value *graph_node_inst::get_incoming(unsigned i) const
	{
		if (const llvm::PHINode *phi = llvm::dyn_cast<llvm::PHINode>(I))
			return phi->getIncomingValue(i);
		if (const llvm::SelectInst *select = llvm::dyn_cast<llvm::SelectInst>(I))
			return i ? select->getTrueValue() : select->getFalseValue();
		assert("invalid graph node class");
		return NULL;
	}

	llvm::BasicBlock *graph_node_inst::get_incoming_block(unsigned i) const
	{
		if (const llvm::PHINode *phi = llvm::dyn_cast<llvm::PHINode>(I))
			return phi->getIncomingBlock(i);
		return NULL;
	}

	bool graph_node_inst::use_constant() const
	{
		for (unsigned i = 0; i < get_num_incoming(); i++)
		{
			const llvm::Value *incoming = get_incoming(i);
			if (!llvm::Instruction::classof(incoming))
				return true;
		}
		return false;
	}

	std::set<graph_node_inst> graph_class::ir_parser::follow_graph_root_node(const llvm::Instruction *user)
	{
		if (!user)
			return std::set<graph_node_inst>();
		std::stack<const llvm::Instruction *> cond;
		std::set<const llvm::Instruction *> seek;
		cond.push(user);
		seek.insert(user);

		std::set<graph_node_inst> root_node;

		while (!cond.empty())
		{
			const llvm::Instruction *I = cond.top();
			cond.pop();

			if (I->isTerminator())
				assert("Inaccesable");
			if (graph_node_inst::is_graph_node_class(I))
			{
				root_node.insert(I);
			}
			else if (const llvm::CallBase *call_base = llvm::dyn_cast<llvm::CallBase>(I))
			{
				for (const llvm::Use &arg : call_base->args())
				{
					const llvm::Value *v = arg.get();
					const llvm::Instruction *arg_inst = llvm::dyn_cast<llvm::Instruction>(v);
					if (!arg_inst)
						continue;
					if (seek.insert(arg_inst).second)
						cond.push(arg_inst);
				}
			}
			else
			{
				for (const llvm::Use &use : I->operands())
				{
					const llvm::Instruction *operand_inst = llvm::dyn_cast<llvm::Instruction>(use.get());
					if (!operand_inst)
						continue;
					if (seek.insert(operand_inst).second)
						cond.push(operand_inst);
				}
			}
		}
		return root_node;
	}

	std::unordered_map<llvm::Instruction *, std::set<graph_node_inst>> graph_class::ir_parser::branch_used_node_root(llvm::Function &F)
	{
		std::unordered_map<llvm::Instruction *, std::set<graph_node_inst>> used_node;
		for (llvm::BasicBlock &BB : F)
			if (BB.getTerminator()->getNumSuccessors() > 1)
#ifdef BRANCH_ONLY_TWO_SUCCESSORS
				if (BB.getTerminator()->getNumSuccessors() == 2)
#endif
					used_node[BB.getTerminator()] = follow_graph_root_node(BB.getTerminator());
#if NOT_FOLLOW_CALL == 0
		for (llvm::BasicBlock &BB : F)
			for (llvm::Instruction &I : BB)
				if (llvm::CallBase *call_base = llvm::dyn_cast<llvm::CallBase>(&I))
					used_node[&I] = follow_graph_root_node(&I);
#endif
		return used_node;
	}

	graph_class *graph_class::ir_parser::create_graph(graph_node_inst root)
	{
		const llvm::Function *F = root.I->getFunction();
		graph_node_inst *root_node = new graph_node_inst(root.I);
		graph_class *graph = new graph_class(root_node, 0);

		std::map<const llvm::Instruction *, const graph_node_inst *> graph_node_list;
		graph_node_list[root.I] = root_node;

		std::set<const llvm::Instruction *> seek;
		std::stack<const llvm::Instruction *> stack;
		stack.push(root.I);
		seek.insert(root.I);

		while (!stack.empty())
		{
			const llvm::Instruction *cur_node_inst = stack.top();
			const graph_node_inst *cur_node_ptr = graph_node_list[cur_node_inst];
			assert(cur_node_ptr);
			stack.pop();
			graph_edge &edge = (*graph)[cur_node_ptr];
			assert(cur_node_ptr->get_num_incoming() > 0);

			// When branching from a switch that matches multiple values and later merges with a phi node, the same incoming block may appear multiple times.
			std::set<llvm::BasicBlock *> looked_incoming_bb;

			for (unsigned int i = 0; i < cur_node_ptr->get_num_incoming(); i++)
			{
				// Skip if the basic block has already been checked and is registered as incoming.
				llvm::BasicBlock *incoming_bb = cur_node_ptr->get_incoming_block(i);
				if (incoming_bb && !looked_incoming_bb.insert(incoming_bb).second)
					continue;
				const llvm::Value *incoming = cur_node_ptr->get_incoming(i);
				const llvm::Instruction *incoming_inst = llvm::dyn_cast<llvm::Instruction>(incoming);
				if (!incoming_inst)
				{
					edge.use_constant = true;
					continue;
				}
				std::set<graph_node_inst> next_nodes = follow_graph_root_node(incoming_inst);
				bool inserted = false;
				for (graph_node_inst next : next_nodes)
				{
					// Do not create edges to itself.
					if (cur_node_inst == next.I)
						continue;
					auto next_node_itr = graph_node_list.find(next.I);
					//	Only add if it does not create a cycle.
					if (next_node_itr == graph_node_list.end() || !graph->if_add_node_create_loop(cur_node_ptr, next_node_itr->second))
					{
						const graph_node_inst *next_node = next_node_itr == graph_node_list.end() ? new graph_node_inst(next.I) : next_node_itr->second;
						if (next_node_itr == graph_node_list.end())
							graph_node_list[next.I] = next_node;

						edge.insert(next_node);
						if (graph->find(next_node) == graph->end())
							(*graph)[next_node] = {};
						inserted = true;
						if (seek.insert(next.I).second)
							stack.push(next.I);
					}
				}
				edge.use_constant |= !inserted;
			}
			edge.use_constant |= cur_node_ptr->use_constant();
		}
		graph->check_valid_edge_destination();
		return graph;
	}

	bool graph_class::if_add_node_create_loop(const graph_node *from, const graph_node *to) const
	{
		assert(from != to);
		std::stack<const graph_node *> stack;
		std::set<const graph_node *> seek;
		stack.push(to);
		seek.insert(to);
		while (!stack.empty())
		{
			const graph_node *node = stack.top();
			stack.pop();
			for (const graph_node *next_node : this->at(node))
			{
				if (next_node == from)
					return true;
				if (seek.insert(next_node).second)
					stack.push(next_node);
			}
		}
		return false;
	}
};
