#pragma once

#include <set>
#include <map>
#include <unordered_map>
#include <tuple>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/PostDominators.h>

namespace dependent_analyzer
{
	struct incoming_info
	{
		// A phi instruction or a select instruction
		const llvm::Instruction *I;
		// Incoming index for a phi or select instruction. For optimization: if the index is -1, incoming_info acts as a flag to indicate whether Instruction I was executed.
		const unsigned incoming_id;
		bool operator==(const incoming_info &info) const;

		bool operator!=(const incoming_info &info) const
		{
			return !(*this == info);
		}

		bool operator<(const incoming_info &info) const;
	};

	struct incoming_result
	{
		llvm::Instruction *terminator;
		std::set<incoming_info> incomings;
	};

	namespace data_flow_branch_graph
	{
		class graph_class;

		class graph_node
		{
		public:
			virtual const llvm::Instruction *ptr() const = 0;
			virtual const llvm::Value *value() const = 0;
			virtual std::tuple<const graph_class *, const graph_node *> subgraph_node() const { return {NULL, NULL}; };

			bool operator==(const graph_node &node) const
			{
				return ptr() == node.ptr();
			}

			bool operator!=(const graph_node &node) const
			{
				return ptr() != node.ptr();
			}

			bool operator<(const graph_node &node) const
			{
				return ptr() < node.ptr();
			}

			bool operator<=(const graph_node &node) const
			{
				return ptr() <= node.ptr();
			}

			virtual void free() const {}
			virtual void dump(unsigned tab = 0) const = 0;

			virtual unsigned get_num_incoming() const = 0;
			virtual const llvm::Value *get_incoming(unsigned i) const = 0;
			virtual llvm::BasicBlock *get_incoming_block(unsigned i) const = 0;
		};

		class graph_node_subgraph;

		class graph_node_inst : public graph_node
		{
		public:
			const llvm::Instruction *I;
			const llvm::Instruction *ptr() const override;
			const llvm::Value *value() const override;

			static bool is_graph_node_class(const llvm::Instruction *I);

			graph_node_inst(const llvm::Instruction *node);

			unsigned get_num_incoming() const override;

			const llvm::Value *get_incoming(unsigned i) const override;

			llvm::BasicBlock *get_incoming_block(unsigned i) const override;

			bool use_constant() const;

			void free() const override {}

			void dump(unsigned tab = 0) const override;
		};

		class graph_edge : public std::set<const graph_node *>
		{
		public:
			// Used for graph analysis: if even one constant value is used, it is not considered dominated.
			bool use_constant = false;
			void copy_from(graph_edge &edge)
			{
				use_constant = edge.use_constant;
				*this = edge;
			}
		};

		class graph_class : public std::map<const graph_node *, graph_edge>
		{
			const unsigned depth = 0;

			void check_valid_edge_destination() const;

		public:
			graph_node *root_node;

			graph_class(const graph_node *root, unsigned depth);
			~graph_class();

			void dump(unsigned tab = 0) const;

			class ir_parser
			{
			public:
				static std::set<graph_node_inst> follow_graph_root_node(const llvm::Instruction *user);
				static std::unordered_map<llvm::Instruction *, std::set<graph_node_inst>> branch_used_node_root(llvm::Function &F);
				static graph_class *create_graph(graph_node_inst root);
			};

		private:
			bool has_instruction_node(const llvm::Instruction *I) const;
			graph_node_subgraph *pullout(const graph_node *root, const graph_node *to);

			bool dominates(const graph_node *dominator, const graph_node *dominated) const;
			bool post_dominates(const graph_node *dominator, const graph_node *dominated) const;

			const graph_node *find_and_pullout_between_root_and_dominator(const graph_node *root, const graph_node *ignore_node);
			std::pair<const graph_node *, std::vector<std::pair<const graph_node *, unsigned>>> find_most_used_value(const graph_node *target_node, const graph_node *ignore_node, std::map<const data_flow_branch_graph::graph_node *, std::list<unsigned>> &check_incoming) const;
			std::pair<const graph_node *, std::vector<std::pair<const graph_node *, unsigned>>> filter_most_used_value(const graph_node *target_node, const graph_node *ignore_node, std::map<const data_flow_branch_graph::graph_node *, std::list<unsigned>> &check_incoming) const;
			std::set<incoming_info> filter(const graph_node *ignore_node, const llvm::Instruction *master, llvm::DominatorTree &DT, llvm::PostDominatorTree &PDT) const;

		public:
			void format_graph(const graph_node *ignore_node = NULL);
			std::set<incoming_info> filter_target_node(const llvm::Instruction *branch, llvm::DominatorTree &DT, llvm::PostDominatorTree &PDT) const;
			bool if_add_node_create_loop(const graph_node *from, const graph_node *to) const;
		};
	};

	void registerFunctionAnalysisPass(llvm::FunctionAnalysisManager &FAM);
	std::list<incoming_result> runOnFunction(llvm::Function &F);
};
