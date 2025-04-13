#include <stdio.h>
#include <string>
#include <unordered_map>
#include <map>
#include <set>
#include <stack>
#include <list>

#include "util.h"
#include "analyzer.h"

// 1. 関数中の各分岐命令のconditionへのデータフロー上にphi命令かselect命令があるか解析
//      1.1. 分岐命令とphiまたはselectの組を作る
// 2. 使われている各phi,selectに対して解析

// selectはthen,elseのどちらに分岐したかだけを見るべきか
// それともconditionが依存する分岐も見るべきか
// conditionに使われるだけならデータは隠蔽されるので一旦無視

namespace dependent_analyzer::data_flow_branch_graph
{
	class graph_node_subgraph : public graph_node
	{
	public:
		const graph_class *subgraph;
		const graph_node *to;
		graph_node_subgraph(const graph_class *graph, const graph_node *to) : subgraph(graph), to(to) {}
		const llvm::Instruction *ptr() const override { return to->ptr(); }
		const llvm::Value *value() const override { return subgraph->root_node->value(); }
		std::tuple<const graph_class *, const graph_node *> subgraph_node() const override { return {subgraph, to}; };

		void free() const override { delete subgraph; }
		void dump(unsigned tab = 0) const override
		{
			print_ntab(tab);
			fprintf(stderr, "subgraph %p: %p\n", this, to->ptr());
			subgraph->dump(tab);
		}

		unsigned get_num_incoming() const override { return to->get_num_incoming(); }
		const llvm::Value *get_incoming(unsigned i) const override { return to->get_incoming(i); }
		llvm::BasicBlock *get_incoming_block(unsigned i) const override { return to->get_incoming_block(i); }
	};

	void graph_node_inst::dump(unsigned tab) const
	{
		print_ntab(tab);
		fprintf(stderr, "%p: %s\n", ptr(), getValueOperand(ptr()).c_str());
	}

	graph_class::graph_class(const graph_node *root, unsigned depth) : depth(depth)
	{
		root_node = const_cast<graph_node *>(root);
	}

	void graph_class::check_valid_edge_destination() const
	{
		for (auto A : *this)
			for (auto B : A.second)
				assert(this->find(B) != this->end());
	}

	graph_class::~graph_class()
	{
		for (auto &edge : *this)
			edge.first->free();
	}

	void graph_class::dump(unsigned tab) const
	{
		if (0)
			return;
		print_ntab(tab);
		fprintf(stderr, "%p: graph_class\n", this);
		print_ntab(tab + 1);
		fprintf(stderr, "root_node=%p\n", root_node->ptr());
		for (auto &[node, edges] : *this)
		{
			node->dump(tab + 1);
			print_ntab(tab + 2);
			fprintf(stderr, "edges: ");
			if (edges.use_constant)
				fprintf(stderr, "const ");
			for (const graph_node *dest : edges)
				fprintf(stderr, "%p ", dest->ptr());
			fprintf(stderr, "\n");
		}
	}

	std::set<incoming_info> graph_class::filter_target_node(const llvm::Instruction *branch, llvm::DominatorTree &DT, llvm::PostDominatorTree &PDT) const
	{
		return filter(NULL, branch, DT, PDT);
	}

	bool graph_class::has_instruction_node(const llvm::Instruction *I) const
	{
		return std::find_if(this->begin(), this->end(), [I](const std::pair<const graph_node *, graph_edge> &node)
							{ return node.first->ptr() == I; }) != this->end();
	}

	std::pair<const graph_node *, std::vector<std::pair<const graph_node *, unsigned>>> graph_class::find_most_used_value(const graph_node *target_node, const graph_node *ignore_node, std::map<const data_flow_branch_graph::graph_node *, std::list<unsigned>> &check_incoming) const
	{
		std::pair<const graph_node *, std::vector<std::pair<const graph_node *, unsigned>>> result;
		for (auto &[node, edge] : *this)
		{
			auto a = filter_most_used_value(node, ignore_node, check_incoming);
			if (result.second.size() < a.second.size())
				result = a;
		}
		return result;
	}

	std::pair<const graph_node *, std::vector<std::pair<const graph_node *, unsigned>>> graph_class::filter_most_used_value(const graph_node *target_node, const graph_node *ignore_node, std::map<const data_flow_branch_graph::graph_node *, std::list<unsigned>> &check_incoming) const
	{
		std::pair<const graph_node *, std::vector<std::pair<const graph_node *, unsigned>>> result;
		if (target_node == ignore_node)
			return result;

		std::stack<const graph_node *> stack;
		std::set<const graph_node *> seek;
		std::unordered_map<const llvm::Value *, std::vector<std::pair<const graph_node *, unsigned>>> values;
		stack.push(target_node);
		seek.insert(target_node);

		while (!stack.empty())
		{
			const graph_node *node = stack.top();
			stack.pop();

			// 観測対象のincomingをリストに追加
			auto incoming_itr = check_incoming.find(node);
			if (incoming_itr != check_incoming.end())
				for (unsigned i : incoming_itr->second)
				{
					const llvm::Value *incoming_value = node->get_incoming(i);
					const llvm::Instruction *incoming_inst = llvm::dyn_cast<llvm::Instruction>(incoming_value);
					values[incoming_value].push_back(std::make_pair(node, i));
				}

			// 子ノードのうち解析対象をスタックに追加
			const data_flow_branch_graph::graph_edge &edges = this->at(node);
			const unsigned n_incoming = node->get_num_incoming();
			for (unsigned i = 0; i < n_incoming; i++)
			{
				const llvm::Value *incoming_value = node->get_incoming(i);
				const llvm::Instruction *incoming_inst = llvm::dyn_cast<llvm::Instruction>(incoming_value);
				// 別の有効なノードにつながらないincomingは無視
				if (!incoming_inst || (ignore_node && incoming_inst == ignore_node->ptr()))
					continue;
				for (const data_flow_branch_graph::graph_node *next_node : edges)
				{
					if (next_node->value() != incoming_inst)
						continue;
					// incomingが直接ほかのノードの結果を参照している場合はそのノードも走査対象に追加
					if (seek.insert(next_node).second)
						stack.push(next_node);
					break;
				}
			}
		}

		// value一覧をもとにまとめるvalueを決定する
		unsigned max_count = 0;
		auto max_itr = values.end();
		for (auto itr = values.begin(); itr != values.end(); itr++)
			if (itr->second.size() > max_count)
			{
				max_count = itr->second.size();
				max_itr = itr;
			}

		if (max_count > 1)
		{
			result.first = target_node;

			// 対応するincomingについての観測をやめる
			for (auto erase_pair : max_itr->second)
			{
				// check_incoming[erase_node].remove(erase_incoming);
				result.second.push_back(erase_pair);
			}
			// nodeが実行されたかを観測に含める
			// check_incoming[from_node].push_back(-1);
		}
		return result;
	}

	// フィルタの方法
	// 1. 各ノードごとのincomingをリスト化
	//     ただしsubgraphのtoノードのincomingは無視
	// 2. 各incomingのうち他のノードの値を直接使用するものを削除
	//     subgraphのrootノードを直接使用するものも削除
	// 3. incomingの重複を削除
	// 4. incomingがsubgraphの値を決定的な計算の後に使用するなら削除
	//     subgraphから伝わる情報はそのsubgraphの解析で決定できる
	// 5. グラフのrootノードが無条件に観測可能な状態であれば、重複削除後のincomingから最も頻度の高いものを削除
	std::set<incoming_info> graph_class::filter(const graph_node *ignore_node, const llvm::Instruction *master, llvm::DominatorTree &DT, llvm::PostDominatorTree &PDT) const
	{
		std::set<incoming_info> filtered_node;
		for (auto &edge : *this)
		{
			const auto [subgraph, to] = edge.first->subgraph_node();
			if (!subgraph)
				continue;
			// root_nodeがsubgraphであればそのsubgraphはターゲット分岐をdominateしている
			// TODO: 親ノードがselectであれば，その子ノードはdomiante状態を親から引き継ぐ
			// TODO: そもそもdominatortreeで判定したい
			std::set<incoming_info> subgraph_filtered_node = subgraph->filter(to, master, DT, PDT);
			filtered_node.merge(subgraph_filtered_node);
		}

		// すべての分岐結果を判別するために必要なincomingを収集
		std::map<const data_flow_branch_graph::graph_node *, std::list<unsigned>> check_incoming;
		for (auto [from_node, from_edges] : *this)
		{
			if (from_node == ignore_node)
				continue;
			const unsigned n_incoming = from_node->get_num_incoming();
			check_incoming[from_node] = {};

			// switchで複数の値とマッチして分岐する場合にpreが複数存在
			std::set<llvm::BasicBlock *> looked_incoming_bb;

			for (unsigned i = 0; i < n_incoming; i++)
			{
				// 既にチェックしたbbがincomingに登録されている場合はスルー
				llvm::BasicBlock *incoming_bb = from_node->get_incoming_block(i);
				if (incoming_bb && !looked_incoming_bb.insert(from_node->get_incoming_block(i)).second)
					continue;

				const llvm::Value *incoming_value = from_node->get_incoming(i);
				const llvm::Instruction *incoming_inst = llvm::dyn_cast<llvm::Instruction>(incoming_value);
				const llvm::BasicBlock *incoming_block = from_node->get_incoming_block(i);

				if (!incoming_inst || !incoming_block || (ignore_node && incoming_inst == ignore_node->ptr()) || !has_instruction_node(incoming_inst))
				{
					// 何らかのValueを直接参照する場合、このincomingは観測対象
					// incoming instがvalueでなくともグラフ内部で変化しない値は定数とみなして観測対象にする
					// incoming blockがない場合(select命令の結果)も観測対象
					// ignoreノードの値はinstructionではなく単なるvalueとみなす
					check_incoming[from_node].push_back(i);
					continue;
				}

				// to_node が実行されたことがわかると必ず i 番目の incoming が選択されたとわかる場合
				// この場合では i 番目の incoming の実行フラグは省略可能
				// 判定方法：(incmoing block, to_node) が full dominate かつ incoming block からは from_node へしか遷移しない
				bool is_watchable = false;
				if (llvm::succ_size(incoming_block) == 1)
					for (auto [to_node, to_edges] : *this)
						if (incoming_block == to_node->ptr()->getParent() || (DT.dominates(to_node->ptr(), incoming_block->getTerminator()) && PDT.dominates(incoming_block->getTerminator(), to_node->ptr())))
						{
							is_watchable = true;
							break;
						}

				if (!is_watchable)
					check_incoming[from_node].push_back(i);
			}
		}

		// グラフのrootノードで出力される値を絞り込める場合
		auto erase_pair = find_most_used_value(root_node, ignore_node, check_incoming);
		if (erase_pair.second.size() > 1)
		{
			// 対応するincomingについての観測をやめる
			for (auto [erase_node, erase_incoming] : erase_pair.second)
			{
				check_incoming[erase_node].remove(erase_incoming);
			}
			// nodeが実行されたかを観測に含める
			check_incoming[erase_pair.first].push_back(-1u);
		}

		// rootノードがターゲット分岐をdominateしていればrootノードに関する観測を減らせる
		// if (DT.dominates(root_node->ptr(), master) && !check_incoming[root_node].empty())
		//	check_incoming[root_node].erase(check_incoming[root_node].begin());
		for (auto &[node, incoming] : check_incoming)
			if (!incoming.empty() && DT.dominates(node->ptr(), master))
			{
				// 命令の実行フラグ観測(末尾要素)を優先して省略
				incoming.erase(--incoming.end());
			}

		for (auto [node, incomings] : check_incoming)
			for (unsigned i : incomings)
				filtered_node.insert({node->ptr(), i});

		return filtered_node;
	}

	// rootからtoまでのノードを抽出する
	// rootはtoをfull dominateしている
	graph_node_subgraph *graph_class::pullout(const graph_node *root, const graph_node *to)
	{
		graph_class *new_graph = new graph_class(root, depth);
		graph_node_subgraph *new_graph_node = new graph_node_subgraph(new_graph, to);

		// 元のグラフにsubgraphを挿入してtoからのエッジを再現
		graph_edge new_edge;
		new_edge.copy_from(this->at(to));
		this->insert(std::make_pair(new_graph_node, new_edge));

		std::set<const graph_node *> seek;
		std::stack<const graph_node *> stack;
		stack.push(root);
		seek.insert(root);
		while (!stack.empty())
		{
			const graph_node *node = stack.top();
			stack.pop();
			assert(node != to);
			auto base_edges_itr = this->find(node);
			// 元のグラフから新しいグラフにコピー
			graph_edge &edges = (*new_graph)[node];
			edges.copy_from(base_edges_itr->second);
			// 元のグラフから新しいグラフのノードを削除
			this->erase(base_edges_itr);
			// to以外の未知なノードへのエッジをstackに追加
			for (const graph_node *e : edges)
				if (e != to && seek.insert(e).second)
					stack.push(e);
		}

		// subgraphにtoノードを追加
		(*new_graph)[to].use_constant = true;
		// 元のグラフからtoノードを削除
		this->erase(to);

		if (root == this->root_node)
			// rootが元のグラフのroot_nodeならばroot_nodeを置き換え
			this->root_node = const_cast<graph_node_subgraph *>(new_graph_node);
		else
			// 元のグラフ上のrootへのエッジを置き換える
			for (auto &edges : *this)
				for (const graph_node *node : edges.second)
					if (node == root)
					{
						edges.second.erase(node);
						edges.second.insert(new_graph_node);
					}
					else if (new_graph->find(node) != new_graph->end())
					{
						dump();
						assert(new_graph->find(node) == new_graph->end() && "新しいグラフへのエッジ");
					}
		return new_graph_node;
	}

	// llvmのdominator treeでは同一BB内の命令はdominateでないと判定されるため独自の関数を定義

	// dominatedが実行されたならばdominatorが必ず実行されたか
	// 注：dominatorはdominatedの前に実行される
	bool graph_class::dominates(const graph_node *dominator, const graph_node *dominated) const
	{
		if (dominator == dominated)
			return false;
		assert(this->find(dominator) != this->end());
		assert(this->find(dominated) != this->end());
		std::stack<const graph_node *> stack;
		std::set<const graph_node *> seek;
		stack.push(dominated);
		seek.insert(dominated);
		while (!stack.empty())
		{
			const graph_node *node = stack.top();
			stack.pop();
			assert(this->find(node) != this->end());
			const graph_edge &edges = this->at(node);
			if (edges.empty() || edges.use_constant)
				return false;
			for (const graph_node *e : edges)
				if (e != dominator && seek.insert(e).second)
					stack.push(e);
		}
		return true;
	}

	// dominatedが実行されたならばdominatorが必ず実行されるか
	// 注：dominatorはdominatedの後に実行される
	bool graph_class::post_dominates(const graph_node *dominator, const graph_node *dominated) const
	{
		if (dominator == dominated)
			return false;
		if (dominator == this->root_node)
			return true;
		assert(this->find(dominator) != this->end());
		assert(this->find(dominated) != this->end());

		std::stack<const graph_node *> stack;
		std::set<const graph_node *> seek;
		stack.push(dominated);
		seek.insert(dominated);

		while (!stack.empty())
		{
			const graph_node *cur_node = stack.top();
			stack.pop();
			assert(this->find(cur_node) != this->end());
			if (cur_node == dominator)
				continue;
			bool no_from_edge = true;
			for (auto &[node, edge] : *this)
				if (edge.find(cur_node) != edge.end())
				{
					if (node == this->root_node)
						return false;
					if (seek.insert(node).second)
						stack.push(node);
					no_from_edge = false;
				}
			if (no_from_edge)
				return false;
		}
		return true;

		// dominatedノードにつながるノード一覧
		std::set<const graph_node *> edge_to_dominated;
		for (auto &edge : *this)
			for (const graph_node *node : edge.second)
				if (node == dominated)
				{
					edge_to_dominated.insert(edge.first);
					break;
				}

		while (!stack.empty())
		{
			const graph_node *node = stack.top();
			stack.pop();
			assert(this->find(node) != this->end());
			const graph_edge &edges = this->at(node);
			if (edges.empty() || edges.use_constant)
				continue;
			for (const graph_node *e : edges)
			{
				if (e == dominated)
				{
					edge_to_dominated.erase(node);
					if (edge_to_dominated.empty())
					{
						// fprintf(stderr, cGRN "%p post dominates %p\n" cRST, dominator->ptr(), dominated->ptr());
						return true;
					}
				}
				if (e != dominated && seek.insert(e).second)
					stack.push(e);
			}
		}
		return false;
	}

	// あるノードrootををfull dominateする最も浅いノードtoを深さ優先探索で見つけて(root, to)間のグラフをsubgraphとして一つのノードにまとめる
	const graph_node *graph_class::find_and_pullout_between_root_and_dominator(const graph_node *root, const graph_node *ignore_node)
	{
		std::set<const graph_node *> seek;
		std::stack<const graph_node *> stack;
		seek.insert(root);
		stack.push(root);

		while (!stack.empty())
		{
			const graph_node *phi = stack.top();
			stack.pop();
			assert(this->find(phi) != this->end() && "すでに分離されたノードへのエッジ");
			graph_edge &EdgesS = (*this)[phi];

			if (EdgesS.empty())
				continue;

			//	erase slash後にiteratorが保証されない問題の対策用
			std::vector<const graph_node *> Edges(EdgesS.begin(), EdgesS.end());

			for (unsigned i = 0; i < Edges.size(); i++)
			{
				const graph_node *prev_node = Edges[i];
				assert(this->find(prev_node) != this->end() && "存在しないノード");

				//	グラフ全体はsubgraph化しない
				// if (root == this->root_node && this->at(prev_node).empty())

				// 一度検討したノードは無視
				if (!seek.insert(prev_node).second)
					continue;

				// ノード一つだけならsubgraph化しない
				if (root == prev_node)
					continue;

				// 無視するノード
				if (prev_node == ignore_node)
					continue;

				if (this->dominates(prev_node, root) && this->post_dominates(root, prev_node))
				{
					// fprintf(stderr, cGRN "%p dominates %p\n" cRST, prev_node->ptr(), root->ptr());
					graph_node_subgraph *new_graph = this->pullout(root, prev_node);

					for (auto &[new_node, new_edge] : *this)
						for (auto new_edge_node : new_edge)
							assert(this->find(new_edge_node) != this->end() && "分離後のグラフへのエッジ");

					// 分解後のグラフも解析
					const_cast<graph_class *>(new_graph->subgraph)->format_graph(prev_node);

					// root-toが置き換わった新しいグラフをrootとして再試行
					return find_and_pullout_between_root_and_dominator(new_graph, ignore_node);
				}

				stack.push(prev_node);
			}
		}
		// ノードの置き換えがなかったらそのまま
		return root;
	}

	// グラフ中の単純化
	// 深さ優先探索でsubgraph化を検討する
	void graph_class::format_graph(const graph_node *ignore_node)
	{
		std::set<const graph_node *> seek;
		std::stack<const graph_node *> stack;
		seek.insert(this->root_node);
		stack.push(this->root_node);

		//	深さ優先探索で内部の支配関係を含めたグラフ分割
		while (!stack.empty())
		{
			const graph_node *root = stack.top();
			stack.pop();
			//	既に分離された場合はスルー
			if (this->find(root) == this->end())
				continue;
			// fprintf(stderr, cGRN "check dominate to %p\n" cRST, root->ptr());
			const graph_node *cur = find_and_pullout_between_root_and_dominator(root, ignore_node);
			for (auto p : (*this)[cur])
				if (seek.insert(p).second)
					stack.push(p);
		}
	}

};
