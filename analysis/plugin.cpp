#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/Path.h>

#include <llvm/Transforms/Utils/PromoteMemToReg.h>
#include <llvm/Analysis/AssumptionCache.h>
#include <llvm/IR/Dominators.h>
#include <llvm/Analysis/TargetTransformInfo.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Verifier.h>
#include <llvm/ADT/Triple.h>

#include <llvm/Transforms/Utils.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
#include <llvm/Transforms/Scalar/Reg2Mem.h>

#include "util.h"
#include "analyzer.h"

#include <fstream>
#include <stack>
#include <unistd.h>
#include <algorithm>
#include <functional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <regex>

using namespace llvm;

namespace Instrumentation
{
#define AFL_LLVM_PASS
#include "../AFLplusplus/include/types.h"
#include "../AFLplusplus/include/config.h"

	llvm::AllocaInst *create_alloca(llvm::Function *F, llvm::Type *Ty)
	{
		llvm::BasicBlock::iterator IP = F->getEntryBlock().begin();
		while (llvm::isa<llvm::AllocaInst>(IP))
			IP++;
		llvm::IRBuilder<> IRB(&(*IP));
		llvm::LLVMContext &C = F->getContext();
		llvm::AllocaInst *alloca = IRB.CreateAlloca(Ty);
		alloca->setMetadata(F->getParent()->getMDKindID("nosanitize"), llvm::MDNode::get(C, llvm::None));
		llvm::StoreInst *store = IRB.CreateStore(llvm::ConstantInt::get(Ty, 0), alloca);
		store->setMetadata(F->getParent()->getMDKindID("nosanitize"), llvm::MDNode::get(C, llvm::None));
		return alloca;
	}

	uint32_t get_cur_afl_loc(llvm::BasicBlock *BB)
	{
		llvm::LoadInst *load_prev_loc_inst = NULL;
		// Search "load i32, ptr @__afl_prev_loc".
		for (auto I = BB->begin(); I != BB->end(); I++)
		{
			llvm::LoadInst *Load = llvm::dyn_cast<llvm::LoadInst>(I);
			if (!Load)
				continue;
			if (Load->getPointerOperand()->getName().equals("__afl_prev_loc"))
			{
				load_prev_loc_inst = Load;
				break;
			}
		}

		if (!load_prev_loc_inst)
			return -1u;

		// Search xor using @__afl_prev_loc
		for (auto I = BB->begin(); I != BB->end(); I++)
		{
			// Determine if the Opcode is and/or/xor.
			if (!I->isBitwiseLogicOp())
				continue;
			// Check if the instruction use @__afl_prev_loc.
			if (I->getOperand(0) != load_prev_loc_inst)
				continue;
			// Check if the operand is 32bit ConstantInt.
			llvm::ConstantInt *cur_loc = llvm::dyn_cast<llvm::ConstantInt>(I->getOperand(1));
			if (!cur_loc || cur_loc->getValue().getBitWidth() != 32)
				continue;
			return cur_loc->getValue().getZExtValue();
		}
		return -1u;
	}

	llvm::Value *getStoredValue(llvm::BasicBlock *BB, llvm::Value *StorePtr)
	{
		for (auto I = BB->begin(); I != BB->end(); I++)
		{
			llvm::StoreInst *Store = llvm::dyn_cast<llvm::StoreInst>(I);
			if (!Store)
				continue;
			if (Store->getPointerOperand() != StorePtr)
				continue;
			return Store->getValueOperand();
		}
		return NULL;
	}

	//	A function is invalid if its BasicBlock containing a branch instruction isn't instrumented for AFL coverage.
	void filter_not_afl_sanitize(std::map<llvm::Function *, std::list<dependent_analyzer::incoming_result>> &dependencies)
	{
		for (auto ditr = dependencies.begin(); ditr != dependencies.end();)
		{
			std::list<dependent_analyzer::incoming_result> &dependence = ditr->second;

			for (auto itr = dependence.begin(); itr != dependence.end();)
				if (get_cur_afl_loc(itr->terminator->getParent()) >= MAP_SIZE)
					itr = dependence.erase(itr);
				else
					itr++;
			if (ditr->second.empty())
				ditr = dependencies.erase(ditr);
			else
				ditr++;
		}
	}

	// Since select instructions with vector operations are not yet supported, filter them out.
	// TODO: Support vector operations
	void filter_vector_inst(std::map<llvm::Function *, std::list<dependent_analyzer::incoming_result>> &dependencies)
	{
		for (auto ditr = dependencies.begin(); ditr != dependencies.end();)
		{
			std::list<dependent_analyzer::incoming_result> &dependence = ditr->second;
			for (auto itr = dependence.begin(); itr != dependence.end();)
			{
				for (auto incoming = itr->incomings.begin(); incoming != itr->incomings.end();)
				{
					const llvm::SelectInst *select = llvm::dyn_cast<llvm::SelectInst>(incoming->I);
					if (select && llvm::VectorType::classof(select->getCondition()->getType()))
						incoming = itr->incomings.erase(incoming);
					else
						incoming++;
				}
				if (itr->incomings.empty())
					itr = dependence.erase(itr);
				else
					itr++;
			}
			if (ditr->second.empty())
				ditr = dependencies.erase(ditr);
			else
				ditr++;
		}
	}

	// Filter by the number of combinations.
	void filter_combi_size(std::map<llvm::Function *, std::list<dependent_analyzer::incoming_result>> &dependencies)
	{
		if (getenv("COMBI_FLAG_ONLY"))
			return;
		for (auto ditr = dependencies.begin(); ditr != dependencies.end();)
		{
			std::list<dependent_analyzer::incoming_result> &dependence = ditr->second;
			if (getenv("USE_ALL_DEPENDENCIES_WITH_SPLIT"))
				for (auto beg = dependence.begin(); beg != dependence.end();)
				{
					const unsigned size = beg->incomings.size();
					if (size <= 1)
					{
						beg = dependence.erase(beg);
						continue;
					}

					if (size > COMBI_LIMIT)
					{
						// Randomly select COMBI_LIMIT items.
						const unsigned n = size - COMBI_LIMIT == 1 ? COMBI_LIMIT / 2 : COMBI_LIMIT;
						std::set<dependent_analyzer::incoming_info> new_incomings;
						for (unsigned i = 0; i < n; i++)
						{
							auto target_itr = std::next(beg->incomings.begin(), AFL_R(beg->incomings.size()));
							new_incomings.insert(*target_itr);
							beg->incomings.erase(target_itr);
						}
						dependence.insert(beg, {beg->terminator, new_incomings});
					}
					else
						beg++;
				}
			else
				for (auto itr = dependence.begin(); itr != dependence.end();)
				{
					const unsigned size = itr->incomings.size();
					if (size <= 0)
					{
						itr = dependence.erase(itr);
						continue;
					}

					// Remove elements until the condition is met.
					while (itr->incomings.size() > COMBI_LIMIT)
						itr->incomings.erase(--itr->incomings.end());
					itr++;
				}
			if (ditr->second.empty())
				ditr = dependencies.erase(ditr);
			else
				ditr++;
		}
	}

	void filter_all(std::map<llvm::Function *, std::list<dependent_analyzer::incoming_result>> &dependencies)
	{
		filter_not_afl_sanitize(dependencies);
		filter_vector_inst(dependencies);
		filter_combi_size(dependencies);
	}

	// Create a list of observed values for each function.
	std::set<dependent_analyzer::incoming_info> collect_depend_basic_blocks(std::list<dependent_analyzer::incoming_result> &dependencies)
	{
		std::set<dependent_analyzer::incoming_info> incoming_set;
		for (dependent_analyzer::incoming_result &r : dependencies)
		{
			auto pos = incoming_set.begin();
			for (auto it = r.incomings.begin(); it != r.incomings.end(); it++)
			{
				pos = incoming_set.emplace_hint(pos, *it);
				pos++;
			}
		}
		return incoming_set;
	}

	struct EmbedPair
	{
		llvm::Value *value;
		unsigned id;
	};

	std::map<dependent_analyzer::incoming_info, EmbedPair> embed_basic_block_flags(llvm::Module &M, std::set<dependent_analyzer::incoming_info> &incomings)
	{
		llvm::LLVMContext &C = M.getContext();
		std::map<dependent_analyzer::incoming_info, EmbedPair> Flags;
		llvm::ConstantInt *zero = llvm::ConstantInt::get(llvm::Type::getInt32Ty(C), 0);

		for (const dependent_analyzer::incoming_info &i : incomings)
		{
			llvm::BasicBlock *BB = const_cast<llvm::BasicBlock *>(i.I->getParent());
			llvm::Function *F = BB->getParent();
			llvm::AllocaInst *alloca = create_alloca(F, llvm::Type::getInt32Ty(C));

			llvm::BasicBlock::iterator IP(const_cast<llvm::Instruction *>(i.I));
			llvm::IRBuilder<> IRB(&(*++IP));
			unsigned iid = AFL_R(MAP_SIZE);
			llvm::ConstantInt *id = llvm::ConstantInt::get(IRB.getInt32Ty(), iid);

			if (i.incoming_id == -1u)
			{
				// TODO: This flag remains set if the branch executes more than once during a single function call.
				// Should we pick the condition of any branch instruction that may lead to i.I?
				IRB.SetInsertPoint(const_cast<llvm::Instruction *>(i.I->getParent()->getFirstNonPHI()));
				IRB.CreateAlignedStore(id, alloca, llvm::MaybeAlign(4))
					->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
			}
			else if (const llvm::PHINode *phi = llvm::dyn_cast<llvm::PHINode>(i.I))
			{
				unsigned n_incoming = phi->getNumIncomingValues();
				llvm::BasicBlock *lookat = phi->getIncomingBlock(i.incoming_id);
				llvm::PHINode *val = IRB.CreatePHI(llvm::Type::getInt32Ty(C), 0);
				for (unsigned j = 0; j < n_incoming; j++)
					val->addIncoming(phi->getIncomingBlock(j) == lookat ? id : zero, phi->getIncomingBlock(j));

				// insert not phinode after phinode
				IRB.SetInsertPoint(val->getParent()->getFirstNonPHI());
				IRB.CreateAlignedStore(val, alloca, llvm::MaybeAlign(4))
					->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
			}
			else if (const llvm::SelectInst *select = llvm::dyn_cast<llvm::SelectInst>(i.I))
			{
				llvm::Value *val = IRB.CreateSelect(const_cast<llvm::Value *>(select->getCondition()), i.incoming_id ? id : zero, i.incoming_id ? zero : id);
				IRB.CreateAlignedStore(val, alloca, llvm::MaybeAlign(4))
					->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
			}
			else
				assert(false);

			Flags[i] = {alloca, iid};
		}
		return Flags;
	}

	std::map<llvm::Instruction *, unsigned> embed_original_coverage(llvm::Module &M, std::list<dependent_analyzer::incoming_result> &Dependencies, std::map<dependent_analyzer::incoming_info, EmbedPair> &Flags)
	{
		if (getenv("COMBI_FLAG_ONLY"))
			return {};
		llvm::LLVMContext &C = M.getContext();
		llvm::IntegerType *Int8Ty = llvm::IntegerType::getInt8Ty(C);

		llvm::ConstantInt *One = llvm::ConstantInt::get(Int8Ty, 1);

		llvm::GlobalVariable *AFLMapPtr = M.getGlobalVariable("__afl_area_ptr");
		if (!AFLMapPtr)
			AFLMapPtr = new llvm::GlobalVariable(M, llvm::PointerType::get(llvm::IntegerType::getInt8Ty(M.getContext()), 0), false,
												 llvm::GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
		std::map<llvm::Instruction *, unsigned> Idxs;
		for (dependent_analyzer::incoming_result &D : Dependencies)
		{
			llvm::Instruction *branch = D.terminator;
			llvm::IRBuilder<> IRB(branch->getParent()->getTerminator());
			const uint32_t Idx = AFL_R(MAP_SIZE);
			Idxs[D.terminator] = Idx;
			llvm::Value *Cov = IRB.CreateAdd(llvm::ConstantInt::get(IRB.getInt32Ty(), Idx), llvm::ConstantInt::get(IRB.getInt32Ty(), 0));

			assert(!D.incomings.empty() && "empty incoming");
			for (const dependent_analyzer::incoming_info &info : D.incomings)
			{
				llvm::LoadInst *Flag = IRB.CreateLoad(IRB.getInt32Ty(), Flags[info].value);
				Flag->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
				Cov = IRB.CreateXor(Cov, Flag);
			}

			llvm::LoadInst *MapPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
				llvm::PointerType::get(Int8Ty, 0),
#endif
				AFLMapPtr);
			MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
			llvm::Value *MapPtrIdx = IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
				Int8Ty,
#endif
				MapPtr, Cov);
			llvm::LoadInst *Counter = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
				IRB.getInt8Ty(),
#endif
				MapPtrIdx);
			Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

			Value *Incr = IRB.CreateAdd(Counter, One);
			IRB.CreateStore(Incr, MapPtrIdx)
				->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
		}
		return Idxs;
	}

	void write_embed_coverage_into_file(std::list<dependent_analyzer::incoming_result> &Dependencies, std::map<dependent_analyzer::incoming_info, EmbedPair> &IdFlags, std::map<llvm::Instruction *, unsigned> &Idx, FILE *File)
	{
		if (getenv("COMBI_FLAG_ONLY"))
		{
			for (dependent_analyzer::incoming_result &D : Dependencies)
				fprintf(File, "%zu\n", D.incomings.size());
		}
		else if (!getenv("NO_EMBED_FILE"))
		{
			for (dependent_analyzer::incoming_result &D : Dependencies)
			{
				if (D.terminator->getParent()->getTerminator() != D.terminator)
					continue;
				const uint32_t PrevLoc = get_cur_afl_loc(D.terminator->getParent());
				fprintf(File, "%u", D.terminator->getNumSuccessors());
				for (auto BB : llvm::successors(D.terminator))
				{
					const uint32_t CurLoc = get_cur_afl_loc(BB);
					const uint32_t EdgeIndex = (PrevLoc >> 1) ^ CurLoc;
					fprintf(File, " %u", EdgeIndex);
				}

				const uint32_t Base = Idx[D.terminator];
				std::vector<uint32_t> Flags;
				for (const dependent_analyzer::incoming_info &info : D.incomings)
					Flags.push_back(IdFlags[info].id);

				fprintf(File, " %zu", Flags.size());

				const uint64_t NumPattern = 1ull << Flags.size();
				for (uint64_t i = 0; i < NumPattern; i++)
				{
					uint32_t original_idx = Base;
					for (uint32_t j = 0; j < Flags.size(); j++)
					{
						if ((i & (1u << j)) > 0)
							original_idx ^= Flags[j];
					}
					fprintf(File, " %u", original_idx);
				}
				fprintf(File, "\n");
			}
		}
	}

	void alloca_and_embed(llvm::Module &M, std::map<llvm::Function *, std::list<dependent_analyzer::incoming_result>> &dependencies)
	{
		llvm::LLVMContext &C = M.getContext();

		if (dependencies.empty())
		{
			fprintf(stderr, "No Dependency in %s.\n", M.getName().data());
			return;
		}

		// Get embdedd info output path
		std::string EmbedInfoPath = getenv("EMBED_INFO_BASE");
		if (EmbedInfoPath.back() != '/')
			EmbedInfoPath.push_back('/');
		EmbedInfoPath.append(std::regex_replace(M.getName().str(), std::regex("/"), "{}"));
		EmbedInfoPath.append(std::to_string(AFL_R(10000000)));
		EmbedInfoPath.append(".embed");
		// Open file with overwrite mode
		FILE *File = fopen(EmbedInfoPath.c_str(), "w");
		assert(File && "Embed info path is invalid.");

		for (auto &[F, Dep] : dependencies)
		{
			std::set<dependent_analyzer::incoming_info> EmbedList = collect_depend_basic_blocks(Dep);
			if (EmbedList.empty())
				continue;
			std::map<dependent_analyzer::incoming_info, EmbedPair> Flags = embed_basic_block_flags(M, EmbedList);
			std::map<llvm::Instruction *, unsigned int> Idxs = embed_original_coverage(M, Dep, Flags);
			write_embed_coverage_into_file(Dep, Flags, Idxs, File);
		}

		fclose(File);
		std::string str = "!!__embed_path=" + EmbedInfoPath;
		llvm::Constant *FileNameInitializer = llvm::ConstantDataArray::getString(C, str, true);
		llvm::GlobalVariable *FileNameArray = new llvm::GlobalVariable(M, FileNameInitializer->getType(), true, llvm::GlobalValue::WeakAnyLinkage,
																	   FileNameInitializer, "!test-string!", nullptr);
		FileNameArray->setAlignment(llvm::Align(1));
	}
}

namespace
{
	struct CombinationAnalysis : llvm::PassInfoMixin<CombinationAnalysis>
	{
		std::list<dependent_analyzer::incoming_result> analyze_function(llvm::Function &F, std::ostream &debug);
		llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &AM);
	};

	struct SamplePass : llvm::PassInfoMixin<SamplePass>
	{
		llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &AM);
	};
}

llvm::PreservedAnalyses SamplePass::run(llvm::Function &F, llvm::FunctionAnalysisManager &AM)
{
	fprintf(stderr, cYEL "sample pass is running on %s" cRST "\n", F.getName().data());
	return llvm::PreservedAnalyses::all();
}

llvm::PreservedAnalyses CombinationAnalysis::run(llvm::Module &M,
												 llvm::ModuleAnalysisManager &AM)
{
	std::ofstream ofs;

#if DEBUG_PRINT == 1
	if (!M.debug_compile_units().empty())
	{
		char cwd[255];
		getcwd(cwd, 255);
		std::string path = M.getName().str() + ".dbg";
		ofs.open(path, std::ios_base::out);
		fprintf(stderr, cYEL "write debug info: " cRST "%s\n", path.c_str());
	}
#endif
	bool Changed = false;
	std::map<llvm::Function *, std::list<dependent_analyzer::incoming_result>> dependencies;
	for (llvm::Function &F : M)
	{
#if WITHOUT_FUZZER != 1
		if (F.hasFnAttribute(llvm::Attribute::OptForFuzzing))
#endif
		{
			std::list<dependent_analyzer::incoming_result> result = analyze_function(F, ofs);
			if (!result.empty())
			{
				dependencies[&F] = result;
			}
		}
	}

	Instrumentation::filter_all(dependencies);
	fprintf(stderr, "Module %s is filtered.\n", M.getName().data());
	fprintf(stderr, cCYA "instrumentation " cRST "for %s\n", M.getName().data());
	Instrumentation::alloca_and_embed(M, dependencies);
	Changed = !dependencies.empty();

#if VERIFY_MODULE == 1
	std::string str;
	llvm::raw_string_ostream os(str);
	if (llvm::verifyModule(M, &os))
	{
		fprintf(stderr, cRED "verify module error on %s\n" cYEL "%s\n\n" cRST, M.getName().data(), str.c_str());
		std::string ModuleStr;
		llvm::raw_string_ostream OS(ModuleStr);
		M.print(OS, NULL);
		std::ofstream ofs2("/bug-ir.dbg", std::ios_base::out);
		ofs2.write(ModuleStr.c_str(), ModuleStr.size());
		ofs2.close();
		fprintf(stderr, cCYA "write to /bug-ir.dbg" cRST);
	}
#endif

	ofs.close();

	return Changed ? llvm::PreservedAnalyses::none() : llvm::PreservedAnalyses::all();
}

std::list<dependent_analyzer::incoming_result> CombinationAnalysis::analyze_function(llvm::Function &F, std::ostream &debug)
{
	//	Empty functions cause a segmentation fault in DominatorTree analysis.
	if (F.empty() || F.size() <= 1)
		return {};

	std::list<dependent_analyzer::incoming_result> result = dependent_analyzer::runOnFunction(F);
	return result;
}

#if LLVM_VERSION_MAJOR <= 13
using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
	return {LLVM_PLUGIN_API_VERSION, "COMBINATION", "0.0.1",
			[](PassBuilder &PB)
			{
#if PASS_REGISTER_EARLY != 0
				PB.registerOptimizerEarlyEPCallback(
#else
				PB.registerOptimizerLastEPCallback(
#endif
					[&](ModulePassManager &MPM, OptimizationLevel opt)
					{
						// mem to reg before analysis
						// not working when opt is -O0
						llvm::FunctionPassManager mem2reg;
						mem2reg.addPass(llvm::PromotePass());
#ifdef CHECK_MEM2REG_RUNNING
						mem2reg.addPass(SamplePass());
#endif
						MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(mem2reg)));

						// original pass
						MPM.addPass(CombinationAnalysis());

#if REG2MEM != 0
						// reg to mem after analysis
						// not working when opt is -O0
						llvm::FunctionPassManager reg2mem;
						reg2mem.addPass(llvm::RegToMemPass());
						MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(reg2mem)));
#endif
					});
			}};
}
