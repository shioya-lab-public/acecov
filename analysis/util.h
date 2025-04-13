#pragma once
#include <stdio.h>
#include <map>

#include <llvm/IR/Value.h>
#include <llvm/Support/raw_os_ostream.h>

#define cBLK "\x1b[0;30m"
#define cRED "\x1b[0;31m"
#define cGRN "\x1b[0;32m"
#define cBRN "\x1b[0;33m"
#define cBLU "\x1b[0;34m"
#define cMGN "\x1b[0;35m"
#define cCYA "\x1b[0;36m"
#define cLGR "\x1b[0;37m"
#define cGRA "\x1b[1;90m"
#define cLRD "\x1b[1;91m"
#define cLGN "\x1b[1;92m"
#define cYEL "\x1b[1;93m"
#define cLBL "\x1b[1;94m"
#define cPIN "\x1b[1;95m"
#define cLCY "\x1b[1;96m"
#define cBRI "\x1b[1;97m"
#define cRST "\x1b[0m"

#define PRINT(Fmt) Printf(Fmt);

#if (DEBUG_LEVEL > 0)
#define PUT_L1(Fmt) Printf(Fmt);
#define PRINT_L1(Fmt, ...) Printf(Fmt, __VA_ARGS__);
#else
#define PUT_L1(Fmt)
#define PRINT_L1(Fmt, ...)
#endif

#if (DEBUG_LEVEL > 1)
#define PUT_L2(Fmt) Printf(Fmt);
#define PRINT_L2(Fmt, ...) Printf(Fmt, __VA_ARGS__);
#else
#define PUT_L2(Fmt)
#define PRINT_L2(Fmt, ...)
#endif

#if (DEBUG_LEVEL > 2)
#define PUT_L3(Fmt) Printf(Fmt);
#define PRINT_L3(Fmt, ...) Printf(Fmt, __VA_ARGS__);
#else
#define PUT_L3(Fmt)
#define PRINT_L3(Fmt, ...)
#endif

#if (DEBUG_LEVEL > 3)
#define PUT_L4(Fmt) Printf(Fmt);
#define PRINT_L4(Fmt, ...) Printf(Fmt, __VA_ARGS__);
#else
#define PUT_L4(Fmt)
#define PRINT_L4(Fmt, ...)
#endif

namespace
{
	inline void print_ntab(const unsigned n)
	{
		for (unsigned i = 0; i < n; i++)
			fprintf(stderr, "\t");
	}

	inline void Printf(const char *Fmt, ...)
	{
#if (DEBUG_LEVEL > 0)
		va_list ap;
		va_start(ap, Fmt);
		vfprintf(stderr, Fmt, ap);
		va_end(ap);
		fflush(stderr);
#endif
	}

	template <typename S, typename T>
	inline T getMapElementOrDefault(const std::map<S, T> &M, const S &Index, const T &Default)
	{
		auto elem = M.find(Index);
		if (elem == M.end())
			return Default;
		return elem->second;
	}

	template <typename S, typename T>
	inline bool contains(const std::map<S, T> &M, const S &Index) { return M.find(Index) != M.end(); }

	inline std::string getValueOperand(const llvm::Value *value)
	{
		std::string BBName;
		llvm::raw_string_ostream OS(BBName);
		value->printAsOperand(OS, false);
		return OS.str();
	}

	inline std::string getValueDump(const llvm::Value *value)
	{
		std::string BBName;
		llvm::raw_string_ostream OS(BBName);
		value->print(OS, false);
		return OS.str();
	}

	inline std::string getNameOrAsOperand(const llvm::Value *value)
	{
		if (!value)
			return "%NULL";
		if (value->hasName() && !value->getName().empty())
			return value->getName().str();
		return "%" + std::to_string(value->getValueID());
	}
}
