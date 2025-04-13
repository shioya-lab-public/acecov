include .env

CXXFLAGS    ?= -O3 -funroll-loops
CXXFLAGS    += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
               -Wno-variadic-macros

CLANG_CFL    = `$(LLVM_CONFIG) --cxxflags`
CLANG_LFL    = `$(LLVM_CONFIG) --ldflags`

plugin.so: plugin.o ir-parser.o graph-analyzer.o analyzer.o
	$(CXX) -shared $(CLANG_CFL) -std=c++17 plugin.o ir-parser.o graph-analyzer.o analyzer.o -o plugin.so
plugin.o: plugin.cpp
	$(CXX) -c $(CLANG_CFL) -std=c++17 -fPIC -DDEBUG_LEVEL=${DEBUG_LEVEL} -DNO_DA -DDEBUG_PRINT=${DEBUG_PRINT} \
		-DPRINT_THROUGH_COMBI=${PRINT_THROUGH_COMBI} -DWITHOUT_FUZZER=${WITHOUT_FUZZER} -DCOMBI_LIMIT=${COMBI_LIMIT} \
		-DVERIFY_MODULE=${VERIFY_MODULE} -DPASS_REGISTER_EARLY=${PASS_REGISTER_EARLY} -DREG2MEM=${REG2MEM} pluginv2.cpp -o plugin.o
graph-analyzer.o: graph-analyzer.cpp
	$(CXX) -c $(CLANG_CFL) -std=c++17 $(CLANG_LFL) -fPIC -DDEBUG_LEVEL=${DEBUG_LEVEL} -DNO_DA -DMAX_DEPTH=${MAX_DEPTH} graph-analyzer.cpp
ir-parser.o: ir-parser.cpp
	$(CXX) -c $(CLANG_CFL) -std=c++17 $(CLANG_LFL) -fPIC -DDEBUG_LEVEL=${DEBUG_LEVEL} -DNO_DA -DMAX_DEPTH=${MAX_DEPTH} -DNOT_FOLLOW_CALL=${NOT_FOLLOW_CALL} ir-parser.cpp
analyzer.o: analyzer.cpp
	$(CXX) -c $(CLANG_CFL) -std=c++17 $(CLANG_LFL) -fPIC -DDEBUG_LEVEL=${DEBUG_LEVEL} -DNO_DA -DMAX_DEPTH=${MAX_DEPTH} analyzer.cpp
clean:
	rm plugin.so *.o
