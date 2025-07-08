CC=gcc
CPP=g++
CPPFLAGS=-g -Wall -O3 -DAArch64 # -DIntel64 -DTIME_MEASUREMENT -DDEBUG_INFO
LINKER_FLAGS=-lpthread -ldl
LIBUNWIND_FLAGS=-lunwind -lunwind-ptrace -lunwind-generic
BOOST_FLAGS=-lboost_serialization
SRC_DIR=src

all: replace_function.so tracer extract_call_sites 
	rm -rf *.o $(SRC_DIR)/*.gch elf-extract/Cargo.lock

replace_function.so: $(SRC_DIR)/replace_function.hpp $(SRC_DIR)/replace_function.cpp	
	$(CPP) $(CPPFLAGS) $^ -o $@ -fPIC -shared -ldl

tracer: $(SRC_DIR)/tracer.cpp utils.o infrastructure.o ptrace_pause.o extract_vtable.o elf-extract/target/release/libelf_extract.a
	$(CPP) $(CPPFLAGS) $^ -o $@ $(LINKER_FLAGS) $(LIBUNWIND_FLAGS) $(BOOST_FLAGS) -lelf
infrastructure.o: $(SRC_DIR)/infrastructure.hpp $(SRC_DIR)/infrastructure.cpp $(SRC_DIR)/utils.hpp
	$(CPP) $(CPPFLAGS) $^ -c $(LINKER_FLAGS) 
utils.o: $(SRC_DIR)/utils.hpp $(SRC_DIR)/utils.cpp
	$(CPP) $(CPPFLAGS) $^ -c $(LINKER_FLAGS) 
ptrace_pause.o: $(SRC_DIR)/ptrace_pause.hpp $(SRC_DIR)/ptrace_pause.cpp $(SRC_DIR)/utils.hpp
	$(CPP) $(CPPFLAGS) $^ -c $(LINKER_FLAGS) 
elf-extract/target/release/libelf_extract.a:
	cd elf-extract/ && cargo build --release
extract_vtable.o: $(SRC_DIR)/extract_vtable.cpp $(SRC_DIR)/extract_vtable.hpp
	$(CPP) -g -Wall -c $< -o $@ -lelf -pthread

extract_call_sites: $(SRC_DIR)/utils.hpp $(SRC_DIR)/utils.cpp $(SRC_DIR)/extract_call_sites.cpp 
	$(CPP) $(CPPFLAGS) $(BOOST_FLAGS) -pthread $(SRC_DIR)/extract_call_sites.cpp $(SRC_DIR)/utils.cpp -o $@ 

clean:
	rm -rf $(SRC_DIR)/*.gch *.so *.bolt *.fdata *.data tracer *.data.old *.txt *.o	extract_call_sites 
