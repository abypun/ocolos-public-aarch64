#include "infrastructure.hpp"
#include "extract_machine_code.hpp"
#include "ptrace_pause.hpp"

using namespace std;

void remove_file(string path) {
    if (remove(path.c_str()) == -1 && errno != ENOENT) {
        exit(-1);
    }
}

void clean_old_temp_files(ocolos_env* ocolos_environ) {
    remove_file(ocolos_environ->bolted_function_bin);
    remove_file(ocolos_environ->v_table_bin);
    remove_file(ocolos_environ->call_sites_bin);
    remove_file(ocolos_environ->unmoved_func_bin);
}

// 外部输入：
// 1. BOLT优化版本的优化函数列表
// 2. 应用pid
// 3. 应用进程内insert_machine_code地址
// ./tracer --pid=12345 --libaddr=0x12345678 --boltinfo=/path/to/bolted_functions.txt
int main() {
    ocolos_env ocolos_environ;

    pid_t target_pid;
    void* lib_addr;
    FILE *f = fopen((ocolos_environ.tmp_data_path + "tracee.txt").c_str(), "r");
    if (f == NULL) {
        exit(-1);
    }
    fscanf(f, "%d %p", &target_pid, &lib_addr);
    fclose(f);

    unordered_map<long, func_info> bolted_func;
    f = fopen((ocolos_environ.tmp_data_path + "bolt.log").c_str(), "r");
    if (f == NULL) {
        exit(-1);
    }
    char tmp[3000];
    while (fgets(tmp, sizeof(tmp), f) != NULL) {
        string line(tmp);
        vector<string> words = split_line(line);
        if (words.size() > 5 && words[0] == "@@@@") {
            func_info new_func;
            new_func.func_name      = words[1];
            new_func.orig_addr_str  = words[2];
            new_func.moved_addr_str = words[3];
            new_func.original_addr  = convert_str_2_long(words[2]);
            new_func.moved_addr     = convert_str_2_long(words[3]);
            new_func.original_size  = convert_str_2_long(words[4]);
            new_func.moved_size     = convert_str_2_long(words[5]);
            bolted_func[new_func.original_addr] = new_func;
        }
    }
    fclose(f);

    unordered_map<long, func_info> func_with_addr = get_func_with_original_addr(&ocolos_environ);
    unordered_map<long, func_info> unmoved_func   = get_unmoved_func(func_with_addr, bolted_func);	
    map<long, func_info> func_heap                = change_func_to_heap(func_with_addr);
    unordered_map<string, string> v_table         = get_v_table(&ocolos_environ);
    vector<long> addr_bolted_func = get_moved_addr_to_array(bolted_func);

    clean_old_temp_files(&ocolos_environ);

    write_functions(ocolos_environ.bolted_binary_path.c_str(),
                    ocolos_environ.bolted_function_bin.c_str(),
                    addr_bolted_func.data(),
                    addr_bolted_func.size());
    write_vtable(ocolos_environ.bolted_binary_path.c_str(), ocolos_environ.v_table_bin.c_str());

#ifdef TIME_MEASUREMENT
    auto begin = std::chrono::high_resolution_clock::now();
#endif

    vector<pid_t> tids = pause_and_get_tids(target_pid);

    // unwind call stack and get the functions in the call stacks of each threads
    vector<unw_word_t> call_stack_ips = unwind_call_stack(tids);
    unordered_map<long, func_info> func_in_call_stack =  get_func_in_call_stack(call_stack_ips, func_heap);
    unordered_map<long, func_info> unmoved_func_not_in_call_stack = get_unmoved_func_not_in_call_stack(func_in_call_stack, unmoved_func);
    // for continuous optimization
    write_func_on_call_stack_into_file(&ocolos_environ, func_in_call_stack);  
    // extract the machine code of each function from the output of objdump
    vector<long> addr_unmoved_func_not_in_call_stack = get_keys_to_array(unmoved_func_not_in_call_stack);
    FILE *call_sites_bin = fopen(ocolos_environ.call_sites_bin.c_str(), "a");
    extract_call_sites(call_sites_bin, bolted_func, func_in_call_stack, &ocolos_environ);
    fclose(call_sites_bin);

    write_functions(ocolos_environ.bolted_binary_path.c_str(),
                    ocolos_environ.unmoved_func_bin.c_str(),
                    addr_unmoved_func_not_in_call_stack.data(),
                    addr_unmoved_func_not_in_call_stack.size());

    // change the IP of the target process to be the starting address of our library code 
    // then make the target process to execute the lib code to insert machine code
    struct user_regs_struct regs, old_regs;
#if defined Intel64
    struct user_fpregs_struct fregs;
    for (unsigned i = 0; i < tids.size(); i++) {
        if(!ptrace_single_step_intel64(tids[i], lib_addr, regs, old_regs, fregs)) {
            continue;
        }
        ptrace_cont_intel64(tids[i], regs, old_regs, fregs);
        break;
    }
#elif defined AArch64
    struct user_fpsimd_struct fregs;
    for (unsigned i = 0; i < tids.size(); i++){
        if (!ptrace_single_step_aarch64(tids[i], lib_addr, regs, old_regs, fregs)) {
            continue;
        }
        ptrace_cont_aarch64(tids[i], regs, old_regs, fregs);
        break;
    }
#endif

    for (unsigned i = 0; i < tids.size(); i++){
        ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
    }

#ifdef TIME_MEASUREMENT
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("[tracer][time] machine code insertion took %f seconds to execute \n", elapsed.count() * 1e-9);
#endif

#ifndef DEBUG_INFO
    clean_up(&ocolos_environ);
#endif

    printf("[tracer][OK] code replacement done!\n");

    // continuous optimization
    // the perf record will collect profile from the C1 round text section
    // the perf.data collected from C1 round together with 
    // (1) BOLTed binary produced from C0 roound + 
    // (2) callstack_func.bin (the function on the call stack when C0 round code replacement is performed) +
    // (3) the info of BOLTed binary (BOLTed text section's starting address)
    // will be sent to llvm-bolt to produce a C1 round BOLTed binary.
    // C1 round's BOLTed binary is used for C1 round's code replacement
#ifdef CONT_OPT
    run_perf_record(target_pid, &ocolos_environ);
#endif
}
