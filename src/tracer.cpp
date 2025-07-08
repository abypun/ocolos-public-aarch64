#include "extract_machine_code.hpp"
#include "extract_vtable.hpp"
#include "infrastructure.hpp"
#include "ptrace_pause.hpp"

typedef struct tracer_args {
    pid_t target_pid;
    void* lib_addr;
    std::string boltinfo_path;
    std::string cmd_path;
} tracer_args;
    
void parse_args(int argc, char* argv[], tracer_args &args) {
    args.target_pid = 0;
    args.lib_addr = 0;
    args.boltinfo_path = "";
    args.cmd_path = "";
    
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) {
            std::cerr << "[tracer] Invalid arguments" << std::endl;
            exit(-1);
        }
           
        std::string arg = argv[i];
        std::string value = argv[i + 1];
           
        if (arg == "--target-pid") {
            args.target_pid = stoi(value);
        } else if (arg == "--lib-addr") {
            args.lib_addr = (void*)stoull(value, nullptr, 16);
        } else if (arg == "--bolt-info") {
            args.boltinfo_path= value;
        } else {
            std::cerr << "[tracer] Unknown argument: " << arg << std::endl;
            exit(-1);
        }
    }

    if (args.target_pid == 0 || args.lib_addr == 0 || args.boltinfo_path.empty()) {
        std::cerr << "[tracer] Missing required arguments" << std::endl;
        exit(-1);
    }
}

// ./tracer --target-pid 12345 --lib-addr 0x1234 --bolt-info /path/to/bolt.txt
int main(int argc, char* argv[]) {
    ocolos_env ocolos_environ;
    tracer_args args;
    parse_args(argc, argv, args);

    // sample + perf2bolt + llvm-bolt
    std::unordered_map<long, func_info> bolted_func = run_llvmbolt(args.boltinfo_path);

    // get all functions that have location changed
    std::unordered_map<long, func_info> func_with_addr = get_func_with_original_addr(&ocolos_environ);
    std::unordered_map<long, func_info> unmoved_func = get_unmoved_func(func_with_addr, bolted_func);
    std::map<long, func_info> func_heap = change_func_to_heap(func_with_addr);
    std::unordered_map<std::string, std::string> v_table = get_v_table(&ocolos_environ);

    // delete the old binary files for code replacement
    // create the num files for code replecement before pausing
    // the target process
    std::string delete_all_bin = "rm -rf " + ocolos_environ.bolted_function_bin + " " + ocolos_environ.v_table_bin +
        " " + ocolos_environ.call_sites_bin + " " + ocolos_environ.unmoved_func_bin;
    if (system(delete_all_bin.c_str()) == -1)
        exit(-1);

    FILE *pFile1 = fopen(ocolos_environ.call_sites_bin.c_str(), "a");

    std::vector<long> addr_bolted_func = get_moved_addr_to_array(bolted_func);
    write_functions(ocolos_environ.bolted_binary_path.c_str(), ocolos_environ.bolted_function_bin.c_str(),
                    addr_bolted_func.data(), addr_bolted_func.size());

    process_vtables(ocolos_environ.bolted_binary_path.c_str(), std::to_string(args.target_pid),
                        ocolos_environ.v_table_bin.c_str());

    // <starting address, call_sites_info>
    std::unordered_map<long, call_site_info> call_sites;
    std::ifstream filestream(ocolos_environ.call_sites_all_bin);
    boost::archive::binary_iarchive archive(filestream);
    archive >> call_sites;

    // <target address, caller inst addresses>
    std::unordered_map<long, std::vector<long>> call_sites_list;
    std::ifstream filestream1(ocolos_environ.call_sites_list_bin);
    boost::archive::binary_iarchive archive1(filestream1);
    archive1 >> call_sites_list;

#ifdef TIME_MEASUREMENT
    auto begin = std::chrono::high_resolution_clock::now();
#endif

    // to pause all running threads of the target process
    // and then get the PIDs(tid) of these threads
    std::vector<pid_t> tids = pause_and_get_tids(args.target_pid);

    // unwind call stack and get the functions
    // in the call stacks of each threads
    std::vector<unw_word_t> call_stack_ips = unwind_call_stack(tids);
    std::unordered_map<long, func_info> func_in_call_stack = get_func_in_call_stack(call_stack_ips, func_heap);
    std::unordered_map<long, func_info> unmoved_func_not_in_call_stack =
        get_unmoved_func_not_in_call_stack(func_in_call_stack, unmoved_func);

    // for continuous optimization
    write_func_on_call_stack_into_file(&ocolos_environ, func_in_call_stack);

    // extract the machine code of each function
    // from the output of objdump
    std::vector<long> addr_unmoved_func_not_in_call_stack = get_keys_to_array(unmoved_func_not_in_call_stack);

    inlined_extract_call_sites(pFile1, bolted_func, func_in_call_stack, call_sites, call_sites_list,
                                   &ocolos_environ);

    write_functions(ocolos_environ.bolted_binary_path.c_str(), ocolos_environ.unmoved_func_bin.c_str(),
                    addr_unmoved_func_not_in_call_stack.data(), addr_unmoved_func_not_in_call_stack.size());

    fflush(pFile1);
    fclose(pFile1);

    // change the IP of the target process to be
    // the starting address of our library code
    // then make the target process to execute
    // the lib code to insert machine code
    struct user_regs_struct regs, old_regs;
#ifdef Intel64
    struct user_fpregs_struct fregs;
#endif
#ifdef AArch64
    struct user_fpsimd_struct fregs;
#endif
    std::vector<pid_t> tids_have_code_insertion;
#ifdef Intel64
    for (unsigned i = 0; i < tids.size(); i++) {
        if (!ptrace_single_step_intel64(tids[i], args.lib_addr, regs, old_regs, fregs)) {
            continue;
        }
        ptrace_cont_intel64(tids[i], regs, old_regs, fregs);
        break;
    }
#endif
#ifdef AArch64
    for (unsigned i = 0; i < tids.size(); i++) {
        if (!ptrace_single_step_aarch64(tids[i], args.lib_addr, regs, old_regs, fregs)) {
            continue;
        }
#ifndef DEBUG
        ptrace_cont_aarch64(tids[i], regs, old_regs, fregs);
#endif
        break;
    }
#endif

#ifdef DEBUG
    // deliver a SIGSTOP signal to target process.
    // before resume the target process, so that
    // we can attach GDB to target process later on.
    for (unsigned i = 0; i < tids.size(); i++) {
        int rc = syscall(SYS_tgkill, tids[0], tids[i], SIGSTOP);
    }
#endif

    // ptrace detach all threads of the target process
    for (unsigned i = 0; i < tids.size(); i++) {
        ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
    }

#ifndef DEBUG_INFO
    clean_up(&ocolos_environ);
#endif

#ifdef TIME_MEASUREMENT
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("[tracer][time] machine code insertion took %f seconds to execute \n", elapsed.count() * 1e-9);
#endif

    printf("[tracer][OK] code replacement done!\n");
#ifdef DEBUG
    while (true);
#endif

    // continuous optimization
    // the perf record will collect profile from the C1 round text section
    // the perf.data collected from C1 round together with
    // (1) BOLTed binary produced from C0 roound +
    // (2) callstack_func.bin (the function on the call stack when C0 round code replacement is performed) +
    // (3) the info of BOLTed binary (BOLTed text section's starting address)
    // will be sent to llvm-bolt to produce a C1 round BOLTed binary.
    // C1 round's BOLTed binary is used for C1 round's code replacement
#ifdef CONT_OPT
    run_perf_record(args.target_pid, &ocolos_environ);
#endif
}