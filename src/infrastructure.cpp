#include "infrastructure.hpp"

std::unordered_map<long, func_info> run_llvmbolt(std::string bolt_info_path) {
#ifdef TIME_MEASUREMENT
    auto begin = std::chrono::high_resolution_clock::now();
#endif

    FILE *fp = fopen(bolt_info_path.c_str(), "r");
    if (fp == NULL) {
        printf("Failed to open llvm-bolt log\n" );
        exit(-1);
    }
    // collect the bolted function name from BOLT's output
    char path[3000];
    std::unordered_map<long, func_info> changed_functions;
    while (fgets(path, sizeof(path), fp) != NULL) {
        std::string line(path);
        std::vector<std::string> words = split_line(line);
        if (words.size() <= 1 || words[0] != "@@@@") {
            continue;
        }
        func_info new_func;
        new_func.func_name = words[1];
        new_func.orig_addr_str = words[2];
        new_func.moved_addr_str = words[3];
        new_func.original_addr = convert_str_2_long(words[2]);
        new_func.moved_addr = convert_str_2_long(words[3]);
        new_func.original_size = convert_str_2_long(words[4]);
        new_func.moved_size = convert_str_2_long(words[5]);
        changed_functions[convert_str_2_long(words[2])] = new_func;
    }

    printf("[tracer] %ld functions was moved (functions reordered) by BOLT\n", changed_functions.size());
    fclose(fp);

#ifdef TIME_MEASUREMENT
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    printf("[tracer(time)] llvm-bolt took %f seconds to execute \n", elapsed.count() * 1e-9);
#endif

    return changed_functions;
}

std::unordered_map<long, func_info> get_func_with_original_addr(const ocolos_env *ocolos_environ) {
    FILE *fp;
    char path[3000];
    std::string command = "" + ocolos_environ->nm_path + " -S -n " + ocolos_environ->target_binary_path;
    char *command_cstr = new char[command.length() + 1];
    strcpy(command_cstr, command.c_str());
    fp = popen(command_cstr, "r");
    free(command_cstr);

    if (fp == NULL) {
        printf("Failed to run nm on original binary\n");
        exit(-1);
    }

    std::vector<std::string> lines;
    while (fgets(path, sizeof(path), fp) != NULL) {
        std::string line(path);
        lines.push_back(line);
    }

    std::unordered_map<long, func_info> func_with_addr;
    for (unsigned i = 0; i < lines.size(); i++) {
        std::string line = lines[i];
        std::vector<std::string> words = split_line(line);
        if (words.size() <= 3) continue;
        if ((words[2] != "T") && (words[2] != "t")) continue;
        
        long addr = convert_str_2_long(words[0]);
        if (func_with_addr.find(addr) == func_with_addr.end()) {
            func_info new_func;
            new_func.original_addr = addr;
            new_func.original_size = convert_str_2_long(words[1]);
            new_func.orig_addr_str = words[0];
            func_with_addr[addr] = new_func;
        }
    }
#ifdef MEASUREMENT
    printf("[tracer] %ld functions are in the target process \n", func_with_addr.size());
#endif
    fclose(fp);
    return func_with_addr;
}

std::unordered_map<long, func_info> get_unmoved_func(
    std::unordered_map<long, func_info> func_with_addr,
    std::unordered_map<long, func_info> bolted_func) {
    std::unordered_map<long, func_info> unmoved_func;
    for (auto it = func_with_addr.begin(); it != func_with_addr.end(); it++) {
        if (bolted_func.find(it->first) == bolted_func.end()) {
            unmoved_func[it->first] = it->second;
        }
    }
#ifdef MEASUREMENT
    printf("[tracer(measure)] the size of unmoved_func is: %lu\n", unmoved_func.size());
    printf("[tracer(measure)] the size of orig_func is: %lu\n", func_with_addr.size());
#endif
    return unmoved_func;
}

std::map<long, func_info> change_func_to_heap(std::unordered_map<long, func_info> func) {
    std::map<long, func_info> func_heap;
    for (auto it = func.begin(); it != func.end(); it++) {
        func_heap[it->first] = it->second;
    }
    return func_heap;
}

std::unordered_map<std::string, std::string> get_v_table(const ocolos_env *ocolos_environ) {
    FILE *fp3;
    char path3[3000];
    std::string command = "" + ocolos_environ->nm_path + " -n -C " + ocolos_environ->bolted_binary_path;
    char *command_cstr = new char[command.length() + 1];
    strcpy(command_cstr, command.c_str());
    fp3 = popen(command_cstr, "r");
    free(command_cstr);
    if (fp3 == NULL) {
        printf("[tracer] Failed to run nm on BOLTed binary\n");
        exit(-1);
    }

    std::unordered_map<std::string, std::string> v_table;
    std::vector<std::string> lines;
    while (fgets(path3, sizeof(path3), fp3) != NULL) {
        std::string line(path3);
        lines.push_back(line);
    }
    for (unsigned i = 0; i < lines.size(); i++) {
        std::string line = lines[i];
        std::vector<std::string> words = split_line(line);
        if ((words.size() > 3 && words[2] == "vtable") ||
            (words.size() > 4 && words[2] == "construction" && words[3] == "vtable")) {
            std::string next_line = lines[i + 1];
            std::vector<std::string> next_line_words = split_line(next_line);
            v_table.insert(make_pair(words[0], next_line_words[0]));
        }
    }
    fclose(fp3);

    return v_table;
}

std::unordered_map<long, func_info> get_func_in_call_stack(
    std::vector<unw_word_t> call_stack_ips,
    std::map<long, func_info> unmoved_func_heap) {
    std::unordered_map<long, func_info> func_in_call_stack;

    for (unsigned i = 0; i < call_stack_ips.size(); i++) {
        auto it_low = unmoved_func_heap.lower_bound(call_stack_ips[i]);
        if (it_low != unmoved_func_heap.end()) {
            auto it = std::prev(it_low);
            if (it != unmoved_func_heap.end()) {
                func_in_call_stack[it->first] = it->second;
            }
        }
    }
#ifdef MEASUREMENT
    printf("[tracer] number of function in call stack: %u\n", func_in_call_stack.size());
#endif
    return func_in_call_stack;
}

void write_func_on_call_stack_into_file(
    const ocolos_env *ocolos_environment,
    std::unordered_map<long, func_info> func_in_call_stack) {
    std::string snapshot_path = ocolos_environment->tmp_data_path + "callstack_func.bin";
    FILE *fp = fopen(snapshot_path.c_str(), "w");

    long callstack_func_number = func_in_call_stack.size();
    fwrite(&callstack_func_number, sizeof(long), 1, fp);

    uint64_t buffer[func_in_call_stack.size()];
    int i = 0;
    for (auto it = func_in_call_stack.begin(); it != func_in_call_stack.end(); it++) {
        buffer[i] = (uint64_t) it->first;
        i++;
    }
    fwrite(buffer, sizeof(uint64_t), callstack_func_number, fp);

    fflush(fp);
    fclose(fp);
}

std::unordered_map<long, func_info> get_unmoved_func_not_in_call_stack(
    std::unordered_map<long, func_info> func_in_call_stack,
    std::unordered_map<long, func_info> unmoved_func) {
    std::unordered_map<long, func_info> unmoved_func_not_in_call_stack;
    for (auto it = unmoved_func.begin(); it != unmoved_func.end(); it++) {
        if (func_in_call_stack.find(it->first) == func_in_call_stack.end()) {
            unmoved_func_not_in_call_stack[it->first] = it->second;
        }
    }
    return unmoved_func_not_in_call_stack;
}
