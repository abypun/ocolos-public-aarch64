#include "utils.hpp"

/*
 * Create a new process that runs BOLT's llvm-bolt.
 * Llvm-bolt will create a BOLTed binary by taking the
 * perf2bolt's output and original server binary.
 */
std::unordered_map<long, func_info> run_llvmbolt(std::string bolt_info_path);

/*
 * Read the output from `nm` to get the starting address,
 * original functions size, function name etc. from `nm`'s
 * output.
 * The output's key is the starting address of the function.
 */
std::unordered_map<long, func_info> get_func_with_original_addr(const ocolos_env *);

/*
 * Get the functions that are not moved by BOLT by checking
 * and comparing both the original binary and the BOLTed
 * binary.
 */
std::unordered_map<long, func_info> get_unmoved_func(
    std::unordered_map<long, func_info> func_with_addr,
    std::unordered_map<long, func_info> bolted_func);

/*
 * Change unordered_map format of the functions info into
 * map format, since map in C++ is heap and provides a better
 * way for checking the bound of a function.
 */
std::map<long, func_info> change_func_to_heap(
    std::unordered_map<long, func_info> unmoved_func);

/*
 * Get vtable from nm's output. The first value (key) stores
 * the starting address of a v-table entry, and the second
 * value (value) stores the ending address of a v-table entry.
 */
std::unordered_map<std::string, std::string> get_v_table(const ocolos_env *);

/*
 * Get the detailed function info based on the ip of the functions
 * on call stack (this is actually the ip of the caller functions's
 * call instruction), and the heap which contains all functions'
 * information.
 * The return value is a list of the caller functions' info.
 * (These caller functions should also be on the call stack.)
 */
std::unordered_map<long, func_info> get_func_in_call_stack(
    std::vector<unw_word_t> call_stack_ips,
    std::map<long, func_info> unmoved_func_heap);

/*
 * Store the starting address of functions that are on the call stack
 * into a binary file.
 * This information is useful for when perf2bolt works on the profile
 * collected from C_x round. It will be read by perf2bolt in the next
 * round of code layout optimization
 */
void write_func_on_call_stack_into_file(
    const ocolos_env *ocolos_environment,
    std::unordered_map<long, func_info> func_in_call_stack);

/*
 * Get the functions that are not moved by BOLT, nor are they on
 * the call stack.
 */
std::unordered_map<long, func_info> get_unmoved_func_not_in_call_stack(
    std::unordered_map<long, func_info> func_in_call_stack,
    std::unordered_map<long, func_info> unmoved_func);
