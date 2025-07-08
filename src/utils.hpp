#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libunwind-ptrace.h>
#include <libunwind.h>
#include <map>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <wait.h>
#ifdef Intel64
#include <libunwind-x86_64.h>
#include <sys/reg.h>
#endif
#ifdef AArch64
#include <elf.h>
#include <errno.h>
#include <libunwind-aarch64.h>
#endif

#define panic(X) fprintf(stderr, #X "\n");

extern char **environ;

#ifndef UTILS
#define UTILS

/*
 * struct that keep track of the functions
 * extracted from the original and BOLTed binary.
 */
typedef struct func_info {
    bool in_call_stack;
    long original_addr;
    long moved_addr;
    long original_size;
    long moved_size;
    std::string func_name;
    std::string orig_addr_str;
    std::string moved_addr_str;
} func_info;

/*
 * struct that stores all the paths and commands
 * that are read from the config file.
 */
typedef struct ocolos_env {
    std::unordered_map<std::string, std::string> configs;

    std::string dir_path;
    std::string bolted_binary_path;
    std::string ld_preload_path;
    std::string bolted_function_bin;

    std::string call_sites_bin;
    std::string v_table_bin;
    std::string unmoved_func_bin;

    std::string call_sites_all_bin;
    std::string call_sites_list_bin;

    std::string perf_path;
    std::string nm_path;
    std::string objdump_path;
    std::string llvmbolt_path;
    std::string perf2bolt_path;

    std::string target_binary_path;
    std::string run_server_cmd;
    std::string init_benchmark_cmd;
    std::string run_benchmark_cmd;

    std::string client_binary_path;
    std::string db_name;
    std::string db_user_name;

    std::string lib_path;
    std::string tmp_data_path;

    int listen_fd;

    /*
     * Constructor function that initialize all strings
     * stored in this struct.
     */
    ocolos_env();

    /*
     * Read the config file and store all information
     * into key-value store. The keys are:
     * (1) the name of the binary
     *     in this case the value is the absolute path
     *     of the binary
     * (2) the abbreviation of the command
     *     in this case the vlue is the full command.
     */
    void read_config();

    /*
     * Get the absolute path of the current directory
     * where the `tracer` locates.
     */
    void get_dir_path();

    /*
     * Get the absolute path of a binary. The binary's
     * name is specified as the argument of this
     * function.
     */
    std::string get_binary_path(std::string);

    /*
     * Extract the target server binary from the command
     * specified in the config file.
     */
    void get_target_binary_path();

    /*
     * Read the command from the config file, including
     * (1) the command of the server process, (2) the
     * command of initialize the benchmark, (3)the
     * command of running the benchmark.
     */
    void get_cmds();
} ocolos_env;

#endif

/*
 * Test whether a string is a decimal number
 * return true: is a decimal number
 * return false: is not a decimal number
 */
bool is_num(std::string);

/*
 * Convert a string that is a decimal number
 * to a long int.
 * The return value is the long int.
 */
long convert_str_2_int(std::string);

/*
 * Split a string by tab and space and then store
 * the splitted strings into vector<string>
 */
std::vector<std::string> split_line(std::string str);

/*
 * Split a string by a delimiter and then store
 * the splitted strings into vector<string>
 */
std::vector<std::string> split(const std::string &s, char delim);

/*
 * Split a string by tab and space and then store
 * the splitted strings into char**.
 */
char **split_str_2_char_array(const std::string &str);

/*
 * Test whether a string is a hexadecimal number
 * return true: is a hexadecimal number
 * return false: is not a hexadecimal number
 */
bool is_hex(std::string);

/*
 * Convert a string that is a hexadecimal number
 * to a long int.
 * The return value is the long int.
 */
long convert_str_2_long(std::string str);

/*
 * Extract all 2-digit hexadecimal number in the
 * string and then store them into vector<uint8>.
 * This is used for extract machine code from
 * `objdump`'s output.
 */
uint8_t convert_str_2_uint8(std::string);

/*
 * Convert a long int to a 4 uint8_t numbers, and
 * push them from the highest digit to the lowest
 * digit to a vector<uint8_t>.
 * This is used to patch call sites in the machine
 * code extracted from objdump.
 */
std::vector<uint8_t> convert_long_2_vec_uint8(long);

/*
 * Convert a long integer to to a string that shows
 * the value of the long interger in hexadecimal.
 * This is used to patch call sites in the machine
 * code extracted from objdump.
 */
std::string convert_long_2_hex_string(long);

/*
 * Get the keys from unordered_map, if the keys are
 * long int type. And then store all keys into a
 * vector. The keys are actually the starting
 * addresses of functions.
 * This is used to pass all starting addresses
 * of unmoved functions in the BOLTed binary to the
 * Rust code.
 */
std::vector<long> get_keys_to_array(std::unordered_map<long, func_info> func);

/*
 * Get the moved addresses (the starting addresses of
 * functions in the BOLTed binary that have starting
 * address changed) from unordered_map.
 * This is used to pass all starting addresses of the
 * moved functions in the BOLTed binary to the Rust
 * code.
 */
std::vector<long> get_moved_addr_to_array(std::unordered_map<long, func_info> func);

/*
 * Delete all intermediate files.
 */
void clean_up(const ocolos_env *);

std::vector<uint8_t> convert_uint32_2_vec_uint8(uint32_t input);

uint32_t compute_bl_instruction(uint32_t target_address, uint32_t instruction_address);
