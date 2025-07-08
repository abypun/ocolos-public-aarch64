#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "boost_serialization.hpp"
#include "utils.hpp"

#define N 16

void thread_function_intel64(
    std::vector<std::pair<long, long>> func_name,
    std::unordered_map<long, call_site_info> &call_sites,
    std::string new_target_binary,
    ocolos_env *ocolos_environ) {
    for (unsigned i = 0; i < func_name.size(); i++) {
        FILE *fp;
        char path[1000];
        std::string start_addr = convert_long_2_hex_string(func_name[i].first);
        std::string stop_addr = convert_long_2_hex_string(func_name[i].first + func_name[i].second);
        std::string command = "" + ocolos_environ->objdump_path + " -d --start-addr=0x" + start_addr +
                              " --stop-addr=0x" + stop_addr + " " + new_target_binary;
        char *command_cstr = new char[command.length() + 1];
        strcpy(command_cstr, command.c_str());

        fp = popen(command_cstr, "r");
        while (fp == NULL) {
            printf("Failed to run command\n");
            printf("function addr: 0x%lx\n", func_name[i].first);
            sleep(1);
            fp = popen(command_cstr, "r");
            // exit(-1);
        }

        std::vector<std::string> assembly_lines;
        while (fgets(path, sizeof(path), fp) != NULL) {
            std::string line(path);
            assembly_lines.push_back(line);
        }
        fclose(fp);

        for (unsigned k = 0; k < assembly_lines.size() - 1; k++) {
            std::string line = assembly_lines[k];
            std::vector<std::string> words = split_line(line);
            if (words.size() <= 8 || (words[6] != "call" && words[6] != "callq")) {
                continue;
            }
            // if it's a library call
            if (words[8].substr(words[8].size() - 5, words[8].size() - 1) == "@plt>")
                continue;
            call_site_info call_info;
            std::cout << line;
            call_info.addr = convert_str_2_long(words[0].substr(0, words[0].size() - 1));
            call_info.belonged_func = func_name[i].first;

            std::string next_line = assembly_lines[k + 1];
            std::vector<std::string> words_next_line = split_line(next_line);

            // if there is no instruction after the call instruction
            if (words_next_line.size() == 0)
                continue;

            call_info.next_addr = convert_str_2_long(words_next_line[0].substr(0, words_next_line[0].size() - 1));
            int idx = 0;
            std::vector<std::string> binary_strs;

            for (unsigned j = 0; j < words.size(); j++) {
                if (words[j].length() == 2 && is_hex(words[j])) {
                    if (idx == 5) {
                        printf("[extract_call_site]: error in the size of a call instruction\n");
                        exit(-1);
                     }
                    binary_strs.push_back(words[j]);
                    call_info.machine_code[idx] = convert_str_2_uint8(words[j]);
                    idx++;
                }
            }

            std::string real_offset = "";
            if (binary_strs.size() != 5) {
                std::cout << "[extract_call_site]: error: binary_strs.size()!=5\n";
            }
            for (unsigned j = binary_strs.size() - 1; j > 0; j--) {
                std::string tmp = real_offset + binary_strs[j];
                real_offset = tmp;
            }
            call_info.target_func_addr = 0xffffffff & (convert_str_2_long(real_offset) + call_info.next_addr);
            call_sites[call_info.addr] = call_info;
        }
    }
}

void thread_function_aarch64(
    std::vector<std::pair<long, long>> func_name,
    std::unordered_map<long, call_site_info> &call_sites,
    std::string new_target_binary,
    ocolos_env *ocolos_environ) {
    for (unsigned i = 0; i < func_name.size(); i++) {
        FILE *fp;
        char path[1000];
        std::string start_addr = convert_long_2_hex_string(func_name[i].first);
        std::string stop_addr = convert_long_2_hex_string(func_name[i].first + func_name[i].second);
        std::string command = "" + ocolos_environ->objdump_path + " -d --start-addr=0x" + start_addr +
                              " --stop-addr=0x" + stop_addr + " " + new_target_binary;
        char *command_cstr = new char[command.length() + 1];
        strcpy(command_cstr, command.c_str());

        fp = popen(command_cstr, "r");
        while (fp == NULL) {
            printf("Failed to run command\n");
            printf("function addr: 0x%lx\n", func_name[i].first);
            sleep(1);
            fp = popen(command_cstr, "r");
            // exit(-1);
        }

        std::vector<std::string> assembly_lines;
        while (fgets(path, sizeof(path), fp) != NULL) {
            std::string line(path);
            assembly_lines.push_back(line);
        }
        fclose(fp);

        for (unsigned k = 0; k < assembly_lines.size() - 1; k++) {
            std::string line = assembly_lines[k];
            std::vector<std::string> words = split_line(line);
            if (words.size() <= 4 || words[2] != "bl") {
                continue;
            }
            // if it's a library call
            if (words[4].substr(words[4].size() - 5, words[4].size() - 1) == "@plt>")
                continue;
            call_site_info call_info;
            std::cout << line;
            call_info.addr = convert_str_2_long(words[0].substr(0, words[0].size() - 1));
            call_info.belonged_func = func_name[i].first;

            std::string next_line = assembly_lines[k + 1];
            std::vector<std::string> words_next_line = split_line(next_line);

            // if there is no instruction after the call instruction
            if (words_next_line.size() == 0)
                continue;

            call_info.next_addr = convert_str_2_long(words_next_line[0].substr(0, words_next_line[0].size() - 1));
            int idx = 0;
            for (unsigned j = 0; j < 8; j += 2) {
                call_info.machine_code[idx] = convert_str_2_uint8(words[1].substr(j, 2));
                idx++;
            }
            long tmp = stoi(words[3], 0, 16);
            call_info.target_func_addr = 0xffffffff & tmp;
            call_sites[call_info.addr] = call_info;
        }
    }
}

int main() {
    FILE *fp3;
    char path3[1000];
    ocolos_env ocolos_environ;
    std::string command = "cp " + ocolos_environ.target_binary_path + " " + ocolos_environ.tmp_data_path;
    system(command.c_str());

    std::vector<std::string> dir_names = split(ocolos_environ.target_binary_path, '/');
    std::string new_target_binary = ocolos_environ.tmp_data_path + dir_names[dir_names.size() - 1];

    command = "strip -g " + new_target_binary;
    system(command.c_str());

    command = "" + ocolos_environ.nm_path + " -S -n " + new_target_binary;
    char *command_cstr = new char[command.length() + 1];
    strcpy(command_cstr, command.c_str());
    fp3 = popen(command_cstr, "r");
    if (fp3 == NULL) {
        printf("Failed to run nm on BOLTed binary\n");
        exit(-1);
    }

    std::vector<std::pair<long, long>> func_name;
    while (fgets(path3, sizeof(path3), fp3) != NULL) {
        std::string line(path3);
        std::vector<std::string> words = split_line(line);
        if (words.size() > 3) {
            std::cout << line;
            if ((words[2] == "T") || (words[2] == "t") || (words[2] == "W") || (words[2] == "w")) {
                long start_addr = convert_str_2_long(words[0]);
                long len_str = convert_str_2_long(words[1]);
                func_name.push_back(std::make_pair(start_addr, len_str));
            }
        }
    }

    printf("\n[extract_call_sites] %ld functions in the original binary\n", func_name.size());
    fclose(fp3);

    int size = (int) (func_name.size() / N);

    std::vector<std::vector<std::pair<long, long>>> func_names;
    std::vector<std::pair<long, long>>::const_iterator first, last;
    for (int i = 0; i < N; i++) {
        first = func_name.begin() + i * size;
        if (i != (N - 1)) {
            last = func_name.begin() + (i + 1) * size;
        } else {
            last = func_name.end();
        }
        std::vector<std::pair<long, long>> new_str(first, last);
        func_names.push_back(new_str);
    }
    std::unordered_map<long, call_site_info> call_sites_array[N];

    std::vector<std::thread> threads;

#ifdef Intel64
    for (int i = 0; i < N; i++) {
        std::thread t(thread_function_intel64, func_names[i], ref(call_sites_array[i]), new_target_binary, &ocolos_environ);
        threads.push_back(std::move(t));
    }
#endif
#ifdef AArch64
    for (int i = 0; i < N; i++) {
        std::thread t(thread_function_aarch64, func_names[i], ref(call_sites_array[i]), new_target_binary, &ocolos_environ);
        threads.push_back(std::move(t));
    }
#endif

    for (int i = 0; i < N; i++) {
        threads[i].join();
        printf("the size of call_sites = %lu\n", call_sites_array[i].size());
    }

    std::unordered_map<long, call_site_info> call_sites;
    for (int i = 0; i < N; i++) {
        call_sites.insert(call_sites_array[i].begin(), call_sites_array[i].end());
    }
    printf("@@@@@@@@@@@@ the size of call_sites (final) = %lu\n", call_sites.size());

    std::ofstream ofs(ocolos_environ.call_sites_all_bin);
    boost::archive::binary_oarchive oa(ofs);
    oa << call_sites;

    std::unordered_map<long, std::vector<long>> call_sites_list;
    for (auto it = call_sites.begin(); it != call_sites.end(); it++) {
        if (call_sites_list.find(it->second.target_func_addr) != call_sites_list.end()) {
            call_sites_list[it->second.target_func_addr].push_back(it->first);
        } else {
            std::vector<long> tmp;
            tmp.push_back(it->first);
            call_sites_list.insert(std::make_pair(it->second.target_func_addr, tmp));
        }
    }
    printf("########### the size of call_sites_list = %lu\n", call_sites_list.size());

    std::ofstream ofs1(ocolos_environ.call_sites_list_bin);
    boost::archive::binary_oarchive oa1(ofs1, boost::archive::no_codecvt);
    oa1 << call_sites_list;

    //   command = "rm -rf "+new_target_binary;
    system(command.c_str());
}
