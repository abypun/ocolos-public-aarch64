#include "utils.hpp"

ocolos_env::ocolos_env() {
    // TODO: 如果指定OCOLOS_CONFIG=/path/to/config.ini，则解析用户配置
    // 默认通过D-FOT配置获取
    tmp_data_path = "/data/wrf/ocolos_data/";
    target_binary_path = "/data/wrf/ocolos_data/mysqld";
    bolted_binary_path = tmp_data_path + "mysqld.bolt";
    ld_preload_path = "/home/wrf/codes/ocolos-public-aarch64/replace_function.so";
    bolted_function_bin = tmp_data_path + "bolted_functions.bin";
    call_sites_bin = tmp_data_path + "call_sites.bin";
    v_table_bin = tmp_data_path + "v_table.bin";
    unmoved_func_bin = tmp_data_path + "unmoved_func.bin";
    call_sites_all_bin = tmp_data_path + "call_sites_all.bin";
    call_sites_list_bin = tmp_data_path + "call_sites_list.bin";
    nm_path = "/usr/bin/nm";
    objdump_path = "/usr/bin/objdump";
}

std::vector<std::string> split_line(std::string str) {
    std::vector<std::string> words;
    std::stringstream ss(str);
    std::string tmp;
    while (ss >> tmp) {
        words.push_back(tmp);
        tmp.clear();
    }
    return words;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;

    while (getline(ss, item, delim)) {
        result.push_back(item);
    }
    return result;
}

long convert_str_2_int(std::string str) {
    long result = 0;
    for (unsigned i = 0; i < str.size(); i++) {
        result += str[i] - '0';
        if (i != str.size() - 1) {
            result = result * 10;
        }
    }
    return result;
}

bool is_num(std::string word) {
    for (unsigned i = 0; i < word.size(); i++) {
        if (!((word[i] >= '0') && (word[i] <= '9'))) {
            return false;
        }
    }
    return true;
}

long convert_str_2_long(std::string str) {
    long result = 0;
    for (unsigned i = 0; i < str.size(); i++) {
        if ((str[i] >= 'a') && (str[i] <= 'f')) {
            result += str[i] - 'a' + 10;
        } else if ((str[i] >= '0') && (str[i] <= '9')) {
            result += str[i] - '0';
        }
        if (i != str.size() - 1) {
            result = result * 16;
        }
    }
    return result;
}

bool is_hex(std::string word) {
    if (word.size() == 0)
        return false;
    for (unsigned int i = 0; i < word.size(); i++) {
        if (!(((word[i] >= '0') && (word[i] <= '9')) || ((word[i] >= 'a') && (word[i] <= 'f')))) {
            return false;
        }
    }
    return true;
}

uint8_t convert_str_2_uint8(std::string str) {
    uint8_t result = 0;
    if ((str[0] >= 'a') && (str[0] <= 'f')) {
        result += str[0] - 'a' + 10;
    } else if ((str[0] >= '0') && (str[0] <= '9')) {
        result += str[0] - '0';
    }
    result = result * 16;
    if ((str[1] >= 'a') && (str[1] <= 'f')) {
        result += str[1] - 'a' + 10;
    } else if ((str[1] >= '0') && (str[1] <= '9')) {
        result += str[1] - '0';
    }
    return result;
}

std::vector<uint8_t> convert_long_2_vec_uint8(long input) {
    std::vector<uint8_t> tmp;
    long divisor = 256 * 256 * 256;
    long input_ = input;
    long tmp1;
    for (int i = 0; i < 4; i++) {
        tmp1 = input_ / divisor;
        input_ = input_ % divisor;
        tmp.push_back((uint8_t) tmp1);
        divisor /= 256;
    }
    std::vector<uint8_t> result;
    for (int i = 3; i >= 0; i--) {
        result.push_back(tmp[i]);
    }
    return result;
}

std::string convert_long_2_hex_string(long num) {
    std::stringstream stream;
    stream << std::hex << num;
    std::string result(stream.str());
    return result;
}

std::vector<long> get_keys_to_array(std::unordered_map<long, func_info> func) {
    std::vector<long> addr_vec;
    for (auto it = func.begin(); it != func.end(); it++) {
        addr_vec.push_back(it->first);
    }
    return addr_vec;
}

std::vector<long> get_moved_addr_to_array(std::unordered_map<long, func_info> func) {
    std::vector<long> addr_vec;
    for (auto it = func.begin(); it != func.end(); it++) {
        addr_vec.push_back(it->second.moved_addr);
    }
    return addr_vec;
}

char **split_str_2_char_array(const std::string &str) {
    std::vector<std::string> word_vec = split_line(str);
    char **words;
    words = (char **) malloc(sizeof(char *) * word_vec.size() + 1);
    for (unsigned i = 0; i < word_vec.size(); i++) {
        words[i] = (char *) malloc(sizeof(char) * word_vec[i].size() + 1);
        memset(words[i], '\0', sizeof(char) * (word_vec[i].size() + 1));
        strcpy(words[i], word_vec[i].c_str());
    }
    words[word_vec.size()] = NULL;
    return words;
}

void clean_up(const ocolos_env *ocolos_environ) {
    std::string command = "rm -rf " + ocolos_environ->tmp_data_path + "bolted_functions.bin " +
                     ocolos_environ->tmp_data_path + "call_sites.bin " + ocolos_environ->tmp_data_path +
                     "v_table.bin " + ocolos_environ->tmp_data_path + "unmoved_func.bin " +
                     ocolos_environ->tmp_data_path + "*.data " + ocolos_environ->tmp_data_path + "*.fdata " +
                     ocolos_environ->tmp_data_path + "*.txt " + ocolos_environ->tmp_data_path + "*.old ";
    if (system(command.c_str()) == -1)
        exit(-1);
}

uint32_t compute_bl_instruction(uint32_t target_address, uint32_t instruction_address) {
    int32_t offset = ((int32_t) target_address - (int32_t) instruction_address) / 4;
    uint32_t imm26 = offset & 0x03ffffff;
    uint32_t imm_sign_bit = (offset >> 25) & 1;
    uint32_t machine_code = 0x94000000 | (imm_sign_bit << 26) | imm26;
    return machine_code;
}

std::vector<uint8_t> convert_uint32_2_vec_uint8(uint32_t input) {
    std::vector<uint8_t> result;
    uint8_t tmp;
    for (int i = 3; i >= 0; i--) {
        int offset = i * 8;
        tmp = (input >> offset) & 0xFF;
        result.push_back(tmp);
    }
    return result;
}
