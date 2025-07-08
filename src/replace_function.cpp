#include "replace_function.hpp"

int MMAP_PAGE_SIZE = 0x1000;
int MMAP_PAGE_OFFSET = 0b111111111111;

// 需要动态确定，并一次申请完毕，否则中间申请失败就很尴尬
uint64_t base_n = 0; // 0x20000000

int __libc_start_main(void *orig_main, int argc, char *argv[], void (*init_func)(void), void (*fini_func)(void),
                      void (*rtld_fini_func)(void), void *stack_end) {
    typedef void (*fnptr_type)(void);
    typedef int (*orig_func_type)(void *, int, char *[], fnptr_type, fnptr_type, fnptr_type, void *);
    orig_func_type orig_func;
    int ret = 0;
    orig_func = (orig_func_type) dlsym(RTLD_NEXT, "__libc_start_main");
    // sbrk(0x8000000); // works to shift the first allocation
    ret = orig_func(orig_main, argc, argv, (fnptr_type) init_func, (fnptr_type) fini_func, rtld_fini_func, stack_end);
    return ret;
}

void ocolos_env::get_dir_path(std::string data_path) {
    ocolos_env::tmp_data_path = data_path;

    ocolos_env::bolted_function_bin = ocolos_env::tmp_data_path + "bolted_functions.bin";
    ocolos_env::call_sites_bin = ocolos_env::tmp_data_path + "call_sites.bin";
    ocolos_env::v_table_bin = ocolos_env::tmp_data_path + "v_table.bin";
    ocolos_env::unmoved_func_bin = ocolos_env::tmp_data_path + "unmoved_func.bin";

    ocolos_env::debug_log = ocolos_env::tmp_data_path + "machine_code.txt";
}

uint64_t convert_str_2_long(std::string str) {
    uint64_t result = 0;
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

void print_err_and_exit(FILE *recordFile, std::string func, long addr = 0, long len = 0, long page = 0) {
#ifdef DEBUG_INFO
    std::string command = "[tracee (lib)] " + func + " failed\n";
    fprintf(recordFile, "%s", command.c_str());
    fprintf(recordFile, "[tracee (lib)] error: %s\n", strerror(errno));
    fprintf(recordFile, "[tracee (lib)] target addr = 0x%lx, len=%ld, page_aligned=%lx\n", addr, len, page);
    fflush(recordFile);
#endif
    exit(-1);
}

void record_machine_code(FILE *recordFile, uint8_t *machine_code, unsigned int len) {
#ifdef DEBUG_INFO
    for (unsigned int i = 0; i < len; i++) {
        fprintf(recordFile, "%x\n", (int) machine_code[i]);
    }
    fprintf(recordFile, "\n\n");
    fflush(recordFile);
#endif
}

void print_func_name(FILE *recordFile, std::string func) {
#ifdef DEBUG_INFO
    std::string func_name = "------------------------ " + func + " ------------------------\n";
    fprintf(recordFile, "%s", func_name.c_str());
    fflush(recordFile);
#endif
}

void insert_code_to_orig_text_sec(FILE *pFile, FILE *recordFile, long base_n) {
    std::unordered_set<long> allocated_pages;
    while (true) {
        long address;
        long len;
        if (fread(&address, sizeof(long), 1, pFile) == 0)
            break;
        if (fread(&len, sizeof(long), 1, pFile) <= 0)
            print_err_and_exit(recordFile, "fread() len: ");
        uint8_t machine_code[len];
        if (fread(machine_code, sizeof(uint8_t), len, pFile) <= 0)
            print_err_and_exit(recordFile, "fread() machine code: ");
        address += base_n;
        // get the page aligned address of the function pointer
        void *page_aligned_addr = (void *) ((long) address & (~MMAP_PAGE_OFFSET));
        // printf("[tracee (lib)] page aligned addr = %p\n", page_aligned_addr);
        for (long offset = 0; offset <= address + len - (long) page_aligned_addr + MMAP_PAGE_SIZE;
             offset += MMAP_PAGE_SIZE) {
            long new_addr = offset + (long) page_aligned_addr;
            if (allocated_pages.find(new_addr) == allocated_pages.end()) {
                allocated_pages.insert(new_addr);
                int err = mprotect((void *) new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
                if (err < 0)
                    print_err_and_exit(recordFile, "mprotect");
            }
        }
        fprintf(recordFile, "function address: %lx\n", address);
        // insert the machine code
        uint8_t *addr = (uint8_t *) address;
        memcpy(addr, machine_code, len);

        record_machine_code(recordFile, machine_code, len);
    }
}

void before_main() {
    // TODO: 这里的实现存在问题，未考虑路径，当前无影响，待修改
    // delete the ld_preload environment variable
    // for (int i = 0; environ[i] != NULL; i++) {
    //     if (strcmp(environ[i], LD_PRELOAD_PATH) == 0) {
    //         int err = unsetenv("LD_PRELOAD");
    //         if (err != 0) {
    //             exit(-1);
    //         }
    //         break;
    //     }
    // }

    printf("\n[tracee (lib)] pid: %d, insert_machine_code: %p\n", getpid(), insert_machine_code);
    // 动态确认页大小
   // TODO：用户配置默认留空，如果用户主动配置，则校验
   // 校验成功则使用，校验失败后以环境配置为准并打印警告
   MMAP_PAGE_SIZE = sysconf(_SC_PAGESIZE);
   MMAP_PAGE_OFFSET = MMAP_PAGE_SIZE - 1;
   printf("[tracee (lib)] MMAP_PAGE_SIZE: %x\n", MMAP_PAGE_SIZE);
}

void insert_BOLTed_function(FILE *pFile, FILE *recordFile, long base_n) {
    print_func_name(recordFile, "BOLTed functions");
    std::unordered_set<long> allocated_pages;
    if (pFile == NULL) {
        printf("[tracee (lib)] cannot open bolted_functions.bin\n");
        exit(-1);
    }
    while (true) {
        long address;
        long len;
        if (fread(&address, sizeof(long), 1, pFile) == 0)
            break;
        if (fread(&len, sizeof(long), 1, pFile) <= 0)
            print_err_and_exit(recordFile, "fread() len: ");
        uint8_t machine_code[len];
        if (fread(machine_code, sizeof(uint8_t), len, pFile) <= 0)
            print_err_and_exit(recordFile, "fread() machine code:");

        address += base_n;

#ifdef DEBUG_INFO
        fprintf(recordFile, "[tracee (lib)] target addr = 0x%lx, len=%ld\n", address, len);
        fflush(recordFile);
#endif

        // get the page aligned address of the function pointer
        void *page_aligned_addr = (void *) ((long) address & (~MMAP_PAGE_OFFSET));

        for (long offset = 0; offset <= address + len - (long) page_aligned_addr + MMAP_PAGE_SIZE;
             offset += MMAP_PAGE_SIZE) {
            long new_addr = offset + (long) page_aligned_addr;
            if (allocated_pages.find(new_addr) != allocated_pages.end()) {
                continue;
            }
            allocated_pages.insert(new_addr);
            void *ret = mmap((void *) new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
            if (ret==MAP_FAILED) {
                // 打印mmap入参和失败原因
                fprintf(recordFile,
                    "[tracee (lib)] mmap failed: %s, new_addr: %lx, MMAP_PAGE_SIZE: %x\n",
                    strerror(errno), new_addr, MMAP_PAGE_SIZE);
                print_err_and_exit(recordFile, "mmap");
            }
            int err = mprotect((void *) new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
            if (err < 0)
                print_err_and_exit(recordFile, "mprotect");
        }

        // insert the machine code
        uint8_t *addr = (uint8_t *) address;
        memcpy(addr, machine_code, len);

#ifdef DEBUG_INFO
        fprintf(recordFile, "function address: %lx\n", address);
        record_machine_code(recordFile, machine_code, len);
#endif
    }

    for (auto itr : allocated_pages) {
        int err = mprotect((void *) itr, MMAP_PAGE_SIZE, PROT_READ | PROT_EXEC);
        if (err < 0)
            print_err_and_exit(recordFile, "mprotect");
    }
}

void insert_call_site(FILE *pFile, FILE *recordFile, long base_n) {
    print_func_name(recordFile, "call sites");
    insert_code_to_orig_text_sec(pFile, recordFile, base_n);
    fflush(recordFile);
}

void insert_v_table(FILE *pFile, FILE *recordFile, long base_n) {
    print_func_name(recordFile, "vtable");
    insert_code_to_orig_text_sec(pFile, recordFile, base_n);
    fflush(recordFile);
}

void insert_unmoved_func(FILE *pFile, FILE *recordFile, long base_n) {
    print_func_name(recordFile, "unmoved func");
    insert_code_to_orig_text_sec(pFile, recordFile, base_n);
    fflush(recordFile);
}

void insert_machine_code(void) {
    ocolos_env ocolos_environ;

    std::string data_path = "/data/wrf/ocolos_data/";
    ocolos_environ.get_dir_path(data_path);

    FILE *f[5];
    f[0] = fopen(ocolos_environ.bolted_function_bin.c_str(), "r");
    f[1] = fopen(ocolos_environ.call_sites_bin.c_str(), "r");
    f[2] = fopen(ocolos_environ.v_table_bin.c_str(), "r");
    f[3] = fopen(ocolos_environ.unmoved_func_bin.c_str(), "r");
    f[4] = fopen(ocolos_environ.debug_log.c_str(), "w");

    for (int i = 0; i < 5; i++) {
        if (f[i] == NULL) exit(-1);
    }

    insert_BOLTed_function(f[0], f[4], base_n);
    insert_call_site(f[1], f[4], base_n);
    insert_v_table(f[2], f[4], base_n);
    insert_unmoved_func(f[3], f[4], base_n);
    for (int i = 0; i < 5; i++) {
        fclose(f[i]);
    }

    printf("[tracee (lib)] insert_machine_code() is done\n");
    raise(SIGSTOP);
}
