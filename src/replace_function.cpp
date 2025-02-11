#include "replace_function.hpp"
#include "l0_mem_pool.h"
#define DEBUG_INFO
#define OCOLOS_TMP_DATA_PATH "/data/wrf/ocolos_data/"
#define DEV "/dev/hisi_l0"
int l0mem_switch = 1;
int mmap_fd = 0; // 使用l0mem时为/dev/hisi_l0的fd，否则为0
cache_tuner *tuner;
void *l0memblock = NULL;
size_t l0mem_size = 0;

int __libc_start_main(void *orig_main,int argc,char* argv[],
                      void (*init_func)(void),
                      void (*fini_func)(void),
                      void (*rtld_fini_func)(void), 
                      void *stack_end) {
    typedef void (*fnptr_type)(void); 
    typedef int (*orig_func_type)(void *, int, char *[], fnptr_type, fnptr_type, fnptr_type, void*);
    orig_func_type orig_func = (orig_func_type)dlsym(RTLD_NEXT, "__libc_start_main");
#ifdef Intel64
    sbrk(0x8000000); // works to shift the first allocation
#endif  
    int ret = orig_func(orig_main, argc, argv,
                        (fnptr_type)init_func,
                        (fnptr_type)fini_func,
                        rtld_fini_func,
                        stack_end);
    return ret;
}

void ocolos_env::get_dir_path(string data_path) {
    ocolos_env::tmp_data_path        = data_path;
    ocolos_env::bolted_function_bin  = ocolos_env::tmp_data_path + "bolted_functions.bin";
    ocolos_env::call_sites_bin       = ocolos_env::tmp_data_path + "call_sites.bin";
    ocolos_env::v_table_bin          = ocolos_env::tmp_data_path + "v_table.bin";
    ocolos_env::unmoved_func_bin     = ocolos_env::tmp_data_path + "unmoved_func.bin";
    ocolos_env::debug_log            = ocolos_env::tmp_data_path + "machine_code.txt";
}

uint64_t convert_str_2_long(string str) {
    uint64_t result = 0;
    for (unsigned i = 0; i < str.size(); i++){
        if ((str[i] >= 'a') && (str[i] <= 'f')) {
            result += str[i] -'a' + 10;
        } else if ((str[i] >= '0') && (str[i] <= '9')) {
            result += str[i] - '0';
        }
        if (i != str.size() - 1){
            result = result * 16;
        }
    }
    return result;
}

void print_err_and_exit(FILE* recordFile, string func, long addr = 0, long len = 0, long page = 0) {
#ifdef DEBUG_INFO
    string command = "[tracee (lib)] " + func + " failed\n";
    fprintf(recordFile, "%s", command.c_str());
    fprintf(recordFile, "[tracee (lib)] error: %s\n", strerror(errno));
    fprintf(recordFile, "[tracee (lib)] target addr = 0x%lx, len=%ld, page_aligned=%lx\n", addr, len, page);
    fflush(recordFile);
#endif
    exit(-1);
}

void record_machine_code(FILE* recordFile, uint8_t* machine_code, unsigned int len){
#ifdef DEBUG_INFO
    for (unsigned int i = 0; i < len; i++){
        fprintf(recordFile, "%x\n", (int)machine_code[i]);
    }
    fprintf(recordFile, "\n\n");
    fflush(recordFile);
#endif
}



void print_func_name(FILE* recordFile, string func){
   #ifdef DEBUG_INFO
   string func_name = "------------------------ " + func + " ------------------------\n";
   fprintf(recordFile, "%s", func_name.c_str());
   fflush(recordFile);
   #endif
}

void insert_code_to_orig_text_sec(FILE* pFile, FILE* recordFile, long base_n) {
    unordered_set<long> allocated_pages;
    while (true) {
        long address, len;
        if (fread(&address, sizeof(long), 1, pFile) == 0)
            break;
        if (fread(&len, sizeof(long), 1, pFile) <= 0)
            print_err_and_exit(recordFile, "fread() len: ");
        uint8_t machine_code[len];
        if (fread(machine_code, sizeof(uint8_t), len, pFile)<=0)
            print_err_and_exit(recordFile, "fread() machine code: ");

        fprintf(recordFile,"[%s]addr: %lx, len: %ld\n",__FUNCTION__, address, len);
        address += base_n;
        void* page_aligned_addr = (void*)((long)address & (~MMAP_PAGE_OFFSET));
        //printf("[tracee (lib)] page aligned addr = %p\n", page_aligned_addr);
        for (long offset = 0; offset <= address + len - (long)page_aligned_addr + MMAP_PAGE_SIZE; offset += MMAP_PAGE_SIZE) {
            long new_addr = offset + (long)page_aligned_addr;
            if (allocated_pages.find(new_addr) == allocated_pages.end()) {
                allocated_pages.insert(new_addr);
                if (mprotect((void*)new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
                    print_err_and_exit(recordFile, "mprotect");
            }
        }
        fprintf(recordFile,"function address: %lx\n",address);
        // insert the machine code 
        uint8_t* addr = (uint8_t*) address;
        memcpy(addr, machine_code, len);

        // record_machine_code(recordFile, machine_code, len);
    }
}

void l0mem_init() {
    // 如果/data/wrf/ocolos_data/usel0文件不存在则将l0mem_switch设置为0
    if (access("/data/wrf/ocolos_data/usel0", F_OK) == -1) {
        printf("[tracee(lib)] cann't use l0 mem, set l0mem_switch = 0\n");
        l0mem_switch = 0;
        return;
    }

    printf("[tracee(lib)] use l0 mem, set l0mem_switch = 1\n");
    l0mem_switch = 1;

    // 初始化l0mem
    // if (cache_tuner_init(&tuner, 80 * 1024 * 1024, 60 * 1024 * 1024) != 0) {
    //     printf("[tracee(lib)] cache_tuner_init failed\n");
    //     exit(-1);
    // }

    // l0memblock = l0_mem_alloc(tuner, 36 * 1024 * 1024);
    // if (l0memblock == NULL) {
    //     printf("[tracee(lib)] l0_mem_alloc failed\n");
    //     exit(-1);
    // }

    mmap_fd = 0;
    if (l0mem_switch) {
        mmap_fd = open(DEV, O_RDWR, 0777);
        if (mmap_fd < 0) {
            printf("[tracee(lib)] insert_machine_code open /dev/hisi_l0 failed!\n");
            mmap_fd = 0;
        }
    }
    long hint_addr = 0x4000000 & (~MMAP_PAGE_OFFSET);
    l0mem_size = 30 * 1024 * 1024;
    l0memblock = mmap((void*)hint_addr, l0mem_size,
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE, mmap_fd, 0);
    if (l0memblock == MAP_FAILED) {
        printf("[tracee(lib)] mmap failed\n");
        exit(-1);
    }
    printf("[tracee(lib)] l0memblock = %p, size = %ld\n", l0memblock, l0mem_size);
}

void before_main() {
    for (int i = 0; environ[i] != NULL; i++) {
        if (strcmp(environ[i], LD_PRELOAD_PATH) == 0) {
            if (unsetenv("LD_PRELOAD") != 0) {
                exit(-1);
            }
            break;
        }
    }

    printf("[tracee(lib)] The virtual address of insert_machine_code() is: %p\n", insert_machine_code);
    // TODO: 通知D-FOT pid和libaddr
    FILE *f = fopen(OCOLOS_TMP_DATA_PATH"tracee.txt", "w");
    if (f != NULL) {
        fprintf(f, "%d %p\n", getpid(), insert_machine_code);
        fclose(f);
    } else {
        exit(-1);
    }

    l0mem_init();
}

void insert_BOLTed_function(FILE* pFile, FILE* recordFile, long base_n) {
    print_func_name(recordFile, "BOLTed functions");
    unordered_set<long> allocated_pages;
    while (true) {
        long address, len;
        if (fread(&address, sizeof(long), 1, pFile) == 0)          // 指令起始地址
            break;
        if (fread(&len, sizeof(long), 1, pFile) <= 0)              // 函数指令长度
            print_err_and_exit(recordFile, "fread len");

        uint8_t machine_code[len];
        if (fread(machine_code, sizeof(uint8_t), len, pFile) <= 0) // 函数指令内容
            print_err_and_exit(recordFile, "fread machine code");

        address += base_n;
#ifdef DEBUG_INFO
        fprintf(recordFile, "[tracee(lib)] target addr = 0x%lx, len=%ld\n", address, len);
        fflush(recordFile);
#endif

        if (l0mem_switch) {
            // 将函数指令写入l0mem
            // insert the machine code 
            uint8_t *addr = (uint8_t *) address;
            memcpy(addr, machine_code, len);
        } else {
        
            // get the page aligned address of the function pointer
            void* page_aligned_addr = (void*)((long)address & (~MMAP_PAGE_OFFSET));  // 指令起始地址所在的页起始地址

            // TODO: 疑似多申请了一个页
            for (long offset = 0; offset <= address + len - (long)page_aligned_addr; offset += MMAP_PAGE_SIZE) {
                long new_addr = offset + (long)page_aligned_addr;
                if (allocated_pages.find(new_addr) == allocated_pages.end()) {
                    allocated_pages.insert(new_addr);
                    if (mmap((void*)new_addr, MMAP_PAGE_SIZE,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE,
                        mmap_fd, 0) == MAP_FAILED)
                        print_err_and_exit(recordFile, "mmap");
                    if (mprotect((void*)new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
                        print_err_and_exit(recordFile, "mprotect");
                }
            }
            // insert the machine code 
            uint8_t *addr = (uint8_t *) address;
            memcpy(addr, machine_code, len);
        }
#ifdef DEBUG_INFO
        // fprintf(recordFile, "function address: %lx\n",address);
        // record_machine_code(recordFile, machine_code, len);
#endif
    }

    fprintf(recordFile, "insert bolted functions done\n");
    if (l0mem_switch) {
        if (mprotect((void*)((long)l0memblock & (~MMAP_PAGE_OFFSET)),
            l0mem_size, PROT_READ | PROT_EXEC) < 0)
            print_err_and_exit(recordFile, "mprotect");
    } else {
        for (auto itr : allocated_pages) {
            if (mprotect((void*)itr, MMAP_PAGE_SIZE, PROT_READ | PROT_EXEC) < 0)
                print_err_and_exit(recordFile, "mprotect");
        }
    }
}

void insert_call_site(FILE* pFile, FILE* recordFile, long base_n) {
    print_func_name(recordFile, "call sites");
    insert_code_to_orig_text_sec(pFile, recordFile, base_n);
}

void insert_v_table(FILE* pFile, FILE* recordFile, long base_n) {
    print_func_name(recordFile, "vtable");
    insert_code_to_orig_text_sec(pFile, recordFile, base_n);
    fflush(recordFile);
}

void insert_unmoved_func(FILE* pFile, FILE* recordFile, long base_n ) {
    print_func_name(recordFile, "unmoved func");
    insert_code_to_orig_text_sec(pFile, recordFile, base_n);
}

void insert_machine_code() {
    uint64_t base_n = 0;
    ocolos_env ocolos_environ;

    // TODO: 获取data_path
    ocolos_environ.get_dir_path(OCOLOS_TMP_DATA_PATH);

    FILE *record_file = fopen(ocolos_environ.debug_log.c_str(), "w");
    if (record_file == NULL) {
        printf("[tracee(lib)] insert_machine_code failed!\n");
        return;
    }

    // TODO: 文件打开失败或者操作失败处理
    // bin file: [addr][len][insts...]...
    FILE *f = fopen(ocolos_environ.bolted_function_bin.c_str(), "r");
    if (f != NULL) {
        // bolted_functions.bin
        insert_BOLTed_function(f, record_file, base_n);
        fclose(f);
    } else {
        fprintf(record_file, "[tracee(lib)] insert_machine_code open %s failed!\n", ocolos_environ.bolted_function_bin.c_str());
        exit(-1);
    }
    f = fopen(ocolos_environ.call_sites_bin.c_str(), "r");
    if (f != NULL) {
        // call_sites.bin
        insert_call_site(f, record_file, base_n);
        fclose (f);
    } else {
        fprintf(record_file, "[tracee(lib)] insert_machine_code open %s failed!\n", ocolos_environ.call_sites_bin.c_str());
        exit(-1);
    }
    f = fopen(ocolos_environ.v_table_bin.c_str(), "r");
    if (f != NULL) {
        // v_table.bin
        insert_v_table(f, record_file, base_n);
        fclose (f);
    } else {
        fprintf(record_file, "[tracee(lib)] insert_machine_code open %s failed!\n", ocolos_environ.v_table_bin.c_str());
        exit(-1);
    }
    f = fopen(ocolos_environ.unmoved_func_bin.c_str(), "r");
    if (f != NULL) {
        // unmoved_func.bin
        insert_unmoved_func(f, record_file, base_n);
        fclose (f);
    } else {
        fprintf(record_file, "[tracee(lib)] insert_machine_code open %s failed!\n", ocolos_environ.unmoved_func_bin.c_str());
        exit(-1);
    }

    fprintf(record_file, "[tracee(lib)] insert_machine_code() is done\n");
    fclose(record_file);
    raise(SIGSTOP);
}
