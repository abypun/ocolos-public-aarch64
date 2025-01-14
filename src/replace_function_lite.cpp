#include "replace_function.hpp"
#define DEBUG_INFO
#define OCOLOS_TMP_DATA_PATH "/data/wrf/ocolos_data/"

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

void ocolos_env::get_dir_path(string data_path){
    ocolos_env::tmp_data_path        = data_path;
    ocolos_env::bolted_function_bin  = ocolos_env::tmp_data_path + "bolted_functions.bin";
    ocolos_env::call_sites_bin       = ocolos_env::tmp_data_path + "call_sites.bin";
    ocolos_env::v_table_bin          = ocolos_env::tmp_data_path + "v_table.bin";
    ocolos_env::unmoved_func_bin     = ocolos_env::tmp_data_path + "unmoved_func.bin";
    ocolos_env::debug_log            = ocolos_env::tmp_data_path + "machine_code.txt";
}

uint64_t convert_str_2_long(string str){
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



void insert_code_to_orig_text_sec(FILE* pFile, FILE* recordFile, long base_n){
   unordered_set<long> allocated_pages;
   while(true){
      long address;
      long len;
      if (fread(&address,sizeof(long),1,pFile)==0) break;	
      if (fread(&len,sizeof(long), 1, pFile)<=0) print_err_and_exit(recordFile, "fread() len: ");
      uint8_t machine_code[len];
      if (fread(machine_code, sizeof(uint8_t), len, pFile)<=0) print_err_and_exit(recordFile, "fread() machine code: ");
      address += base_n;
      // get the page aligned address of the function pointer
      void*	page_aligned_addr = (void*)((long)address & (~MMAP_PAGE_OFFSET));
      //printf("[tracee (lib)] page aligned addr = %p\n", page_aligned_addr);
      for (long offset = 0; offset<=address+len-(long)page_aligned_addr+MMAP_PAGE_SIZE; offset += MMAP_PAGE_SIZE){
         long new_addr = offset+(long)page_aligned_addr;				
         if (allocated_pages.find(new_addr)==allocated_pages.end()){
            allocated_pages.insert(new_addr);
            int err =  mprotect((void*)new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
            if (err<0) print_err_and_exit(recordFile, "mprotect");
         }
      }
      fprintf(recordFile,"function address: %lx\n",address);
      // insert the machine code 
      uint8_t* addr = (uint8_t*) address;
      memcpy(addr, machine_code, len);

      record_machine_code(recordFile, machine_code, len);
   }
}




void create_tcp_socket(int & listen_fd, struct sockaddr_in & servaddr){
   bzero(&servaddr, sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr = htons(INADDR_ANY);
   servaddr.sin_port = htons(18000);
   bind(listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
   listen(listen_fd, 10);
}




string get_data_path(int listen_fd){
   struct sockaddr_in clientaddr;
   socklen_t clientaddrlen = sizeof(clientaddr);
   int comm_fd = accept(listen_fd, (struct sockaddr*)&clientaddr, &clientaddrlen);
   const int enable = 1;
   if (setsockopt(comm_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
      printf("[tracer(lib)] setsockopt(SO_REUSEADDR) failed\n");
      exit(-1);
   }

   printf("[tracee (lib)] connection from %s\n", inet_ntoa(clientaddr.sin_addr));
   char* buf = (char*)malloc(500*sizeof(char));
   memset(buf, 0, 500*sizeof(char));
   int n = read(comm_fd, buf, 80);
   if (n<=0){
      printf("[tracee (lib)] error in receiving msg from tracee.\n");
      exit(-1);
   }
   close(comm_fd);
   string path(buf);
   free(buf);
   return path;
}

void before_main() {
    for (int i = 0; environ[i] != NULL; i++) {
        if (strcmp(environ[i], LD_PRELOAD_PATH) == 0){
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
}

void insert_BOLTed_function(FILE* pFile, FILE* recordFile, long base_n){
   print_func_name(recordFile, "BOLTed functions");
   unordered_set<long> allocated_pages;
   if (pFile!=NULL){
      while(true){
         long address;
         long len;
         if (fread(&address,sizeof(long),1,pFile)==0) break;	
         if (fread(&len,sizeof(long), 1, pFile)<=0) print_err_and_exit(recordFile, "fread() len: ");
         uint8_t machine_code[len];
         if (fread(machine_code, sizeof(uint8_t), len, pFile)<=0) print_err_and_exit(recordFile, "fread() machine code:");

         address += base_n;

         #ifdef DEBUG_INFO
         fprintf(recordFile, "[tracee(lib)] target addr = 0x%lx, len=%ld\n", address, len);
         fflush(recordFile);
         #endif

         // get the page aligned address of the function pointer
         void*	page_aligned_addr = (void*)((long)address & (~MMAP_PAGE_OFFSET));

         for (long offset = 0; offset<=address+len-(long)page_aligned_addr+MMAP_PAGE_SIZE; offset += MMAP_PAGE_SIZE){
            long new_addr = offset + (long)page_aligned_addr;
            if (allocated_pages.find(new_addr)==allocated_pages.end()){
               allocated_pages.insert(new_addr);
               void* ret = mmap((void*)new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC , MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE , 0, 0);	
               if (ret==MAP_FAILED) print_err_and_exit(recordFile, "mmap");
               int err =  mprotect((void*)new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
               if (err<0) print_err_and_exit(recordFile, "mprotect");
            }
         }

         // insert the machine code 
         uint8_t* addr = (uint8_t*) address;
         memcpy(addr, machine_code, len);

         #ifdef DEBUG_INFO
         fprintf(recordFile,"function address: %lx\n",address);
         record_machine_code(recordFile, machine_code, len);
         #endif
      }

      for (auto itr : allocated_pages){
         int err =  mprotect((void*)itr, MMAP_PAGE_SIZE, PROT_READ | PROT_EXEC);
         if (err<0) print_err_and_exit(recordFile, "mprotect");
      }
   }
   else{
      printf("[tracee(lib)] cannot open bolted_functions.bin\n");
      exit(-1);
   }
}



void insert_call_site(FILE* pFile, FILE* recordFile, long base_n){
   print_func_name(recordFile, "call sites");
   if (pFile!=NULL){
      insert_code_to_orig_text_sec(pFile, recordFile, base_n);
   }else{
      printf("[tracee(lib)] cannot open call_sites.bin\n");
      exit(-1);
   }
}



void insert_v_table(FILE* pFile, FILE* recordFile, long base_n){
   print_func_name(recordFile, "vtable");
   if (pFile!=NULL){
      insert_code_to_orig_text_sec(pFile, recordFile, base_n);
   }else{
      printf("[tracee(lib)] cannot open v_table.bin\n");
      exit(-1);
   }
   fflush(recordFile);
}



void insert_unmoved_func(FILE* pFile, FILE* recordFile, long base_n ){
   print_func_name(recordFile, "unmoved func");
   if (pFile!=NULL){
      insert_code_to_orig_text_sec(pFile, recordFile, base_n);
   } else{
      printf("[tracee(lib)] cannot open unmoved_functions.bin\n");
      exit(-1);
   }
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
    FILE *f = fopen(ocolos_environ.bolted_function_bin.c_str(), "r");
    if (f != NULL) {
        insert_BOLTed_function(f, record_file, base_n);
        fclose(f);
    }

    f = fopen(ocolos_environ.call_sites_bin.c_str(), "r");
    if (f != NULL){
        insert_call_site(f, record_file, base_n);
        fclose (f);
    }

    f = fopen(ocolos_environ.v_table_bin.c_str(), "r");
    if (f != NULL){
        insert_v_table(f, record_file, base_n);
        fclose (f);
    }

    f = fopen(ocolos_environ.unmoved_func_bin.c_str(), "r");
    if (f != NULL){		
        insert_unmoved_func(f, record_file, base_n);
        fclose (f);
    }

    fclose(record_file);
    printf("[tracee(lib)] insert_machine_code() is done\n");
    raise(SIGSTOP);
}
