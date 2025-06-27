#include "replace_function.hpp"

int MMAP_PAGE_SIZE = 4*1024; // huge page: 2*1024*1024
int MMAP_PAGE_OFFSET = 0b111111111111; // huge page: 0b111111111111111111111


int __libc_start_main(void *orig_main,int argc,char* argv[],
  void (*init_func)(void),
  void (*fini_func)(void),
  void (*rtld_fini_func)(void), 
  void *stack_end){
  typedef void (*fnptr_type)(void); 
  typedef int (*orig_func_type)(void *, int, char *[], fnptr_type,fnptr_type, fnptr_type, void*);
  orig_func_type orig_func;
  int ret = 0;
  orig_func = (orig_func_type) dlsym(RTLD_NEXT, "__libc_start_main");
//   sbrk(0x8000000); // works to shift the first allocation
  ret = orig_func(orig_main,argc,argv,
                  (fnptr_type)init_func,
                  (fnptr_type)fini_func,
                  rtld_fini_func,
                  stack_end); 
  return ret;
}                                                                 

void ocolos_env::get_dir_path(string data_path){
   ocolos_env::tmp_data_path        = data_path;

   ocolos_env::bolted_function_bin  = ocolos_env::tmp_data_path+"bolted_functions.bin";
   ocolos_env::call_sites_bin       = ocolos_env::tmp_data_path+"call_sites.bin";
   ocolos_env::v_table_bin          = ocolos_env::tmp_data_path+"v_table.bin";
   ocolos_env::unmoved_func_bin     = ocolos_env::tmp_data_path+"unmoved_func.bin";

   ocolos_env::debug_log            = ocolos_env::tmp_data_path+"machine_code.txt";
}

uint64_t convert_str_2_long(string str){
   uint64_t result = 0;
   for (unsigned i=0; i<str.size(); i++){
      if ((str[i]>='a')&&(str[i]<='f')){
         result += str[i] -'a'+10;
      }
      else if ((str[i]>='0')&&(str[i]<='9')){
         result += str[i] - '0';
      }
      if (i!=str.size()-1){
         result = result * 16;
      }
   }
   return result;
}



void print_err_and_exit(FILE* recordFile, string func, long addr=0, long len=0, long page=0){
   #ifdef DEBUG_INFO
   string command = "[tracee (lib)] "+func+" failed\n";
   fprintf(recordFile, "%s", command.c_str());
   fprintf(recordFile, "[tracee (lib)] error: %s\n", strerror(errno));
   fprintf(recordFile, "[tracee (lib)] target addr = 0x%lx, len=%ld, page_aligned=%lx\n", addr, len, page);
   fflush(recordFile);
   #endif	
   exit(-1);
}



void record_machine_code(FILE* recordFile, uint8_t* machine_code, unsigned int len){
   #ifdef DEBUG_INFO
   for (unsigned int i=0; i<len; i++){
      fprintf(recordFile,"%x\n", (int)machine_code[i]);
   }
   fprintf(recordFile,"\n\n");
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

void before_main(){
   // delete the ld_preload environment variable
   for (int i=0; environ[i] !=NULL; i++){
      if (strcmp(environ[i], LD_PRELOAD_PATH)==0){
         int err = unsetenv("LD_PRELOAD");
         if (err!=0){
            exit(-1);
         }
         break;
      }
   }	

   printf("\n[tracee (lib)] pid: %d, insert_machine_code: %p\n", getpid(), insert_machine_code);

   // 动态确认页大小
   // TODO：用户配置默认留空，如果用户主动配置，则校验
   // 校验成功则使用，校验失败后以环境配置为准并打印警告
   MMAP_PAGE_SIZE = sysconf(_SC_PAGESIZE);
   MMAP_PAGE_OFFSET = MMAP_PAGE_SIZE - 1;
   printf("[tracee (lib)] MMAP_PAGE_SIZE: %lx\n", MMAP_PAGE_SIZE);
}



void insert_BOLTed_function(FILE* pFile, FILE* recordFile, long base_n){
   printf("[tracee (lib)] insert_BOLTed_function\n");
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
         fprintf(recordFile, "[tracee (lib)] target addr = 0x%lx, len=%ld\n", address, len);
         fflush(recordFile);
         #endif

         // get the page aligned address of the function pointer
         void*	page_aligned_addr = (void*)((long)address & (~MMAP_PAGE_OFFSET));

         for (long offset = 0; offset<=address+len-(long)page_aligned_addr+MMAP_PAGE_SIZE; offset += MMAP_PAGE_SIZE){
            long new_addr = offset + (long)page_aligned_addr;
            if (allocated_pages.find(new_addr)==allocated_pages.end()){
               allocated_pages.insert(new_addr);
               void* ret = mmap((void*)new_addr, MMAP_PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC , MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE , 0, 0);	
               if (ret==MAP_FAILED) {
                  // 打印mmap入参和失败原因
                  fprintf(recordFile, "[tracee (lib)] mmap failed: %s, new_addr: %lx, MMAP_PAGE_SIZE: %lx\n", strerror(errno), new_addr, MMAP_PAGE_SIZE);
                  print_err_and_exit(recordFile, "mmap");
               }
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
      printf("[tracee (lib)] cannot open bolted_functions.bin\n");
      exit(-1);
   }
}



void insert_call_site(FILE* pFile, FILE* recordFile, long base_n){
   printf("[tracee (lib)] insert_call_site\n");
   print_func_name(recordFile, "call sites");
   unordered_set<long> allocated_pages;
   if (pFile!=NULL){
      insert_code_to_orig_text_sec(pFile, recordFile, base_n);
   }
   else{
      printf("[tracee (lib)] cannot open call_sites.bin\n");
      exit(-1);
   }
}



void insert_v_table(FILE* pFile, FILE* recordFile, long base_n){
   printf("[tracee (lib)] insert_v_table\n");
   print_func_name(recordFile, "vtable");
   unordered_set<long> allocated_pages;
   if (pFile!=NULL){
      insert_code_to_orig_text_sec(pFile, recordFile, base_n);
   }
   else{
      printf("[tracee (lib)] cannot open v_table.bin\n");
      exit(-1);
   }
   fflush(recordFile);
}



void insert_unmoved_func(FILE* pFile, FILE* recordFile, long base_n ){
   printf("[tracee (lib)] insert_unmoved_func\n");
   print_func_name(recordFile, "unmoved func");
   unordered_set<long> allocated_pages;	
   if (pFile!=NULL){
      insert_code_to_orig_text_sec(pFile, recordFile, base_n);
   }
   else{
      printf("[tracee (lib)] cannot open unmoved_functions.bin\n");
      exit(-1);
   }
}



void insert_machine_code(void){
   printf("[tracee (lib)] insert_machine_code\n");
   uint64_t base_n = 0;
   ocolos_env ocolos_environ;
   string data_path = "/data/wrf/ocolos_data/";
   ocolos_environ.get_dir_path(data_path);

   FILE *pFile, *pFile2, *pFile3, *pFile4, *recordFile;
   string cmd1 = "" + ocolos_environ.bolted_function_bin;
   string cmd2 = "" + ocolos_environ.call_sites_bin;
   string cmd3 = "" + ocolos_environ.v_table_bin;
   string cmd4 = "" + ocolos_environ.unmoved_func_bin;
   string cmd5 = "" + ocolos_environ.debug_log;

   pFile =  fopen(cmd1.c_str(),"r");
   pFile2 = fopen(cmd2.c_str(),"r");
   pFile3 = fopen(cmd3.c_str(),"r");
   pFile4 = fopen(cmd4.c_str(),"r");

   recordFile = fopen(cmd5.c_str(),"w");

   unordered_set<long> allocated_pages;

   if (recordFile !=NULL){	
      if (pFile!=NULL){
         insert_BOLTed_function(pFile, recordFile, base_n);
         fclose (pFile);
      }
      if (pFile2 != NULL){
         insert_call_site(pFile2, recordFile, base_n);
         fclose (pFile2);
      }
      if (pFile3 != NULL){
         insert_v_table(pFile3, recordFile, base_n);
         fclose (pFile3);
      }
      if (pFile4 !=NULL){		
         insert_unmoved_func(pFile4, recordFile, base_n);
         fclose (pFile4);
      }
   }
   fclose(recordFile);

   for (auto itr : allocated_pages){
      int err =  mprotect((void*)itr, MMAP_PAGE_SIZE, PROT_READ | PROT_EXEC);
      if (err<0) print_err_and_exit(recordFile, "mprotect", itr);
   }

   // 写入code_replacement_done到/data/wrf/ocolos_data/cmd.txt
   FILE *file = fopen("/data/wrf/ocolos_data/cmd.txt", "w");
   if (file) {
      fprintf(file, "code_replacement_done");
      fclose(file);
   } else {
      printf("[tracee (lib)] Failed to open cmd.txt\n");
   }

   printf("[tracee (lib)] insert_machine_code() is done\n");
   raise(SIGSTOP);	
}
