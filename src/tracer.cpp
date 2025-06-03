#include "infrastructure.hpp"
#include "extract_machine_code.hpp"
#include "ptrace_pause.hpp"

using namespace std;

int main(){
   ocolos_env ocolos_environ;
   void* lib_addr;

   // 删除/data/wrf/ocolos_data/target.txt
   // system("rm -rf /data/wrf/ocolos_data/target.txt");

   pid_t target_pid = 0;
   // pid_t target_pid = fork();
   // if (target_pid == 0){
   //    char* ld_pre = "LD_PRELOAD=/home/wrf/codes/ocolos-public-aarch64/replace_function.so";
   //    string exe_cmd = ocolos_environ.run_server_cmd;
   //    char** argv = split_str_2_char_array(exe_cmd);
   //    putenv(ld_pre);
   //    char **envp = environ;
   //    execve(argv[0], argv, envp);
   // } else {
   // sleep(10);
   // 轮询/data/wrf/ocolos_data/target.txt，如果存在且有内容，则读取内容，否则等待1s后继续轮询
   while (true) {
      FILE *file = fopen("/data/wrf/ocolos_data/target.txt", "r");
      if (file) {
         fscanf(file, "%lx %d", &lib_addr, &target_pid);
         fclose(file);
         break;
      }
      sleep(1);
   }

      // sample + perf2bolt + llvm-bolt
      unordered_map<long, func_info> bolted_func = run_llvmbolt(&ocolos_environ);

      // get all functions that have location changed		
      unordered_map<long, func_info> func_with_addr = get_func_with_original_addr(&ocolos_environ);
      unordered_map<long, func_info> unmoved_func = get_unmoved_func(func_with_addr, bolted_func);	
      map<long, func_info> func_heap = change_func_to_heap(func_with_addr);
      unordered_map<string, string> v_table = get_v_table(&ocolos_environ);

      // delete the old binary files for code replacement
      // create the num files for code replecement before pausing 
      // the target process 
      string delete_all_bin = "rm -rf "+
                              ocolos_environ.bolted_function_bin+" "+
                              ocolos_environ.v_table_bin+" "+
                              ocolos_environ.call_sites_bin+" "+
                              ocolos_environ.unmoved_func_bin;
      if (system(delete_all_bin.c_str())==-1) exit(-1);

      FILE *pFile1;
      pFile1 = fopen(ocolos_environ.call_sites_bin.c_str(), "a");

      vector<long> addr_bolted_func = get_moved_addr_to_array(bolted_func);
      write_functions ( ocolos_environ.bolted_binary_path.c_str(), 
                        ocolos_environ.bolted_function_bin.c_str(), 
                        addr_bolted_func.data(), 
                        addr_bolted_func.size() );

      write_vtable(ocolos_environ.bolted_binary_path.c_str(), 
                   ocolos_environ.v_table_bin.c_str() );

      // <starting address, call_sites_info>
      unordered_map<long, call_site_info> call_sites;
      ifstream filestream(ocolos_environ.call_sites_all_bin);
      boost::archive::binary_iarchive archive(filestream);
      archive >> call_sites;

      // <target address, caller inst addresses>
      unordered_map<long, vector<long> > call_sites_list;
      ifstream filestream1(ocolos_environ.call_sites_list_bin);
      boost::archive::binary_iarchive archive1(filestream1);
      archive1 >> call_sites_list;

    
      #ifdef TIME_MEASUREMENT
      auto begin = std::chrono::high_resolution_clock::now();
      #endif

      // to pause all running threads of the target process
      // and then get the PIDs(tid) of these threads
      vector<pid_t> tids = pause_and_get_tids(target_pid);
      for (auto tid : tids) {
         printf("[tracer] tid: %d\n", tid);
      }

      // unwind call stack and get the functions
      // in the call stacks of each threads
      vector<unw_word_t> call_stack_ips = unwind_call_stack(tids);
      unordered_map<long, func_info> func_in_call_stack =  get_func_in_call_stack(call_stack_ips, func_heap);
      unordered_map<long, func_info> unmoved_func_not_in_call_stack = get_unmoved_func_not_in_call_stack(func_in_call_stack, unmoved_func);

      // for continuous optimization
      write_func_on_call_stack_into_file(&ocolos_environ, func_in_call_stack);   

      // extract the machine code of each function
      // from the output of objdump
      vector<long> addr_unmoved_func_not_in_call_stack = get_keys_to_array(unmoved_func_not_in_call_stack); 
      
      inlined_extract_call_sites(pFile1, bolted_func, func_in_call_stack, call_sites, call_sites_list,&ocolos_environ);
		
      write_functions(ocolos_environ.bolted_binary_path.c_str(), ocolos_environ.unmoved_func_bin.c_str(), addr_unmoved_func_not_in_call_stack.data(), addr_unmoved_func_not_in_call_stack.size());
	

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
      vector<pid_t> tids_have_code_insertion;
#ifdef Intel64
      for (unsigned i=0; i<tids.size(); i++){
         if(!ptrace_single_step_intel64(tids[i], lib_addr, regs, old_regs, fregs)){
            continue;
         }
         ptrace_cont_intel64(tids[i], regs, old_regs, fregs);
         break;			
      }
#endif
#ifdef AArch64
      for (unsigned i=0; i<tids.size(); i++){
         printf("[tracer] tid: %d, ptrace_single_step_aarch64\n", tids[i]);
         if(!ptrace_single_step_aarch64(tids[i], lib_addr, regs, old_regs, fregs)){
            continue;
         }
         printf("[tracer] tid: %d, ptrace_cont_aarch64\n", tids[i]);
         ptrace_cont_aarch64(tids[i], regs, old_regs, fregs);
         break;
      }
#endif

      #ifdef DEBUG	
      // deliver a SIGSTOP signal to target process. 
      // before resume the target process, so that 
      // we can attach GDB to target process later on.
      for (unsigned i=0; i<tids.size(); i++){
         int rc = syscall(SYS_tgkill, tids[0], tids[i], SIGSTOP);	
      }
      #endif


      // ptrace detach all threads of the
      // target process
      for (unsigned i=0; i<tids.size(); i++){
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

      // 轮询/data/wrf/ocolos_data/cmd.txt，如果存在且有内容，则读取内容，否则等待1s后继续轮询
   while (true) {
      FILE *file = fopen("/data/wrf/ocolos_data/cmd.txt", "r");
      if (file) {
         char cmd[1024];
         fscanf(file, "%s", cmd);
         fclose(file);
         if (strcmp(cmd, "code_replacement_done") == 0) {
            break;
         }
      }
      sleep(1);
   }
     
      printf("[tracer][OK] code replacement done!\n");
      #ifdef DEBUG
      while(true);
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
      run_perf_record(target_pid, &ocolos_environ);
      #endif
   // }
}



