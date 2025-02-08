#!/bin/bash

export OCOLOS_PATH=/home/wrf/codes/ocolos-public-aarch64

# 配置config

tmp_data_dir=$(grep -E '^tmp_data_dir=' "config" | sed 's/^tmp_data_dir=//;s/[[:space:]]*$//')
cd $OCOLOS_PATH
if [ ! -e $tmp_data_dir/call_sites_list.bin ] || [ ! -e $tmp_data_dir/call_sites_all.bin ];then
    ./extract_call_sites
fi

pkill mysqld
LD_PRELOAD=$OCOLOS_PATH/replace_function.so numactl -C 88-95 /home/wrf/install/mysql-8.0.25_Wlq_nojt_nopie/bin/mysqld --defaults-file=/home/wrf/scripts/test/mysql/sysbench/my.cnf.8u32g &
# wait
# 预热+测试
numactl -C 64-87 /usr/local/bin/sysbench /usr/local/share/sysbench/oltp_read_only.lua --mysql-host=192.168.1.10 --mysql-port=3306 --mysql-user=root --mysql-password=123456 --mysql-db=sysbench --tables=64 --table_size=10000000 --time=180 --report-interval=10 --threads=32 run
# 基线：4249.20

./tracer
# 预热+测试
numactl -C 64-87 /usr/local/bin/sysbench /usr/local/share/sysbench/oltp_read_only.lua --mysql-host=192.168.1.10 --mysql-port=3306 --mysql-user=root --mysql-password=123456 --mysql-db=sysbench --tables=64 --table_size=10000000 --time=180 --report-interval=10 --threads=32 run
# 动态优化后：5138.75


info function insert_BOLTed_function
b insert_BOLTed_function