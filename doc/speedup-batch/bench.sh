#!/bin/bash

output_file=$1
cur_dir=$(pwd)

cd ../../
echo "HEAD: $(git rev-parse --short HEAD)" > "$cur_dir/$output_file.log"
make clean
./autogen.sh
./configure --enable-experimental --enable-module-schnorrsig >> "$cur_dir/$output_file.log"
make -j
./bench_schnorrsig > "$cur_dir/$output_file"

