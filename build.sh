#!/bin/bash
# build_and_move.sh - 自动构建和移动文件的脚本

echo "开始构建过程..."
sudo make all

echo "移动生成的文件..."
sudo mv kern/tc.o user/bytecode/

echo "生成 asset..."
sudo rm assets/ebpf_probe.go
sudo make asset

echo "编译 Go 程序..."
sudo go build -o .

echo "所有操作完成！"
