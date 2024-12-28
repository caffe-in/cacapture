APPS = socket
SRC_DIR = kern
.PHONY: all
all: $(APPS)

# $(APPS):
# 	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c $(SRC_DIR)/$@.bpf.c -o $(SRC_DIR)/$@.o
main: $(SRC_DIR)/main.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c $(SRC_DIR)/main.bpf.c -o $(SRC_DIR)/main.o

tc:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c $(SRC_DIR)/tc.bpf.c -o $(SRC_DIR)/tc.o
socket:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c $(SRC_DIR)/socket.bpf.c -o $(SRC_DIR)/socket.o

syscall:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c $(SRC_DIR)/syscall.bpf.c -o $(SRC_DIR)/syscall.o
container_states:
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c $(SRC_DIR)/container_states.bpf.c -o $(SRC_DIR)/container_states.o
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(SRC_DIR)/vmlinux.h

asset-main:
	mv kern/main.o user/bytecode/main.o
	rm assets/ebpf_probe.go
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" "user/bytecode/main.o"
asset-tc:
	cp kern/tc.o user/bytecode/tc.o
	rm assets/ebpf_probe.go
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" "user/bytecode/tc.o"
asset-socket:
	cp kern/socket.o user/bytecode/socket.o
	rm assets/ebpf_probe.go
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" "user/bytecode/socket.o"
asset-syscall:
	cp kern/syscall.o user/bytecode/syscall.o
	rm assets/ebpf_probe.go
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" "user/bytecode/syscall.o"
asset-container_states:
	cp kern/container_states.o user/bytecode/container_states.o
	rm assets/ebpf_probe.go
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" "user/bytecode/container_states.o" "user/bytecode/tc.o"