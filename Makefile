APPS = tc
SRC_DIR = kern
.PHONY: all
all: $(APPS)

$(APPS):
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I/usr/include/x86_64-linux-gnu -I. -c $(SRC_DIR)/$@.bpf.c -o $(SRC_DIR)/$@.o

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(SRC_DIR)/vmlinux.h
asset:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "assets/ebpf_probe.go" "kern/tc.o"