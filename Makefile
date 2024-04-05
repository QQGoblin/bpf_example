CLANG ?= clang
WORKSPACE := /home/yoaz/projects/bpf_example
LIBBPF_OBJ := $(WORKSPACE)/libbpf/lib64/libbpf.a
LIBBPF_LIB := -L$(WORKSPACE)/libbpf/lib64
INCLUDES := -I$(WORKSPACE)/libbpf/include -I$(WORKSPACE)/linux-headers/include -I$(WORKSPACE)/src
CFLAGS := -g -Wall
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
OUTPUT := perf_event_out


.PHONY: all
all: clean build

build:
	$(CLANG) $(CFLAGS) -o ${OUTPUT}.o $(INCLUDES) -c src/perf_event_out_user.c
	$(CLANG) $(CFLAGS) -lelf -lz -o ${OUTPUT} ${OUTPUT}.o $(LIBBPF_OBJ) 

clean:
	rm -rf $(OUTPUT) $(OUTPUT).o