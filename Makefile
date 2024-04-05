CLANG ?= clang
LIBBPF_OBJ := $(CURDIR)/libbpf/lib64/libbpf.a
LIBBPF_LIB := -L$(CURDIR)/libbpf/lib64
INCLUDES := -I$(CURDIR)/libbpf/include -I$(CURDIR)/linux-headers/include -I$(CURDIR)/src
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