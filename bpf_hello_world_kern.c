#include <uapi/linux/bpf.h>
#define SEC(NAME) __attribute__((section(NAME), used))

/*
    编译命令：clang -O2 -v -target bpf -I /usr/src/linux-headers-$(uname -r)/include -c bpf_hello_world_kern.c -o bpf_hello_world_kern
*/

static int (*trace_printk)(const char *fmt, u32 fmt_size, ...) = (void *)BPF_FUNC_trace_printk;

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_hello_world(void *ctx)
{
    char msg[] = "Hello, BPF World";
    // 这里等价于直接调用 bpf_trace_printk(msg, sizeof(msg))
    trace_printk(msg, sizeof(msg));
    return 0;
}

char _license[] SEC("license") = "GPL";
