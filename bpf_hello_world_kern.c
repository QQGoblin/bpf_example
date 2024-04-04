#include <vmlinux.h>
#define SEC(NAME) __attribute__((section(NAME), used))

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
