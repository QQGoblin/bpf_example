#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <perf_event_out.h>
#include <bpf/bpf_core_read.h>

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
    clang -v -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -o perf_event_out_kern.o -I../libbpf/include -I../linux-headers/include -I. -c perf_event_out_kern.c
*/
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{

    u64 id;
    pid_t pid, tgid;
    struct event event = {0};
    struct task_struct *task;

    uid_t uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    event.pid = tgid;
    event.uid = uid;
    task = (struct task_struct *)bpf_get_current_task();

    // 等价于：
    // event.ppid = task->real_parent->tgid;
    // char *cmd_ptr=(char *)(ctx->args[0]);
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    char *cmd_ptr = (char *)BPF_CORE_READ(ctx, args[0]);

    // bpf_probe_read_str 作用时将 cmd_ptr 地址的内容拷贝到 event.comm 中
    bpf_probe_read_str(&event.comm, sizeof(event.comm), cmd_ptr);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";