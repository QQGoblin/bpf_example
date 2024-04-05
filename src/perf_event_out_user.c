#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "perf_event_out_kern.skel.h"
#include "perf_event_out.h"

static volatile int exiting = false;
static void sig_handler(int sig)
{
    exiting = true;
}

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    /* Ignore debug-level libbpf logs */
    if (level > LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-8s %-5s %-7d %-16s\n", ts, "EXEC", e->pid, e->comm);
}

int main(int argc, char **argv)
{

    /* 加载 bpf 程序 */
    libbpf_set_print(libbpf_print_fn);
    struct perf_event_out_kern *skel;
    skel = perf_event_out_kern__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    if (perf_event_out_kern__attach(skel) != 0)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* 注册退出信号 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 创建 perf buffer */
    int err;
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb = NULL;
    pb_opts.sample_cb = handle_event;                                                      // 注册处理函数
    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8 /* 32KB per CPU */, &pb_opts); // 这里从 skel 处获取 perf 队列的句柄
    if (libbpf_get_error(pb))
    {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    /* 开始从 perf buffer 读取数据 */
    printf("%-8s %-5s %-7s %-16s\n", "TIME", "EVENT", "PID", "COMM");
    while (!exiting)
    {
        err = perf_buffer__poll(pb, 100);
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_event_out_kern__destroy(skel);
}