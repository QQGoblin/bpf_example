#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

void read_trace_pipe(void)
{
    int trace_fd;

    trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
    if (trace_fd < 0)
        return;

    while (1)
    {
        static char buf[4096];
        ssize_t sz;

        sz = read(trace_fd, buf, sizeof(buf) - 1);
        if (sz > 0)
        {
            buf[sz] = 0;
            puts(buf);
        }
    }
}

int main(int argc, char **argv)
{

    char *filename = "bpf_hello_world_kern";
    char *progname = "bpf_hello_world";
    struct bpf_link *link;
    struct bpf_object *obj;
    struct bpf_program *prog;

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj))
    {
        fprintf(stderr, "opening BPF object file failed\n");
        obj = NULL;
        goto cleanup;
    }

    /* load BPF program */
    if (bpf_object__load(obj))
    {
        fprintf(stderr, "loading BPF object file failed\n");
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, progname);
    if (!prog)
    {
        fprintf(stderr, "loading BPF program failed\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (libbpf_get_error(link))
    {
        fprintf(stderr, "bpf_program__attach failed\n");
        link = NULL;
        goto cleanup;
    }

    read_trace_pipe();

cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}