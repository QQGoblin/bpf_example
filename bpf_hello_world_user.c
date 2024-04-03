#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <uapi/linux/bpf.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

/*
    编译命令：clang -v -o bpf_hello_world_user \
    -I /usr/src/linux-headers-$(uname -r)/include \
    -I /usr/src/linux-headers-$(uname -r)/arch/x86/include/ \
    -I /home/yoaz/projects/linux-5.15.153/tools/lib \
    bpf_hello_world_user.c 
*/

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(int argc, char **argv)
{


    char *filename = "bpf_hello_world_kern";
    struct bpf_link *links;
    struct bpf_object *objs;
    struct bpf_program *prog;

    objs = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(objs))
    {
        fprintf(stderr, "opening BPF object file failed\n");
        objs = NULL;
        goto cleanup;
    }

    /* load BPF program */
    if (bpf_object__load(objs))
    {
        fprintf(stderr, "loading BPF object file failed\n");
        goto cleanup;
    }

    bpf_object__for_each_program(prog, objs);
    {
        links = bpf_program__attach(prog);
        if (libbpf_get_error(links))
        {
            fprintf(stderr, "bpf_program__attach failed\n");
            links = NULL;
            goto cleanup;
        }
    }

    read_trace_pipe();

cleanup:
    bpf_link__destroy(links);
    bpf_object__close(objs);
    return 0;
}