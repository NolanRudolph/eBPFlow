#!/usr/bin/env python3

# Learning basic functionality of python3-bcc

# Used to import class required to create BPF object
from bcc import BPF

# The actual BCC code itself
# bpf_trace_printk is an example of a BPF helper - many more are provided
#     - Allows printing to trace pipe @ /sys/kernel/debug/tracing/trace_pipe
BPF_PROGRAM = r"""
int hello(void *ctx) 
{
  bpf_trace_printk("Hello world! File opened\n");
    return 0;
}
    """

# BPF initialization
bpf = BPF(text=BPF_PROGRAM)  # Compile and execute BPF program
bpf.attach_kprobe(event=bpf.get_syscall_fnname("clone"), fn_name="hello")

while True:
    try:
        (_, _, _, _, _, msg_b) = bpf.trace_fields()
        msg = msg_b.decode('utf8')
        if "Hello world" in msg:
            print(msg)
    except ValueError:
        continue
    except KeyboardInterrupt:
        break
