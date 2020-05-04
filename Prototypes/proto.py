#!/usr/bin/env python3

""" Work-in-Progress eBPF Flow Collecting Prototype """

# Imports #
from bcc import BPF, USDT
from enum import Enum
import argparse
import logging

# Global Variables #
# The actual BCC code itself
BPF_PROGRAM = r"""
int hello(void *ctx) 
{
  bpf_trace_printk("Hello world! File opened\n");
    return 0;
}
    """

# Header size enum class
class H_LEN(Enum):
    IP_ETH = 14
    VLAN_ETH= 4
    TCP = 20
    UDP = 8

# Main #
def main(args):
    # Logger stuff
    loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel, 
                        format="%(asctime)s - %(levelname)s - %(message)s")
    logger = logging.getLogger(__name__)

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

# Argparse and Main Call #
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, type=str,
                        help="Specify which network interface to listen for packets on")
    parser.add_argument("-d", "--debug", required=False, action="store_true",
                        help="Allow debug logging")
    args = parser.parse_args()
    main(args)
