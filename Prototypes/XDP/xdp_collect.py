#!/usr/bin/env python3

""" Work-in-Progress eBPF Flow Collecting Prototype """
# Requirements:
#   1. Network Driver of the following devices:
#       a. bnxt
#       b. thunder
#       c. i40e
#       d. ixgbe
#       e. mlx4/mlx5
#       f. nfp
#       g. qede
#       h. tun
#       i. virtio_net

# Imports #
import bcc
from bcc import BPF
from enum import Enum
import ctypes
import argparse
import logging
import os

# Global Variables #

MAX_BUFFER = 2048
ETH_IP = 14
ETH_VLAN = 4
TCP = 20
UDP = 8

# Main #
def main(args):
    # Logger stuff
    loglevel = logging.INFO
    if args.debug:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel, 
                        format="[%(levelname)s] %(name)s : %(message)s")
    logger = logging.getLogger(__name__)

    # Retrieve user arguments
    IF = args.interface
    logger.info("Using interface %s" % IF)

    # Compile and load the required source C file
    logger.debug("Loading xdp_collect.c...")
    bpf = BPF(src_file="xdp_collect.c", debug=bcc.DEBUG_SOURCE)

    # Get the main function
    logger.debug("Loading function xdp_parser()...")
    fn = bpf.load_func("xdp_parser", BPF.XDP)
    logger.debug("Attaching xdp_parser() to kernel hook...")
    bpf.attach_xdp(IF, fn, 0)

    #bpf['counters'][ctypes.c_int(RESULTS_IDX)] = ctypes.c_int(0)

    # Set up jump tables for protocol parsing
    for i, fn in [(4, "parse_ipv4"), (6, "parse_ipv6")]:
        _set_bpf_jumptable(bpf, "parse_layer3", i, fn, BPF.XDP)

    # Main flow collecting segment
    while True:
        logger.warn("HI")
        try:
            (_, _, _, _, _, msg) = bpf.trace_fields()
            msg = msg.decode('utf8')
            if "hi" in msg:
                print(msg)
        except ValueError:
            continue
        except KeyboardInterrupt:
            break

# Credit to Joel Sommers
def _set_bpf_jumptable(bpf, tablename, idx, fnname, progtype):
    '''
    (bccobj, str, int, str, int) -> None
    Set up one entry in a bpf jump table to enable chaining
    bpf function calls.
    '''
    tail_fn = bpf.load_func(fnname, progtype)
    prog_array = bpf.get_table(tablename)
    prog_array[ctypes.c_int(idx)] = ctypes.c_int(tail_fn.fd)

# Argparse and Main Call #
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, type=str,
                        help="Specify which network interface to listen for packets on")
    parser.add_argument("-d", "--debug", default=False, required=False, action="store_true",
                        help="Allow debug logging")
    args = parser.parse_args()
    main(args)
