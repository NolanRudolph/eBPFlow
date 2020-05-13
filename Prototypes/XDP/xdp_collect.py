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
import time
from socket import inet_ntoa
import struct

# Global Variables #

MAX_BUFFER = 2048
ETH_IP = 14
ETH_VLAN = 4
TCP = 20
UDP = 8

# Main #
def main(args):
    begin = time.time()

    # User argument handling
    loglevel = logging.INFO
    run_time = 5
    out_file = "flows.csv"
    if args.debug:
        loglevel = logging.DEBUG
    if args.time:
        run_time = args.time
    if args.output:
        out_file = args.output

    # Logger stuff
    logging.basicConfig(level=loglevel, 
                        format="[%(levelname)s] %(name)s : %(message)s")
    logger = logging.getLogger(__name__)

    # Retrieve user arguments
    IF = args.interface
    logger.info("Using interface %s" % IF)

    # Compile and load the required source C file
    logger.debug("Loading xdp_collect.c...")
    bpf = BPF(src_file="xdp_collect.c", debug=bcc.DEBUG_BPF_REGISTER_STATE | bcc.DEBUG_SOURCE | bcc.DEBUG_BPF)

    # Get the main function
    logger.debug("Loading function xdp_parser()...")
    fn = bpf.load_func("xdp_parser", BPF.XDP)
    logger.debug("Attaching xdp_parser() to kernel hook...")
    bpf.attach_xdp(IF, fn, 0)

    # Set up jump tables for protocol parsing
    for i, fn in [(4, "parse_ipv4"), (6, "parse_ipv6")]:
        _set_bpf_jumptable(bpf, "parse_layer3", i, fn, BPF.XDP)

    # Main flow collecting segment
    while abs(time.time() - begin) < run_time:
        print("*** COLLECTING ***")

    # Retrieve the main table that is saturated by xdp_collect.c
    flows = bpf.get_table("flows")

    f = open(out_file, "w+")
    try:
        all_flows = flows.items()
        all_flows_len = len(all_flows)
        logger.info("SOURCE IP, DEST IP,  S_PORT, D_PORT, E_TYPE, PROTO")
        f.write("SRC IP, DST IP, SRC PORT, DST PORT, ETHER TYPE, PROTO\n")
        for i in range(0, all_flows_len):
            cur_flow = all_flows[i][1]
            src_ip = inet_ntoa(struct.pack('!L', cur_flow.src_ip))
            dst_ip = inet_ntoa(struct.pack('!L', cur_flow.dst_ip))
            src_p  = cur_flow.src_port
            dst_p  = cur_flow.dst_port
            proto1 = cur_flow.l2_proto
            proto2 = cur_flow.l4_proto
            logger.info("New Flow: {}, {}, {}, {}, {}, {}".format(src_ip, dst_ip, src_p, dst_p, proto1, proto2))
            f.write("{},{},{},{},{},{}\n".format(src_ip, dst_ip, src_p, dst_p, proto1, proto2))
    except ValueError:
        logger.error("VALUE ERROR")

    bpf.remove_xdp(IF, 0)
    logger.info("Removed XDP Program from Kernel.")

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
    parser.add_argument("-t", "--time", default=5, required=False, type=int, 
                        help="Time to run in seconds (default = 5)")
    parser.add_argument("-o", "--output", default="flows.csv", required=False, type=str,
                        help="Name of file to output flows in CSV format")
    args = parser.parse_args()
    main(args)
