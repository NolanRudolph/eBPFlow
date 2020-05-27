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
from socket import inet_ntoa, ntohl, ntohs
import struct
import ipaddress

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

    # Main flow collecting segment (Basically sleep, but time.sleep() is janky)
    while abs(time.time() - begin) < run_time:
        logger.info("*** COLLECTING FOR %ss ***" % run_time)

    # Retrieve the main table that is saturated by xdp_collect.c
    flows = bpf.get_table("flows")

    try:
        # File to write to
        f = open(out_file, "w+")
        
        # Retrive individual items as list
        all_flows = flows.items()
        all_flows_len = len(all_flows)

        logger.debug("SOURCE IP, DEST IP,  S_PORT, D_PORT, E_TYPE, PROTO, #PACKETS, #BYTES")
        f.write("SRC IP, DST IP, SRC PORT, DST PORT, ETHER TYPE, PROTO, #PACKETS, #BYTES\n")

        # Writing to CSV + Debugging
        for i in range(0, all_flows_len):
            # Key: Attributes | Val: Accumulators
            attrs = all_flows[i][0]
            accms = all_flows[i][1]

            l2_proto = attrs.l2_proto
            l4_proto = attrs.l4_proto
            src_ip = ""
            dst_ip = ""

            # Parse IP addresses according to ethertype (EIP4 / EIP6)
            if l2_proto == 0x0800:
                src_ip = ipaddress.ip_address(ntohl(attrs.src_ip))
                dst_ip = ipaddress.ip_address(ntohl(attrs.dst_ip))
            elif l2_proto == 0x8100:
                src_ip = ipaddress.ipv6_address(ntohl(attrs.src_ip))
                dst_ip = ipaddress.ipv6_address(ntohl(attrs.dst_ip))

            # Port requires little endian conversion
            src_p = ntohs(attrs.src_port)
            dst_p = ntohs(attrs.dst_port)

            n_packets = accms.packets
            n_bytes = accms.bytes

            logger.debug("New Flow: {}, {}, {}, {}, {}, {}, {}, {}" \
                   .format(src_ip, dst_ip, src_p, dst_p, hex(l2_proto), \
                           l4_proto, n_packets, n_bytes))
            f.write("{},{},{},{},{},{},{},{}\n"\
              .format(src_ip, dst_ip, src_p, dst_p, hex(l2_proto), \
                      l4_proto, n_packets, n_bytes))
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
