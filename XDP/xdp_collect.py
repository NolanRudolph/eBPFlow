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
import ctypes, struct
import argparse, logging
import os, sys, time
from socket import inet_ntoa, ntohl, ntohs
import ipaddress

# Global Variables #

MAX_BUFFER = 2048
ETH_IP = 14
ETH_VLAN = 4
TCP = 20
UDP = 8
CPU_COUNT = os.cpu_count()

# Main #
def main(args):
    # User argument handling
    loglevel = logging.INFO
    run_time = 5
    agg_time = 60
    out_file = "flows.csv"
    if args.debug:
        loglevel = logging.DEBUG
    if args.time:
        run_time = args.time
    if args.output:
        out_file = args.output
    if args.aggregate:
        agg_time = args.aggregate
    agg_time *= 1e9

    # Logger stuff
    logging.basicConfig(level=loglevel, 
                        format="[%(levelname)s] %(name)s : %(message)s")
    logger = logging.getLogger(__name__)

    # Retrieve user arguments
    IF = args.interface
    logger.info("Using interface %s" % IF)

    # CFlags for eBPF compile
    _cflags = []
    _cflags.append("-DAGG=" + str(agg_time))

    # Compile and load the required source C file
    logger.debug("Loading xdp_collect.c...")
    bpf = BPF(src_file="xdp_collect.c", \
              cflags=_cflags, \
              debug=bcc.DEBUG_SOURCE | bcc.DEBUG_BPF)

    # Get the main function
    logger.debug("Loading function xdp_parser()...")
    fn = bpf.load_func("xdp_parser", BPF.XDP)
    logger.debug("Attaching xdp_parser() to kernel hook...")
    bpf.attach_xdp(IF, fn, 0)

    # Set up jump tables for protocol parsing
    for i, fn in [(4, "parse_ipv4"), (6, "parse_ipv6")]:
        _set_bpf_jumptable(bpf, "parse_layer3", i, fn, BPF.XDP)

    logger.info("*** COLLECTING FOR %ss ***" % run_time)

    time_table = bpf.get_table("start_time")

    # Main flow collecting segment (Basically sleep, but time.sleep() is janky)
    begin = time.time()
    while abs(time.time() - begin) < run_time:
        logger.debug("*** COLLECTING FOR %ss ***" % run_time)

    # Retrieve the main table that is saturated by xdp_collect.c
    flows = bpf.get_table("flows")
    capture_start = time_table[0].value

    try:
        # File to write to
        f = open(out_file, "w+")
        
        # Retrive individual items as list
        all_flows = flows.items()
        all_vals = flows.values()
        all_flows_len = len(all_flows)

        logger.debug("START, END, SOURCE IP, DEST IP,S_PORT, D_PORT, E_TYPE, PROTO, #PACKETS, #BYTES")
        f.write("START, END, SRC IP, DST IP, SRC PORT, DST PORT, ETHER TYPE, PROTO, #PACKETS, #BYTES\n")

        # This set will hold all flows to sort
        flow_set = set()

        # Writing to CSV + Debugging
        for i in range(0, all_flows_len):
            # Key: Attributes | Val: Accumulators
            attrs = all_flows[i][0]
            accms = all_flows[i][1]

            # Get accumulation variables over all CPUs
            n_packets = 0
            n_bytes = 0
            start = 0
            end = 0
            for j in range(0, CPU_COUNT):
                n_packets += all_flows[i][1][j].packets
                n_bytes += all_flows[i][1][j].bytes
                if all_flows[i][1][j].start != 0:
                    start = (all_flows[i][1][j].start - capture_start) / 1e9
                if all_flows[i][1][j].end != 0:
                    end = (all_flows[i][1][j].end - capture_start) / 1e9

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

            logger.debug("New Flow: {}, {}, {}, {}, {}, {}, {}, {}, {}, {}" \
                   .format(start, end, src_ip, dst_ip, src_p, dst_p, hex(l2_proto), \
                           l4_proto, n_packets, n_bytes))
            flow_set.add("{},{},{},{},{},{},{},{},{},{}\n"\
                      .format(start, end, src_ip, dst_ip, src_p, dst_p, hex(l2_proto), \
                              l4_proto, n_packets, n_bytes))
    finally:
        bpf.remove_xdp(IF, 0)
        f.close()
        logger.info("Removed XDP Program from Kernel.")

    # Final touch ups to CSV
    s_flow_set = sorted(flow_set)
    f.close()

    f = open(out_file, "r+")
    for entry in s_flow_set:
        print(entry.strip())
        f.write(entry)

    f.close()


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
                        help="Specify which interface to listen for packets on")
    parser.add_argument("-t", "--time", default=5, required=False, type=int, 
                        help="Time to run (s) [default = 5]")
    parser.add_argument("-a", "--aggregate", default=60, required=False, type=int,
                        help="Aggregation time (s) to close flows [default = 60]")
    parser.add_argument("-o", "--output", default="flows.csv", required=False, type=str,
                        help="Name of file to output flows in CSV format")
    parser.add_argument("-d", "--debug", default=False, required=False, action="store_true",
                        help="Allow debug logging")
    args = parser.parse_args()
    main(args)
