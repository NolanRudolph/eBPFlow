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
from bcc import BPF
from enum import Enum
import argparse
import logging
import os
from socket import *

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
    bpf = BPF(src_file="xdp_collect.c");

    # Get the main function
    logger.debug("Loading function xdp_parser()...")
    fn = bpf.load_func("xdp_parse", BPF.XDP)
    logger.debug("Attaching xdp_parser() to kernel hook...")
    bpf.attach_xdp(IF, fn, 0)

    # Main flow collecting segment
    while True:
        logger.info("Running :)");

def byte_array_to_ipv4(byte_array):
    assert len(byte_array) == 4, "Cannot convert incompatible array to IPv4"
    ipv4 = ""
    for byte in byte_array:
        if ipv4 == "":
            ipv4 += str(byte)
        else:
            ipv4 += "." + str(byte)

    return ipv4

def byte_array_to_ipv6(byte_array):
    assert len(byte_array) == 16, "Cannot convert incompatible array to IPv6"
    ipv6 = ""
    i = 0
    trunc = False
    for byte in src_bytes:
        if i % 2 == 0:
            byte <<= 8

        if byte == 0:
            trunc = True
        elif byte < 0x10:
            byte = str(byte).replace('0', '')
            if trunc:
                src_ip += "::" + byte
            else:
                src_ip += ":" + byte
            trunc = False
        else:
            if trunc:
                src_ip += "::" + str(byte)
            else:
                src_ip += ":" + str(byte)
            trunc = False

        i += 1 


# Argparse and Main Call #
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, type=str,
                        help="Specify which network interface to listen for packets on")
    parser.add_argument("-d", "--debug", default=False, required=False, action="store_true",
                        help="Allow debug logging")
    args = parser.parse_args()
    main(args)
