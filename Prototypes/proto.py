#!/usr/bin/env python3

""" Work-in-Progress eBPF Flow Collecting Prototype """

# Imports #
from bcc import BPF, USDT
from enum import Enum
import argparse
import logging
import os
from socket import *
import netifaces as ni

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

    # Create BPF object
    logger.debug("Creating BPF Object...")

    # Compile and load the required source C file
    logger.debug("Loading proto.c...")
    bpf = BPF(src_file="proto.c");

    # Assign filtration function to specified interface
    logger.info("Binding flow collector to interface \"%s\"" % args.interface)
    filter_func = bpf.load_func("filter", BPF.SOCKET_FILTER);
    bpf.attach_raw_socket(filter_func, args.interface)

    # Use Python Sockets to create new socket object from respective file descriptor
    logger.debug("Generating Python socket for incoming messages...")
    socket_fd = filter_func.sock
    sock = fromfd(socket_fd, PF_PACKET, SOCK_RAW, IPPROTO_IP)

    # Set as blocking to record all flows
    sock.setblocking(True)

    while True:
        # Retrieve packet
        packet = os.read(socket_fd, MAX_BUFFER)
        packet_bytes = bytearray(packet)

        # Initialize packet variables
        ethertype = ""
        protocol = 0
        payload_len = 0

        # Ethernet Type - https://en.wikipedia.org/wiki/Ethernet_frame
        ethertype_hex = (packet_bytes[ETH_IP - 2] << 8) + packet_bytes[ETH_IP - 1]
        if ethertype_hex == 0x0800:
            ethertype = "IPv4"
            logger.debug("Received an IPv4 packet.")
        elif ethertype_hex == 0x86DD:
            ethertype = "IPv6"
            logger.debug("Received an IPv6 packet.")
        else:
            ethertype = "VLAN"
            logger.debug("Received a VLAN packet.")


        if ethertype == "IPv4":
            payload_len = (packet_bytes[ETH_IP + 2] << 8) + packet_bytes[ETH_IP + 3]
            logger.debug("Payload Length: %s" % str(payload_len))
        elif ethertype == "IPv6":
            payload_len = (packet_bytes[ETH_IP + 4] << 8) + packet_bytes[ETH_IP + 5]
            pass
            # ip_length = packet_bytes[ETH_IP + 
            # Do this
        else:
            pass
            # idk


# Argparse and Main Call #
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, type=str,
                        help="Specify which network interface to listen for packets on")
    parser.add_argument("-d", "--debug", default=False, required=False, action="store_true",
                        help="Allow debug logging")
    args = parser.parse_args()
    main(args)
