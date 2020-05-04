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

    ni.ifaddresses(args.interface)
    try:
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    except:
        ip = "127.0.0.1"
    while True:
        # Retrieve packet
        packet = os.read(socket_fd, MAX_BUFFER)
        packet_bytes = bytearray(packet)

        # Ethernet Type - https://en.wikipedia.org/wiki/Ethernet_frame
        ethertype = packet_bytes[H_LEN.IP_ETH.value - 2]
        if ethertype == 0x0800:
            logger.info("Got a normal packet.")
        elif ethertype == 0x8100:
            logger.info("Got a VLAN packet.")
        else:
            logger.info("Got some packet?")


# Argparse and Main Call #
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", required=True, type=str,
                        help="Specify which network interface to listen for packets on")
    parser.add_argument("-d", "--debug", default=False, required=False, action="store_true",
                        help="Allow debug logging")
    args = parser.parse_args()
    main(args)
