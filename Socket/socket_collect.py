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
    logger.debug("Loading socket_collect.c...")
    bpf = BPF(src_file="socket_collect.c");

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

    # Main flow collecting segment
    while True:
        # Retrieve packet
        packet = os.read(socket_fd, MAX_BUFFER)
        packet_bytes = bytes(packet)

        # Initialize packet variables
        ethertype = ""
        protocol = 0
        payload_len = 0
        src_ip = ""
        dst_ip = "" 

        # Ethernet Type - https://en.wikipedia.org/wiki/Ethernet_frame
        ethertype_hex = (packet_bytes[ETH_IP - 2] << 8) + packet_bytes[ETH_IP - 1]

        # IPv4 - https://en.wikipedia.org/wiki/IPv4, Ctrl + F "Header"
        if ethertype_hex == 0x0800:
            logger.debug("Received an IPv4 packet.")
            ethertype = "IPv4"

            payload_len = (packet_bytes[ETH_IP + 2] << 8) + packet_bytes[ETH_IP + 3]

            protocol = packet_bytes[ETH_IP + 9]

            src_bytes = [packet_bytes[i] for i in range(ETH_IP + 12, ETH_IP + 16)]
            dst_bytes = [packet_bytes[i] for i in range(ETH_IP + 16, ETH_IP + 20)]
            src_ip = byte_array_to_ipv4(src_bytes)
            dst_ip = byte_array_to_ipv4(dst_bytes)

        # IPv6 - https://en.wikipedia.org/wiki/IPv6_packet, Ctrl + F "Fixed header"
        elif ethertype_hex == 0x86dd:
            logger.debug("Received an IPv6 packet.")
            ethertype = "IPv6"

            payload_len = (packet_bytes[ETH_IP + 4] << 8) + packet_bytes[ETH_IP + 5]

            protocol = packet_bytes[ETH_IP + 6]

            src_bytes = [hex(packet_bytes[i]) for i in range(ETH_IP + 8, ETH_IP + 24)]
            dst_bytes = [hex(packet_bytes[i]) for i in range(ETH_IP + 24, ETH_IP + 40)]
            src_ip = byte_array_to_ipv6(src_bytes)
            dst_ip = byte_array_to_ipv6(dst_bytes)

        else:
            ethertype = "VLAN"
            logger.debug("Received a VLAN packet.")

        # Make sure we parsed correctly
        """
        logger.debug("Payload Length: %s" % str(payload_len))
        logger.debug("Protocol: %s" % str(protocol))
        logger.debug("Source IP: %s" % src_ip)
        logger.debug("Destin IP: %s" % dst_ip)
        """

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
