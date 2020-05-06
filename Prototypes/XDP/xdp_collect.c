// xdp_collect.c - Used to instantiate BPF program in xdp_collect.py
// NOTE: This module cannot have...
//         1. Loops
//         2. Access outside of contextual (ctx) memory
//         3. Excessive use of eBPF instructions

#define BPF_LICENSE GPL
#define KBUILD_MODNAME "foo"
#define IPv4 0x0800
#define IPv6 0X86dd
#define VLAN 0x8100
#define ICMP 1
#define TCP 6
#define UDP 17
#define IP_LEN 40
#define IP4_LEN 20
#define IP6_LEN 40
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bcc/proto.h>
#include "lib/bpf_helpers.h"

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;

typedef struct packet_attrs
{
  u_short proto;
  u_char src_ip[IP_LEN + 1];
  u_char dst_ip[IP_LEN + 1];
  u_short src_port;  // Type for ICMP
  u_short dst_port;  // Code for ICMP
} packet_attrs;

static void parse_icmp(void *data, void *data_end, u_short offset, packet_attrs *p)
{
  return;
}

// Currently identical to parse_udp() but subject to change
static void parse_tcp(void *data, void *data_end, u_short offset, packet_attrs *p)
{
  return;
}


static void parse_udp(void *data, void *data_end, u_short offset, packet_attrs *p)
{
  return;
}

// (IPv4) Passed data pointers and a packet_attrs struct to fill
static void parse_ipv4(void *data, void *data_end, u_short offset, packet_attrs *p) 
{
  struct iphdr *iph = data + offset;

  // Make sure the data is accessible (see note 2 above)
  if ((void *)&iph[1] > data_end)
    return;

  u_short proto = iph -> protocol;

  // Fill in packet attributes
  p -> proto = proto;

  snprintf(p -> src_ip, IP4_LEN, "%uI4", ntohs(iph -> saddr));
  snprintf(p -> dst_ip, IP4_LEN, "%uI4", ntohs(iph -> daddr));

  // Update offset
  offset += sizeof(*iph);

  // Forward packet to respective next header
  switch (proto)
  {
    case ICMP:
      parse_icmp(data, data_end, offset, p);
      break;

    case TCP:
      parse_tcp(data, data_end, offset, p);
      break;

    case UDP:
      parse_udp(data, data_end, offset, p);
      break;
  }
}

// (IPv6) Passed data pointers and a packet_attrs struct to fill
static void parse_ipv6(void *data, void *data_end, u_short offset, packet_attrs *p)
{
  struct ipv6hdr *ip6h = data + offset;

  // Make sure the data is accessible (see note 2 above)
  if ((void *)&ip6h[1] > data_end)
    return;

  u_short proto = ip6h -> nexthdr;

  // Fill in packet attributes
  p -> proto = proto;
  //snprintf(p -> src_ip, IP6_LEN, "%lluI6", ip6h -> saddr.in6_u);
  //snprintf(p -> dst_ip, IP6_LEN, "%lluI6", ip6h -> daddr.in6_u);

  // Update offset
  offset += sizeof(*ip6h);

  // Forward packet to respective next header
  switch (proto)
  {
    case ICMP:
      parse_icmp(data, data_end, offset, p);
      break;

    case TCP:
      parse_tcp(data, data_end, offset, p);
      break;

    case UDP:
      parse_udp(data, data_end, offset, p);
      break;
  }
}

SEC("xdp_parse")
int xdp_parser(struct xdp_md *ctx)
{
  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Cast Ethernet Header to data
  struct ethhdr *ether = data;

  // Extract Little Endian Ethertype
  __be16 ether_be = ether -> h_proto;
  u_short ether_le = ntohs(ether_be);
  u_long nh_off = sizeof(*ether);

  // IPv4 Packet Handling
  if (ether_le == IPv4)
  {
    // Packet to be filled out
    packet_attrs p;

    // Fill out sections of packet_attrs
    parse_ipv4(data, data_end, nh_off, &p);
    bpf_trace_printk("Hi.");
  }
  // IPv6 Packet Handling
  else if (ether_le == IPv6)
  {
    // Packet to be filled out
    packet_attrs p;

    // Fill out sections of packet_attrs
    parse_ipv6(data, data_end, nh_off, &p);
  }
  // VLAN Packet Handling
  else if (ether_le == VLAN)
  {
    return XDP_DROP;
  }

  return XDP_DROP;
}

