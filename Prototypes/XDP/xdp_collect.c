// xdp_collect.c - Used to instantiate BPF program in xdp_collect.py
// NOTE: This module cannot have...
//         1. Loops
//         2. Access outside of contextual (ctx) memory
//         3. Excessive use of eBPF instructions

#define BPF_LICENSE GPL
#define KBUILD_MODNAME "xdp_collector"
#include <linux/bpf.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#define IPv4 0x0800
#define IPv6 0X86dd
#define VLAN 0x8100
#define ICMP 1
#define TCP 6
#define UDP 17
#define IP_LEN 40
#define IP4_LEN 20
#define IP6_LEN 40

BPF_PROG_ARRAY(parse_layer3, 7);
//BPF_PROG_ARRAY(parse_layer4, 18);

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;

typedef struct packet_attrs
{
  u_short l3_proto;
  u_short l4_proto;
  u_char src_ip[IP_LEN + 1];
  u_char dst_ip[IP_LEN + 1];
  u_short src_port;  // Type for ICMP
  u_short dst_port;  // Code for ICMP
} packet_attrs;

BPF_HASH(flows, int, struct packet_attrs);

int xdp_parser(struct xdp_md *ctx)
{
  bpf_trace_printk("hi");
  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Accomplishes NOTE 2
  if (data + sizeof(struct ethhdr) > data_end)
  {
    return XDP_PASS;
  }

  // Cast Ethernet Header to data
  struct ethhdr *ether = data;

  // Extract Little Endian Ethertype
  __be16 ether_be = ether -> h_proto;
  u_short ether_le = ntohs(ether_be);

  // IPv4 Packet Handling
  if (ether_le == IPv4)
  {
    parse_layer3.call(ctx, 4);
  }
  // IPv6 Packet Handling
  else if (ether_le == IPv6)
  {
    parse_layer3.call(ctx, 6);
  }
  // VLAN Packet Handling
  else if (ether_le == VLAN)
  {
    bpf_trace_printk("Receive Ethertype VLAN!");
  }
  // Other Packet Handling
  else
  {
    bpf_trace_printk("IPv4/IPv6/VLAN Ethertypes were not hit!");
  }

  return XDP_DROP;
}

// (IPv4 i.e. parse_layer3.call(ctx, 4)) Passed context via program array
int parse_ipv4(struct xdp_md *ctx) 
{
  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  struct iphdr *iph = data + sizeof(struct ethhdr);

  // Make sure the data is accessible (see note 2 above)
  if ((void *)&iph[1] > data_end)
    return XDP_DROP;

  u_short proto = iph -> protocol;

  if (proto == ICMP)
  {

  }
  else if (proto == TCP)
  {

  }
  else if (proto == UDP)
  {

  }
  else
  {
    return XDP_DROP;
  }

  return XDP_PASS;
}

// (IPv6 i.e. parse_layer3.call(ctx, 6)) Passed context via program array
int parse_ipv6(struct xdp_md *ctx)
{
  return 1;
  /*
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
  */
}

int parse_icmp(struct xdp_md *ctx)
{
  return 1;
}

// Currently identical to parse_udp() but subject to change later in project
int parse_tcp(struct xdp_md *ctx)
{
  return 1;
}


int parse_udp(struct xdp_md *ctx)
{
  return 1;
}

