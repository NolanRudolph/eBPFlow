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
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_IP6 0X86dd
#define ETHERTYPE_VLAN 0x8100
#define ICMP 1
#define TCP 6
#define UDP 17
#define IP_LEN 41
#define IP4_LEN 21
#define IP6_LEN 41

BPF_PROG_ARRAY(parse_layer3, 7);

typedef unsigned char u_char;

typedef struct packet_attrs
{
  uint16_t l2_proto;
  uint8_t l3_proto;
  uint8_t l4_proto;
  u_char src_ip[IP_LEN];
  u_char dst_ip[IP_LEN];
  uint16_t src_port;  // Type for ICMP
  uint16_t dst_port;  // Code for ICMP
} packet_attrs;

BPF_HASH(flows, uint16_t, struct packet_attrs);

int xdp_parser(struct xdp_md *ctx)
{
  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Accomplishes NOTE 2
  if (data + sizeof(struct ethhdr) > data_end)
  {
    return XDP_PASS;
  }

  // Cast Ethernet Header to data
  struct ethhdr *ether = (struct ethhdr *)data;

  // Extract Little Endian Ethertype
  __be16 ether_be = ether -> h_proto;
  uint16_t ether_le = ntohs(ether_be);

  // IPv4 Packet Handling
  if (ether_le == ETHERTYPE_IP)
  {
    parse_layer3.call(ctx, 4);
  }
  // IPv6 Packet Handling
  else if (ether_le == ETHERTYPE_IP6)
  {
    parse_layer3.call(ctx, 6);
  }
  /*
  // VLAN Packet Handling
  else if (ether_le == ETHERTYPE_VLAN)
  {
    bpf_trace_printk("Receive Ethertype VLAN!");
  }
  // Other Packet Handling
  else
  {
    bpf_trace_printk("IPv4/IPv6/VLAN Ethertypes were not hit!");
  }
  */

  return XDP_DROP;
}

// (IPv4 i.e. parse_layer3.call(ctx, 4)) Passed context via program array
int parse_ipv4(struct xdp_md *ctx) 
{
  // Packet to store in hash
  packet_attrs p;

  // Offset for memory boundary checks
  uint16_t offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Make sure the data is accessible (see note 2 above)
  if (data + offset > data_end)
    return XDP_DROP;

  // Fix IP Header pointer to correct location
  struct iphdr *iph = (struct iphdr *)(data + offset);

  u_short proto = iph -> protocol;

  // Store L2 + L3 Protocol, src_ip, and dst_ip
  p.l2_proto = ETHERTYPE_IP;
  p.l3_proto = proto;
  __builtin_memcpy(p.src_ip, &(iph -> saddr), IP4_LEN);
  __builtin_memcpy(p.dst_ip, &(iph -> daddr), IP4_LEN);

  // Put layer 4 attributes in packet_attrs
  if (proto == ICMP)
  {
    offset += sizeof(struct icmphdr);
    if (data + offset > data_end)
      return XDP_DROP;

    struct icmphdr *icmph = (struct icmphdr *)(data + offset);

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;
    p.src_port = icmph -> type;
    p.dst_port = icmph -> code;

  }
  else if (proto == TCP)
  {
    offset += sizeof(struct tcphdr);
    if (data + offset > data_end)
      return XDP_DROP;

    struct tcphdr *tcph = (struct tcphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;
    p.src_port = tcph -> source;
    p.dst_port = tcph -> dest;
  }
  else if (proto == UDP)
  {
    offset += sizeof(struct udphdr);
    if (data + offset > data_end)
      return XDP_DROP;

    struct udphdr *udph = (struct udphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;
    p.src_port = udph -> source;
    p.dst_port = udph -> dest;
  }
  else
  {
    return XDP_DROP;
  }
  
  // flows.insert(&p.src_port, &p);
  return XDP_PASS;
}

// (IPv6 i.e. parse_layer3.call(ctx, 6)) Passed context via program array
int parse_ipv6(struct xdp_md *ctx)
{
  return 1;
  /*
  // Make sure the data is accessible (see note 2 above)
  if ((void *)&ip6h[1] > data_end)
    return;

  struct ipv6hdr *ip6h = data + offset;

  u_short proto = ip6h -> nexthdr;

  */
}


