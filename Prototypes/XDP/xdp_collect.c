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

  return XDP_DROP;
}

// (IPv4 i.e. parse_layer3.call(ctx, 4)) Passed context via program array
int parse_ipv4(struct xdp_md *ctx) 
{
  // Packet to store in hash
  packet_attrs p = {0, 0, 0, "", "", 0, 0};

  // Store L2 Protocol
  p.l2_proto = ETHERTYPE_IP;
  
  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Fix IP Header pointer to correct location
  struct iphdr *iph = data + sizeof(struct ethhdr);

  // Make sure the data is accessible (see note 2 above)
  if ((void *)&iph[1] > data_end)
    return XDP_DROP;

  u_short proto = iph -> protocol;

  // Store L3 Protocol, src_ip, and dst_ip
  p.l3_proto = proto;
  __builtin_memcpy(p.src_ip, &(iph -> saddr), IP4_LEN);
  __builtin_memcpy(p.dst_ip, &(iph -> daddr), IP4_LEN);

  // Next Header Offset
  uint16_t nh_off = sizeof(struct ethhdr) + sizeof(*iph);

  // Put layer 4 attributes in packet_attrs
  if (proto == ICMP)
  {
    struct icmphdr *icmph = data + nh_off;

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;
    p.src_port = icmph -> type;
    p.dst_port = icmph -> code;

  }
  else if (proto == TCP)
  {
    struct tcphdr *tcph = data + nh_off;
    
    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;
    p.src_port = tcph -> source;
    p.dst_port = tcph -> dest;
  }
  else if (proto == UDP)
  {
    struct udphdr *udph = data + nh_off;
    
    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;
    p.src_port = udph -> source;
    p.dst_port = udph -> dest;
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

