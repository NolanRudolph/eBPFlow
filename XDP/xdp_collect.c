// xdp_collect.c - Used to instantiate BPF program in xdp_collect.py
// NOTE: This module cannot have...
//         1. Loops
//         2. Access outside of contextual (ctx) memory
//         3. Excessive use of eBPF instructions

/* PREPROCESSORS */
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
#define ICMP 1
#define TCP 6
#define UDP 17

/* TYPEDEFS */
typedef unsigned char u_char;

typedef struct flow_attrs
{
  uint16_t l2_proto;
  uint8_t l4_proto;
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
  u32 store_id;
} flow_attrs;

typedef struct flow_accms
{
  u64 start;
  u64 end;
  uint64_t packets;
  uint64_t bytes;
} flow_accms;

/* BPF MAPS */
BPF_TABLE("percpu_hash", struct flow_attrs, struct flow_accms, flows, 65536);
BPF_PROG_ARRAY(parse_layer3, 7);

/* CODE */
int xdp_parser(struct xdp_md *ctx)
{
  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Accomplishes NOTE 2
  if (data + sizeof(struct ethhdr) > data_end)
  {
    return XDP_DROP;
  }

  // Cast Ethernet Header to data
  struct ethhdr *ether = (struct ethhdr *)data;

  // Extract Little Endian Ethertype
  __be16 ether_be = ether -> h_proto;
  uint16_t ether_le = ntohs(ether_be);

  // IPv4 Packet Handling
  if (ether_be == htons(ETH_P_IP))
  {
    parse_layer3.call(ctx, 4);
    return XDP_PASS;
  }
  // IPv6 Packet Handling
  else if (ether_be == htons(ETH_P_IPV6))
  {
    parse_layer3.call(ctx, 6);
    return XDP_PASS;
  }
  // VLAN Packet Handling
  else if (ether_be == htons(ETH_P_8021Q) || ether_be == htons(ETH_P_8021AD))
  {
    bpf_trace_printk("Received Ethertype VLAN!");
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
  flow_attrs p = {0, 0, 0, 0, 0, 0, 0};

  // Offset for memory boundary checks
  int offset = sizeof(struct ethhdr);

  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Make sure the data is accessible (see note 2 above)
  if (data + offset + sizeof(struct iphdr) > data_end)
    return XDP_DROP;

  // Fix IP Header pointer to correct location
  struct iphdr *iph = (struct iphdr *)(data + offset);
  offset += sizeof(struct iphdr);

  // # of bytes for accumulator variables
  uint16_t bytes = (ctx -> data_end) - (ctx -> data);

  // Store L2 + L3 Protocol, src_ip, dst_ip, and #bytes
  p.l2_proto = ETH_P_IP;
  __builtin_memcpy(&p.src_ip, &(iph -> saddr), sizeof(__be32));
  __builtin_memcpy(&p.dst_ip, &(iph -> daddr), sizeof(__be32));
  // __builtin_memcpy(&bytes, &(iph -> tot_len), sizeof(uint16_t));

  // Get L4 protocol
  u_short proto = iph -> protocol;

  // Put layer 4 attributes in flow_attrs
  if (proto == ICMP && (data + offset + sizeof(struct icmphdr) < data_end))
  {
    struct icmphdr *icmph = (struct icmphdr *)(data + offset);

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;
    
    __builtin_memcpy(&p.src_port, &(icmph -> type), sizeof(uint8_t));
    __builtin_memcpy(&p.dst_port, &(icmph -> code), sizeof(uint8_t));
  }
  else if (proto == TCP && (data + offset + sizeof(struct tcphdr) < data_end))
  {
    struct tcphdr *tcph = (struct tcphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;

    __builtin_memcpy(&p.src_port, &(tcph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(tcph -> dest), sizeof(__be16));
  }
  else if (proto == UDP && (data + offset + sizeof(struct udphdr) < data_end))
  {
    struct udphdr *udph = (struct udphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;
    __builtin_memcpy(&p.src_port, &(udph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(udph -> dest), sizeof(__be16));
  }
  else
  {
    return XDP_DROP;
  }

  u64 now = bpf_ktime_get_ns();
  flow_accms def_acc = {now, now, 0, 0};
  flow_accms *flow_ptr = flows.lookup_or_try_init(&p, &def_acc);
  //u64 now = bpf_ktime_get_ns();

  if (flow_ptr)
  {
    // Store if above aggregation time (i.e. set ID field)
    /*
    if (now - (flow_ptr -> start) > AGG)
    {
      __builtin_memcpy(&ins_acc, flow_ptr, sizeof(struct flow_accms));
      ins_acc.end = now;
      ins_acc.packets++;
      ins_acc.bytes += bytes;

      // Generate a unique Store ID
      // 
      while(flows.lookup(&p))
      {
        p.store_id = bpf_get_prandom_u32();
      }
      //

      flows.insert(&p, &ins_acc);
    }
    else
    {
    }
  */
    // Update the flow otherwise
    __builtin_memcpy(&def_acc.packets, &(flow_ptr -> packets), sizeof(uint64_t));
    __builtin_memcpy(&def_acc.bytes, &(flow_ptr -> bytes), sizeof(uint64_t));
    ++def_acc.packets;
    def_acc.bytes += bytes;
    def_acc.end = now;
    flows.update(&p, &def_acc); 
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
  // Packet to store in hash
  flow_attrs p = {0, 0, 0, 0, 0, 0};

  // Offset for memory boundary checks
  int offset = sizeof(struct ethhdr);

  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Make sure the data is accessible (see note 2 above)
  if (data + offset + sizeof(struct ipv6hdr) > data_end)
    return XDP_DROP;

  // Fix IP Header pointer to correct location
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + offset);
  offset += sizeof(struct ipv6hdr);

  // # of bytes for accumulator variables
  uint16_t bytes = 0;

  // Store L2 + L3 Protocol, src_ip, and dst_ip
  p.l2_proto = ETH_P_IPV6;
  __builtin_memcpy(&p.src_ip, &(ip6h -> saddr), sizeof(__be32));
  __builtin_memcpy(&p.dst_ip, &(ip6h -> daddr), sizeof(__be32));

  // Get L4 Protocol
  u_short proto = ip6h -> nexthdr;

  // Put layer 4 attributes in flow_attrs
  if (proto == ICMP && (data + offset + sizeof(struct icmphdr) < data_end))
  {
    struct icmphdr *icmph = (struct icmphdr *)(data + offset);

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;

    __builtin_memcpy(&p.src_port, &(icmph -> type), sizeof(uint8_t));
    __builtin_memcpy(&p.dst_port, &(icmph -> code), sizeof(uint8_t));
  }
  else if (proto == TCP && (data + offset + sizeof(struct tcphdr) < data_end))
  {
    struct tcphdr *tcph = (struct tcphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;

    __builtin_memcpy(&p.src_port, &(tcph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(tcph -> dest), sizeof(__be16));
  }
  else if (proto == UDP && (data + offset + sizeof(struct udphdr) < data_end))
  {
    struct udphdr *udph = (struct udphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;

    __builtin_memcpy(&p.src_port, &(udph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(udph -> dest), sizeof(__be16));
  }
  else
  {
    return XDP_DROP;
  }

  u64 now = 60;
  flow_accms def_acc = {now, now, 0, 0};
  flow_accms *flow_ptr = flows.lookup_or_try_init(&p, &def_acc);

  if (flow_ptr)
  {
    __builtin_memcpy(&def_acc.packets, &(flow_ptr -> packets), sizeof(uint64_t));
    __builtin_memcpy(&def_acc.bytes, &(flow_ptr -> bytes), sizeof(uint64_t));
    ++def_acc.packets;
    def_acc.bytes += bytes;
    def_acc.end = now;
    flows.update(&p, &def_acc); 
  }
  else
  {
    return XDP_DROP;
  }
  return XDP_PASS;
}

