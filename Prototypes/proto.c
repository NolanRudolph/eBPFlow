#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

int filter(struct __sk_buff *skb)
{
  u8 *mem_ref = 0;

  struct ethernet_t *ethernet = cursor_advance(mem_ref, sizeof(*ethernet));

  int ethertype = ethernet -> type;

  // Keep IP Ethernet || VLAN Ethernet
  if (ethertype == 0x0800 || ethertype == 0x8100)
  {
    return -1;
  }
  // Drop anything else
  else
  {
    return 0;
  }
}
