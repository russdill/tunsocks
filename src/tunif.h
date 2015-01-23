#ifndef __TUNIF_H__
#define __TUNIF_H__

#include <sys/types.h>

#define NETIF_FLAG_BROADCAST    0x02U
#define NETIF_FLAG_POINTTOPOINT 0x04U

struct netif;
struct event_base;

struct netif *tunif_add(struct event_base *base, int fd_in, int fd_out,
				const char *pcap_file);

#endif
