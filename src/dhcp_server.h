#ifndef __DHCP_SERVER_H__
#define __DHCP_SERVER_H__

struct netif;

int dhcp_server_add(struct netif *netif);

#endif
