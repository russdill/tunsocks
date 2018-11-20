#ifndef __NAT_H__
#define __NAT_H__

struct netif;

int nat_add(struct netif *out_if, struct netif *in_if);

#endif
