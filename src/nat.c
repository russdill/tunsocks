#include <lwip/netif.h>

#include "nat/nat.h"
#include "dhcp_server.h"

int
nat_add(struct netif *out_if, struct netif *in_if)
{
	struct nat_rule *rule;
	err_t ret;

	if (in_if->flags & (NETIF_FLAG_ETHERNET | NETIF_FLAG_ETHARP)) {
		if (dhcp_server_add(in_if) < 0)
			return -1;
	}

	rule = calloc(1, sizeof(*rule));
	rule->inp = in_if;
	rule->outp = out_if;
	ret = nat_rule_add(rule);
	if (ret < 0)
		free(rule);

	return ret;
}

