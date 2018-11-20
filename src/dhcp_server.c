#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include <lwip/netif.h>
#include <lwip/stats.h>
#include <lwip/init.h>
#include <lwip/snmp.h>
#include <lwip/dns.h>

#include "dhcp_server.h"
#include "udhcp_common.h"
#include "dhcpd.h"
#include "util/host.h"

int
dhcp_server_add(struct netif *netif)
{
	struct udhcpd_server *server;
	struct option_set *option;
	int i;
	int n;
	const char *first;
	uint8_t cstr[1024];
	int clen;
	int cpos;

	server = udhcpd_init(netif, 67);
	if (!server) {
		return -1;
	}

	option = calloc(1, sizeof(*option) + 2 + 4);
	option->data = (uint8_t *)(option + 1);
	option->data[OPT_CODE] = DHCP_ROUTER;
	option->data[OPT_LEN] = 4;
	memcpy(option->data + 2, &netif->ip_addr.addr, 4);
	option->next = server->options;
	server->options = option;

	option = calloc(1, sizeof(*option) + 2 + 4);
	option->data = (uint8_t *)(option + 1);
	option->data[OPT_CODE] = DHCP_SUBNET;
	option->data[OPT_LEN] = 4;
	memcpy(option->data + 2, &netif->netmask.addr, 4);
	option->next = server->options;
	server->options = option;

	option = calloc(1, sizeof(*option) + 2 + 4 * DNS_MAX_SERVERS);
	option->data = (uint8_t *)(option + 1);
	option->data[OPT_CODE] = DHCP_DNS_SERVER;
	for (n = 0, i = 0; i < DNS_MAX_SERVERS; i++) {
		const ip_addr_t *dns = dns_getserver(i);
		if (dns->addr) {
			memcpy(option->data + 2 + 4 * n, &dns->addr, 4);
			n++;
		}
	}
	option->data[OPT_LEN] = 4 * n;
	option->next = server->options;
	server->options = option;

	clen = 0;
	first = NULL;
	for (i = 0; i < HOST_SEARCH_SIZE; i++) {
		const char *host = host_get_search(i);
		if (host) {
			int retlen = 0;
			uint8_t *dname = dname_enc(cstr, clen, host, &retlen);
			if (!first && strlen(host) < 255)
				first = host;
			if (dname && clen + retlen < sizeof(cstr)) {
				memcpy(cstr + clen, dname, retlen);
				clen += retlen;
			}
			free(dname);
		}
	}

	if (first) {
		option = calloc(1, sizeof(*option) + 2 + strlen(first) + 1);
		option->data = (uint8_t *)(option + 1);
		option->data[OPT_CODE] = DHCP_DOMAIN_NAME;
		option->data[OPT_LEN] = strlen(first) + 1;
		strcpy((char *)option->data + 2, first);
		option->next = server->options;
		server->options = option;
	}

	cpos = 0;
	while (cpos < clen) {
		int len = (clen - cpos) > 255 ? 255 : (clen - cpos);
		option = calloc(1, sizeof(*option) + 2 + len);
		option->data = (uint8_t *)(option + 1);
		option->data[OPT_CODE] = DHCP_DOMAIN_SEARCH;
		option->data[OPT_LEN] = len;
		memcpy(option->data + 2, cstr + cpos, len);
		option->next = server->options;
		server->options = option;
		cpos += len;
	}

	return 0;
}

