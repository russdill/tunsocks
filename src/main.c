#define _GNU_SOURCE
#include <event2/event.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <lwip/ip.h>
#include <lwip/init.h>
#include <lwip/dns.h>
#include <signal.h>

#include "socks.h"
#include "host.h"
#include "forward_local.h"
#include "forward_remote.h"
#include "tunif.h"
#include "libevent.h"

struct conn_info {
	char *bind;
	char *bind_port;
	char *host;
	char *host_port;
	struct conn_info *next;
};

static char *tokenize(const char *str, const char *sep, char **endptr)
{
	int i;

	/* left strip */
	while (str[0] && strchr(sep, str[0]))
		str++;

	if (!str[0])
		return NULL;

	for (i = 0; str[i] && !strchr(sep, str[i]); i++);

	*endptr = (char *) str + i;

	return strndup(str, i);
}

static struct conn_info *parse_conn_info(const char *str, int fmin, int fmax)
{
	int fields = 1;
	int f0;
	const char *field[4] = {NULL, NULL, NULL, NULL};
	struct conn_info *info;

	for (field[0] = str; *str; str++)
		if (*str == ':') {
			if (fields == fmax)
				return NULL;
			field[fields] = str + 1;
			fields++;
		}

	if (fields < fmin)
		return NULL;

	info = calloc(1, sizeof(*info));

	/* Bind address is the leading optional field */
	if (fields > fmin) {
		f0 = 1;
		fields--;
		info->bind = strndup(field[0], field[1] - field[0] - 1);
	} else {
		f0 = 0;
		info->bind = NULL;
	}

	info->bind_port = strndup(field[f0], field[f0 + 1] - field[f0] - 1);

	if (fields >= 2)
		info->host = strndup(field[f0 + 1],
					field[f0 + 2] - field[f0 + 1] - 1);
	else
		info->host = NULL;

	if (fields >= 3) {
		if (f0)
			info->host_port = strdup(field[f0 + 2]);
		else
			info->host_port = strndup(field[f0 + 2],
					field[f0 + 3] - field[f0 + 2] - 1);
	} else
		info->host_port = strdup(info->bind_port);

	return info;
}

static void free_conn_info(struct conn_info *info)
{
	free(info->bind);
	free(info->bind_port);
	free(info->host);
	free(info->host_port);
	free(info);
}

static void print_usage(const char *argv0)
{
	fprintf(stderr,
"usage: %s <options>\n\n"
"    -L [bind_address:]bind_port:host_address:host_port\n"
"    -D [bind_address:]bind_port\n"
"    -R bind_port:host_address:host_port\n"
"    -g Allow non-local clients (command line compatibility for ocproxy)\n"
"    -k keep alive interval (seconds)\n"
"    -m mtu (env INTERNAL_IP4_MTU)\n"
"    -s domain_search[,domain_search,...] (env CISCO_DEF_DOMAIN)\n"
"    -d dns,[dns,...] (env INTERNAL_IP4_DNS)\n"
"    -i ip address (env INTERNAL_IP4_ADDRESS)\n"
"    -n netmask\n"
"    -G gateway\n"
#ifdef USE_PCAP
"    -p pcap_file\n"
#endif
"\n", basename((char *) argv0));
	exit(1);
}

int main(int argc, char *argv[])
{
	int c;
	int keep_alive;
	int non_local;
	struct netif *netif;
	int dns_count;
	char *str;
	char *endptr;
	int mtu;
	int fd_in;
	int fd_out;
	ip4_addr_t ipaddr;
	ip4_addr_t netmask;
	ip4_addr_t gateway;
	ip4_addr_t dns;
	struct event_base *base;
	char *pcap_file;
	struct conn_info *local;
	struct conn_info *remote;
	struct conn_info *socks;
	struct conn_info *info;

	ip_addr_set_zero(&ipaddr);
	ip_addr_set_zero(&netmask);
	ip_addr_set_zero(&gateway);

	local = remote = socks = NULL;
	dns_count = 0;
	keep_alive = 0;
	fd_in = 0;
	fd_out = 1;
	mtu = 0;
	pcap_file = NULL;
	non_local = 0;

	signal(SIGPIPE, SIG_IGN);

	base = event_base_new();
	lwip_init();
	libevent_timeouts_init(base);

	if ((str = getenv("INTERNAL_IP4_ADDRESS")))
		ip4addr_aton(str, &ipaddr);

	if ((str = getenv("INTERNAL_IP4_MTU")))
		mtu = strtoul(str, NULL, 0);

	if ((str = getenv("VPNFD")))
		fd_in = fd_out = strtoul(str, NULL, 0);

	if ((str = getenv("CISCO_DEF_DOMAIN"))) {
		endptr = str;
		while ((str = tokenize(endptr, ", ", &endptr)))
			host_add_search(str);
	}

	if ((str = getenv("INTERNAL_IP4_DNS")))	{
		endptr = str;
		while ((str = tokenize(endptr, ", ", &endptr))) {
			ip4addr_aton(str, &dns);
			dns_setserver(dns_count++, &dns);
			free(str);
		}
	}

	while ((c = getopt(argc, argv, "L:D:R:k:m:s:d:i:n:G:p:gh")) != -1) {

		switch (c) {
		case 'L':
			info = parse_conn_info(optarg, 3, 4);
			if (!info)
				print_usage(argv[0]);

			info->next = local;
			local = info;
			break;
		case 'D':
			info = parse_conn_info(optarg, 1, 2);
			if (!info)
				print_usage(argv[0]);

			info->next = socks;
			socks = info;
			break;
		case 'R':
			info = parse_conn_info(optarg, 3, 3);
			if (!info)
				print_usage(argv[0]);

			info->next = remote;
			remote = info;
			break;
		case 'k':
			keep_alive = strtoul(optarg, &endptr, 0);
			if (*endptr)
				print_usage(argv[0]);
			keep_alive *= 1000;
			break;
		case 'm':
			mtu = strtoul(optarg, &endptr, 0);
			if (*endptr)
				print_usage(argv[0]);
			break;
		case 's':
			while ((str = tokenize(optarg, ", ", &optarg)))
				host_add_search(str);
			break;
		case 'd':
			while ((str = tokenize(optarg, ", ", &optarg))) {
				ip4addr_aton(str, &dns);
				dns_setserver(dns_count++, &dns);
				free(str);
			}
			break;
		case 'i':
			ip4addr_aton(optarg, &ipaddr);
			break;
		case 'n':
			ip4addr_aton(optarg, &netmask);
			break;
		case 'G':
			ip4addr_aton(optarg, &gateway);
			break;
#ifdef USE_PCAP
		case 'p':
			pcap_file = strdup(optarg);
			break;
#endif
		case 'g':
			non_local = 1;
			break;
		default:
			print_usage(argv[0]);
		}
	}

	while (local) {
		info = local;
		str = info->bind && info->bind[0] ? info->bind : NULL;
		if (!non_local)
			str = str ? : "localhost";

		if (forward_local(base, str, info->bind_port,
			info->host, info->host_port, keep_alive) < 0)
			return -1;

		local = info->next;
		free_conn_info(info);
	}

	while (socks) {
		info = socks;
		str = info->bind && info->bind[0] ? info->bind : NULL;
		if (!non_local)
			str = str ? : "localhost";
		if (socks_listen(base, str, info->bind_port, keep_alive) < 0)
			return -1;
		socks = socks->next;
		free_conn_info(info);
	}

	while (remote) {
		info = remote;
		if (forward_remote(base, info->bind_port, info->host,
					info->host_port, keep_alive) < 0)
			return -1;
		remote = info->next;
		free_conn_info(info);
	}

	netif = tunif_add(base, fd_in, fd_out, pcap_file);

	netif_set_ipaddr(netif, &ipaddr);
	netif_set_netmask(netif, &netmask);
	netif_set_gw(netif, &gateway);
	if (mtu)
		netif->mtu = mtu;
	netif_set_up(netif);

	event_base_dispatch(base);

	return 0;
}
