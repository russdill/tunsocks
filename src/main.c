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

static int parse_conn_info(const char *str, struct conn_info *info)
{
	int fields = 1;
	int f0;
	const char *field[4] = {NULL, NULL, NULL, NULL};

	free(info->bind);
	free(info->bind_port);
	free(info->host);
	free(info->host_port);
	info->bind = info->bind_port = info->host = info->host_port = NULL;

	for (field[0] = str; *str; str++)
		if (*str == ':') {
			if (fields == 4)
				return -1;
			field[fields] = str + 1;
			fields++;
		}

	f0 = fields == 4 ? 1 : 0;

	info->bind_port = strndup(field[f0], field[f0 + 1] - field[f0] - 1);

	if (fields == 4)
		info->bind = strndup(field[0], field[1] - field[0] - 1);
	else
		info->bind = NULL;

	if (fields >= 3)
		info->host_port = strndup(field[f0 + 2],
					field[f0 + 3] - field[f0 + 2] - 1);
	else
		info->host_port = strdup(info->bind_port);

	if (fields >= 2)
		info->host = strndup(field[f0 + 1],
					field[f0 + 2] - field[f0 + 1] - 1);
	else
		info->host = NULL;

	return fields;
}

static void print_usage(const char *argv0)
{
	fprintf(stderr,
"usage: %s <options>\n\n"
"    -L [bind_address:]port:host:hostport\n"
"    -D [bind_address:]port\n"
"    -R port:host:hostport\n"
"    -k keep alive interval (seconds)\n"
"    -m mtu (env INTERNAL_IP4_MTU)\n"
"    -s domain_search[,domain_search,...] (env CISCO_DEF_DOMAIN)\n"
"    -d dns,[dns,...] (env INTERNAL_IP4_DNS)\n"
"    -i ip address (env INTERNAL_IP4_ADDRESS)\n"
"    -n netmask\n"
"    -g gateway\n"
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
	int ret;
	struct netif *netif;
	int dns_count;
	char *str;
	char *endptr;
	int mtu;
	int fd_in;
	int fd_out;
	ip_addr_t ipaddr;
	ip_addr_t netmask;
	ip_addr_t gateway;
	ip_addr_t dns;
	struct event_base *base;
	struct conn_info info;
	char *pcap_file;

	ip_addr_set_zero(&ipaddr);
	ip_addr_set_zero(&netmask);
	ip_addr_set_zero(&gateway);

	dns_count = 0;
	keep_alive = 0;
	fd_in = 0;
	fd_out = 1;
	mtu = 0;
	pcap_file = NULL;

	memset(&info, 0, sizeof(info));

	base = event_base_new();
	lwip_init();
	libevent_timeouts_init(base);

	if ((str = getenv("INTERNAL_IP4_ADDRESS")))
		ipaddr_aton(str, &ipaddr);

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
			ipaddr_aton(str, &dns);
			dns_setserver(dns_count++, &dns);
			free(str);
		}
	}

	while ((c = getopt(argc, argv, "L:D:R:k:m:s:d:i:n:g:p:h")) != -1) {

		switch (c) {
		case 'L':
			ret = parse_conn_info(optarg, &info);
			if (ret < 0)
				print_usage(argv[0]);

			str = info.bind && info.bind[0] ?
					info.bind : "localhost";

			if (forward_local(base, str, info.bind_port,
				info.host, info.host_port, &keep_alive) < 0)
				return -1;
			break;
		case 'D':
			ret = parse_conn_info(optarg, &info);
			if (ret < 0 || ret > 2)
				print_usage(argv[0]);

			str = info.bind && info.bind[0] ?
					info.bind : "localhost";
			if (socks_listen(base, str, info.bind_port,
							&keep_alive) < 0)
				return -1;
			break;
		case 'R':
			ret = parse_conn_info(optarg, &info);
			if (ret < 0 || ret > 3)
				print_usage(argv[0]);

			if (forward_remote(base, info.bind_port, info.host,
						info.host_port, &keep_alive) < 0)
				return -1;
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
				ipaddr_aton(str, &dns);
				dns_setserver(dns_count++, &dns);
				free(str);
			}
			break;
		case 'i':
			ipaddr_aton(optarg, &ipaddr);
			break;
		case 'n':
			ipaddr_aton(optarg, &netmask);
			break;
		case 'g':
			ipaddr_aton(optarg, &gateway);
			break;
#ifdef USE_PCAP
		case 'p':
			pcap_file = strdup(optarg);
			break;
#endif
		default:
			print_usage(argv[0]);
		}
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
