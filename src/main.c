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
#include "util/host.h"
#include "forward_local.h"
#include "forward_remote.h"
#include "util/pcap.h"
#include "util/libevent.h"

#include "netif/fdif.h"
#include "netif/slirpif.h"
struct conn_info {
	char *bind;
	char *bind_port;
	char *host;
	char *host_port;
	struct conn_info *next;
};

struct pcap_entry {
	char *file;
	char *netif;
	struct pcap_entry *next;
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
"    -S (Use slirp interface instead VPN, useful for testing)\n"
#ifdef USE_PCAP
"    -p pcap_file[:netif] (Default netif 'fd', VPN input)\n"
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
	int use_slirp;
	int fd_in;
	int fd_out;
	ip_addr_t ipaddr;
	ip_addr_t netmask;
	ip_addr_t gateway;
	ip_addr_t dns;
#if LWIP_IPV4
	ip_addr_t ipaddr4;
	ip_addr_t netmask4;
	ip_addr_t gateway4;
#endif
#if LWIP_IPV6
	ip_addr_t ipaddr6;
	ip_addr_t netmask6;
	ip_addr_t gateway6;
#endif
	struct event_base *base;
#ifdef USE_PCAP
	struct pcap_entry *pcap_entries, *pcap_entry;
#endif
	struct conn_info *local;
	struct conn_info *remote;
	struct conn_info *socks;
	struct conn_info *info;

#if LWIP_IPV4
	IP4_ADDR(&ipaddr4, 10, 0, 3, 1);
	IP4_ADDR(&netmask4, 255, 255, 255, 0);
	ip_addr_set_zero(&gateway4);
#endif
#if LWIP_IPV6
	ip_addr_set_zero(&ipaddr6);
	ip_addr_set_zero(&netmask6);
	ip_addr_set_zero(&gateway6);
#endif

	local = remote = socks = NULL;
	dns_count = 0;
	keep_alive = 0;
	use_slirp = 0;
	fd_in = 0;
	fd_out = 1;
	mtu = 0;
	pcap_entries = NULL;
	non_local = 0;

	signal(SIGPIPE, SIG_IGN);

	base = event_base_new();
	lwip_init();
	libevent_timeouts_init(base);


#if LWIP_IPV4
	if ((str = getenv("INTERNAL_IP4_ADDRESS")))
		ip4addr_aton(str, ip_2_ip4(&ipaddr4));

	if ((str = getenv("INTERNAL_IP4_NETMASK")))
		ip4addr_aton(str, ip_2_ip4(&netmask4));

	if ((str = getenv("INTERNAL_IP4_DNS")))	{
		endptr = str;
		while ((str = tokenize(endptr, ", ", &endptr))) {
			ip4addr_aton(str, ip_2_ip4(&dns));
			dns_setserver(dns_count++, &dns);
			free(str);
		}
	}
#endif

	if ((str = getenv("INTERNAL_IP4_MTU")))
		mtu = strtoul(str, NULL, 0);

#if LWIP_IPV6
	if ((str = getenv("INTERNAL_IP6_ADDRESS")))
		ip6addr_aton(str, ip_2_ip6(&ipaddr6));

	if ((str = getenv("INTERNAL_IP6_NETMASK")))
		ip6addr_aton(str, ip_2_ip6(&netmask6));

	if ((str = getenv("INTERNAL_IP6_DNS")))	{
		endptr = str;
		while ((str = tokenize(endptr, ", ", &endptr))) {
			ip6addr_aton(str, ip_2_ip6(&dns));
			dns_setserver(dns_count++, &dns);
			free(str);
		}
	}
#endif

	if ((str = getenv("VPNFD")))
		fd_in = fd_out = strtoul(str, NULL, 0);

	if ((str = getenv("CISCO_DEF_DOMAIN"))) {
		endptr = str;
		while ((str = tokenize(endptr, ", ", &endptr)))
			host_add_search(str);
	}

	while ((c = getopt(argc, argv, "SL:D:R:k:m:s:d:i:n:G:p:gh")) != -1) {

		switch (c) {
		case 'S':
			use_slirp = 1;
			break;
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
				if (!ip4addr_aton(str, &dns))
					print_usage(argv[0]);
				dns_setserver(dns_count++, &dns);
				free(str);
			}
			break;
		case 'i':
			if (!ipaddr_aton(optarg, &ipaddr))
				print_usage(argv[0]);
#if LWIP_IPV4
			if (IP_IS_V4(&ipaddr))
				ip_addr_copy(ipaddr4, ipaddr);
#endif
#if LWIP_IPV6
			if (IP_IS_V6(&ipaddr))
				ip_addr_copy(ipaddr6, ipaddr);
#endif
			break;
		case 'n':
			if (!ipaddr_aton(optarg, &netmask))
				print_usage(argv[0]);
#if LWIP_IPV4
			if (IP_IS_V4(&netmask))
				ip_addr_copy(netmask4, netmask);
#endif
#if LWIP_IPV6
			if (IP_IS_V6(&netmask))
				ip_addr_copy(netmask6, netmask);
#endif
			break;
		case 'G':
			if (!ipaddr_aton(optarg, &gateway))
				print_usage(argv[0]);
#if LWIP_IPV4
			if (IP_IS_V4(&gateway))
				ip_addr_copy(gateway4, gateway);
#endif
#if LWIP_IPV6
			if (IP_IS_V6(&gateway))
				ip_addr_copy(gateway6, gateway);
#endif
			break;
#ifdef USE_PCAP
		case 'p':
			pcap_entry = calloc(1, sizeof(*pcap_entry));
			pcap_entry->next = pcap_entries;
			pcap_entries = pcap_entry;
			pcap_entry->file = strdup(optarg);
			pcap_entry->netif = strchr(pcap_entry->file, ':');
			if (pcap_entry->netif) {
				pcap_entry->netif[0] = '\0';
				pcap_entry->netif++;
			}
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

	/* "External" interface */
	if (use_slirp)
		netif = slirpif_add(base);
	else
		netif = fdif_add(base, fd_in, fd_out, 0);
	netif_set_default(netif);

	netif_set_ipaddr(netif, &ipaddr4);
	netif_set_netmask(netif, &netmask4);
	netif_set_gw(netif, &gateway4);
	if (mtu)
		netif->mtu = mtu;


#ifdef USE_PCAP
	for (pcap_entry = pcap_entries; pcap_entry; pcap_entry = pcap_entry->next) {
		const char *name = pcap_entry->netif;
		struct netif *pcapif = NULL;
		if (strlen(name) == 2) {
			NETIF_FOREACH(pcapif) {
				if (name[0] == pcapif->name[0] && name[1] == pcapif->name[1])
				break;
			}
		} else if (strlen(name) > 2)
			pcapif = netif_find(name);

		if (!pcapif) {
			fprintf(stderr, "Could not find netif: '%s'\n", name);
			print_usage(argv[0]);
		}
		if (pcap_dump_add(pcapif, pcap_entry->file) < 0)
			return -1;
	}
#endif

	netif_set_up(netif);
	event_base_dispatch(base);

	return 0;
}
