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
#include "http/http.h"
#include "http/http_server.h"
#include "util/host.h"
#include "forward_local.h"
#include "forward_remote.h"
#include "nat.h"

#include "nat/nat.h"

#include "util/pcap.h"
#include "util/nettest.h"
#include "util/libevent.h"

#include "netif/fdif.h"
#include "netif/slirpif.h"
#include "netif/udptapif.h"
#include "netif/vdeportif.h"
#include "netif/vdeswitchif.h"
#include "netif/tunif.h"

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
"    -D [bind_address:]bind_port SOCKS4a/5 proxy\n"
"    -H [bind_address:]bind_port HTTP proxy\n"
"    -P proxy_pac_file:bind_port HTTP server for proxy.pac\n"
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
"    -l Add deLay (in ms) to inbound/outbound packets (useful for testing)\n"
"    -o DrOp probability ([0.0..1.0]) for inbound/outbound (useful for testing)\n"
#ifdef USE_PCAP
"    -p pcap_file[:netif] (Default netif 'fd', VPN input)\n"
#endif
"    -u port (UDP listener port of TAP NAT with no length header, netif=ut)\n"
"    -U port (UDP listener port of TAP NAT with 2 byte length header, netif=ut)\n"
"    -v VDE path (Connect NAT to a VDE switch. netif=vp)\n"
"    -V VDE path (Expose NAT via a reduced functionality VDE switch. netif=vs)\n"
"    -t tun name (Expose NAT via a PTP TUN device. netif=tu)\n"
"    -T tap name (Expose NAT via a TAP device with DHCP. netif=ta)\n"
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
	char *vdeswitch;
	char *vdeport;
	char *tunname;
	char *tapname;
	int mtu;
	int use_slirp;
	unsigned int delay_ms;
	float drop;
	unsigned short nat_port_raw;
	unsigned short nat_port_len;
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
	struct conn_info *http;
	struct conn_info *http_server;
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

	local = remote = socks = http = http_server = NULL;
	dns_count = 0;
	keep_alive = 0;
	use_slirp = 0;
	delay_ms = 0;
	drop = 0.0;
	fd_in = 0;
	fd_out = 1;
	mtu = 0;
#ifdef USE_PCAP
	pcap_entries = NULL;
#endif
	non_local = 0;
	nat_port_raw = 0;
	nat_port_len = 0;
	vdeswitch = NULL;
	vdeport = NULL;
	tunname = NULL;
	tapname = NULL;

	signal(SIGPIPE, SIG_IGN);

	base = event_base_new();
	lwip_init();
	libevent_timeouts_init(base);
#if LWIP_NAT
	sys_timer_add_internal(base, LWIP_NAT_TICK_PERIOD_MS, nat_timer_tick);
#endif


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

	while ((c = getopt(argc, argv, "Sl:o:L:D:H:P:R:k:m:s:d:i:n:G:p:gu:U:v:V:t:T:h")) != -1) {

		switch (c) {
		case 'S':
			use_slirp = 1;
			break;
		case 'l':
			delay_ms = strtoul(optarg, &endptr, 0);
			if (*endptr)
				print_usage(argv[0]);
			break;
		case 'o':
			drop = strtof(optarg, &endptr);
			if (*endptr || !(drop >= 0.0 && drop <= 1.0))
				print_usage(argv[0]);
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
		case 'H':
			info = parse_conn_info(optarg, 1, 2);
			if (!info)
				print_usage(argv[0]);

			info->next = http;
			http = info;
			break;
		case 'P':
			info = parse_conn_info(optarg, 2, 2);
			if (!info)
				print_usage(argv[0]);

			info->next = http_server;
			http_server = info;
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
		case 'u':
			nat_port_raw = strtoul(optarg, &endptr, 0);
			if (*endptr)
				print_usage(argv[0]);
			break;
		case 'U':
			nat_port_len = strtoul(optarg, &endptr, 0);
			if (*endptr)
				print_usage(argv[0]);
			break;
		case 'v':
			vdeport = strdup(optarg);
			break;
		case 'V':
			vdeswitch = strdup(optarg);
			break;
		case 't':
			tunname = strdup(optarg);
			break;
		case 'T':
			tapname = strdup(optarg);
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

	while (http) {
		info = http;
		str = info->bind && info->bind[0] ? info->bind : NULL;
		if (!non_local)
			str = str ? : "localhost";
		if (http_listen(base, str, info->bind_port, keep_alive) < 0)
			return -1;
		http = http->next;
		free_conn_info(info);
	}

	while (http_server) {
		info = http_server;
		if (http_server_listen(base, info->host, info->bind_port) < 0)
			return -1;
		http_server = http_server->next;
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

	if (nat_port_raw || nat_port_len) {
		struct netif *natif;
		natif = udptapif_add(base, nat_port_raw, nat_port_len);
		if (!natif)
			return -1;
		IP4_ADDR(&ipaddr4, 10, 0, 4, 1);
		IP4_ADDR(&netmask4, 255, 255, 255, 0);
		netif_set_ipaddr(natif, &ipaddr4);
		netif_set_netmask(natif, &netmask4);
		if (nat_add(netif, natif) < 0)
			return -1;
		netif_set_up(natif);
	}

	if (vdeport) {
		struct netif *vportif;
		vportif = vdeportif_add(base, vdeport);
		if (!vportif)
			return -1;
		IP4_ADDR(&ipaddr4, 10, 0, 5, 1);
		IP4_ADDR(&netmask4, 255, 255, 255, 0);
		netif_set_ipaddr(vportif, &ipaddr4);
		netif_set_netmask(vportif, &netmask4);
		if (nat_add(netif, vportif) < 0)
			return -1;
		netif_set_up(vportif);
	}

	if (vdeswitch) {
		struct netif *vswitchif;
		vswitchif = vdeswitchif_add(base, vdeswitch);
		if (!vswitchif)
			return -1;
		IP4_ADDR(&ipaddr4, 10, 0, 6, 1);
		IP4_ADDR(&netmask4, 255, 255, 255, 0);
		netif_set_ipaddr(vswitchif, &ipaddr4);
		netif_set_netmask(vswitchif, &netmask4);
		if (nat_add(netif, vswitchif) < 0)
			return -1;
		netif_set_up(vswitchif);
	}

	if (tunname) {
		struct netif *tunif;
		tunif = tunif_add(base, tunname, 0);
		if (!tunif)
			return -1;
		IP4_ADDR(&ipaddr4, 10, 0, 7, 1);
		IP4_ADDR(&netmask4, 255, 255, 255, 255);
		netif_set_ipaddr(tunif, &ipaddr4);
		netif_set_netmask(tunif, &netmask4);
		if (nat_add(netif, tunif) < 0)
			return -1;
		netif_set_up(tunif);
	}

	if (tapname) {
		struct netif *tapif;
		tapif = tunif_add(base, tapname, 0);
		if (!tapif)
			return -1;
		IP4_ADDR(&ipaddr4, 10, 0, 8, 1);
		IP4_ADDR(&netmask4, 255, 255, 255, 0);
		netif_set_ipaddr(tapif, &ipaddr4);
		netif_set_netmask(tapif, &netmask4);
		if (nat_add(netif, tapif) < 0)
			return -1;
		netif_set_up(tapif);
	}

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

	if (delay_ms || drop != 0.0)
		nettest_add(base, netif, delay_ms, drop);

	netif_set_up(netif);
	event_base_dispatch(base);

	return 0;
}
