#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>

#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/stats.h>
#include <lwip/ip4.h>
#include <lwip/init.h>
#include <lwip/tcp_impl.h>
#include <lwip/dns.h>
#include <lwip/snmp_mib2.h>

#ifdef USE_PCAP
#include <pcap/pcap.h>
#endif

#include <event2/event.h>

#include "tunif.h"

struct tunif_data {
	struct netif netif;
	int fd;
	struct event *ev;
	u_char buf[4096];
#ifdef USE_PCAP
	pcap_dumper_t *pcap_dumper;
#endif
};

static err_t
tunif_output(struct netif *netif, struct pbuf *p, const ip_addr_t *ipaddr)
{
	struct tunif_data *data = netif->state;
	int len;

	len = pbuf_copy_partial(p, data->buf, sizeof(data->buf), 0);
#ifdef USE_PCAP
	if (data->pcap_dumper) {
		struct pcap_pkthdr hdr = {.caplen = len, .len = len};
		gettimeofday(&hdr.ts, NULL);
		pcap_dump((void *) data->pcap_dumper, &hdr, data->buf);
	}
#endif
	len = write(data->fd, data->buf, len);
	if (len < 0)
		LINK_STATS_INC(link.drop);
	else
		LINK_STATS_INC(link.xmit);

	return 0;
}

static void
tunif_ready(evutil_socket_t fd, short events, void *ctx)
{
	struct tunif_data *data = ctx;
	int ret;

again:
	ret = read(fd, data->buf, sizeof(data->buf));
	if ((ret < 0 && errno != EAGAIN) || !ret) {
		/* FATAL */
		event_del(data->ev);
	} else if (ret > 0) {
		struct pbuf *p;
		p = pbuf_alloc(PBUF_IP, ret, PBUF_POOL);
		if (!p) {
			LINK_STATS_INC(link.memerr);
			LINK_STATS_INC(link.drop);
			return;
		}
		LINK_STATS_INC(link.recv);
#ifdef USE_PCAP
		if (data->pcap_dumper) {
			struct pcap_pkthdr hdr = {.caplen = ret, .len = ret};
			gettimeofday(&hdr.ts, NULL);
			pcap_dump((void *) data->pcap_dumper, &hdr, data->buf);
		}
#endif
		pbuf_take(p, data->buf, ret);
		if (data->netif.input(p, &data->netif) < 0)
			pbuf_free(p);
		goto again;
	}
}

static err_t
tunif_init(struct netif *netif)
{
	MIB2_INIT_NETIF(netif, snmp_ifType_other, 0);
	netif->name[0] = 't';
	netif->name[1] = 'p';

	netif->output = tunif_output;
	netif->mtu = 1360;
	netif->flags = NETIF_FLAG_LINK_UP;

	return 0;
}

struct netif *
tunif_add(struct event_base *base, int fd_in, int fd_out, const char *pcap_file)
{
	struct tunif_data *data;

	data = calloc(1, sizeof(*data));

#ifdef USE_PCAP
	if (pcap_file) {
		pcap_t *p;
		p = pcap_open_dead(DLT_RAW, 2000);
		data->pcap_dumper = pcap_dump_open(p, pcap_file);
	}
#endif

	evutil_make_socket_nonblocking(fd_in);
	evutil_make_socket_nonblocking(fd_out);

	data->fd = fd_out;
	data->ev = event_new(base, fd_in, EV_READ | EV_PERSIST, tunif_ready, data);
	event_add(data->ev, NULL);
	netif_add(&data->netif, NULL, NULL, NULL, data, tunif_init, ip_input);
	netif_set_default(&data->netif);
	return &data->netif;
}
