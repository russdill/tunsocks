#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <netdb.h>
#include <string.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>

#include "container_of.h"
#include "util/host.h"
#include "forward_remote.h"
#include "util/lwipevbuf.h"
#include "util/lwipevbuf_bev_join.h"

struct forward_data {
	struct addrinfo *remote;
	struct event_base *base;
	int keep_alive;
};

static err_t forward_tcp_accept(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct forward_data *data = ctx;
	struct addrinfo *remote = data->remote;
	struct bufferevent *bev;
	struct lwipevbuf *lwipevbuf;

	bev = bufferevent_socket_new(data->base, -1, BEV_OPT_CLOSE_ON_FREE);

	if (bufferevent_socket_connect(bev, remote->ai_addr,
				remote->ai_addrlen) < 0) {
		/* die */
		bufferevent_free(bev);
		tcp_abort(pcb);
		return ERR_ABRT;
	}

	if (data->keep_alive) {
		pcb->so_options |= SOF_KEEPALIVE;
		pcb->keep_intvl = data->keep_alive;
		pcb->keep_idle = data->keep_alive;
	}

	lwipevbuf = lwipevbuf_new(pcb);
	lwipevbuf_bev_join(bev, lwipevbuf, 256*1024, NULL, NULL, NULL, NULL, NULL, NULL);

	return ERR_OK;
}


static int forward_listen(struct forward_data *data, const ip_addr_t *ipaddr, int port)
{
	struct tcp_pcb *pcb;
	struct tcp_pcb *_pcb;
	err_t ret;

	pcb = tcp_new();
	if (!pcb)
		return -1;

	ip_set_option(pcb, SOF_REUSEADDR);

	ret = tcp_bind(pcb, ipaddr, port);
	if (ret < 0) {
		tcp_abort(pcb);
		return -1;
	}

	_pcb = tcp_listen(pcb);
	if (!_pcb) {
		tcp_abort(pcb);
		return -1;
	}
	pcb = _pcb;

	tcp_arg(pcb, data);
	tcp_accept(pcb, forward_tcp_accept);

	return 0;
}

int forward_remote(struct event_base *base, const char *remote_port,
	const char *local_host, const char *local_port, int keep_alive)
{
	u_int16_t port;
	char *endptr;
	struct addrinfo hints;
	struct addrinfo *result;
	struct forward_data *data;
	int success = 0;
	err_t ret;

	port = strtoul(remote_port, &endptr, 0);
	if (endptr[0]) {
		struct servent *s;
		s = getservbyname(remote_port, "tcp");
		port = ntohs(s->s_port);
		endservent();
		if (!s)
			return -1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(local_host, local_port, &hints, &result);
	if (ret < 0) {
		fprintf(stderr, "%s: %s\n", __func__, gai_strerror(ret));
		return ret;
	}

	data = calloc(1, sizeof(*data));
	data->remote = result;
	data->base = base;
	data->keep_alive = keep_alive;

#if LWIP_IPV4
	success = forward_listen(data, IP4_ADDR_ANY, port) == 0;
#endif
#if LWIP_IPV6
	success = forward_listen(data, IP6_ADDR_ANY, port) == 0;
#endif

	if (!success) {
		freeaddrinfo(result);
		free(data);
	}

	return 0;
}
