#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <netdb.h>
#include <string.h>
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>

#include "container_of.h"
#include "host.h"
#include "pipe.h"
#include "forward_remote.h"

struct forward_data {
	struct addrinfo *remote;
	struct event_base *base;
	int *keep_alive;
};

static void forward_tcp_err(void *ctx, err_t err)
{
	bufferevent_free(ctx);
}

static void forward_connect(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_CONNECTED)
		pipe_join(ctx, bev);
	else {
		bufferevent_free(bev);
		tcp_err(ctx, NULL);
		tcp_abort(ctx);
	}
}

static err_t forward_tcp_accept(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct forward_data *data = ctx;
	struct addrinfo *remote = data->remote;
	struct bufferevent *bev;

	bev = bufferevent_socket_new(data->base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, NULL, NULL, forward_connect, pcb);

	if (bufferevent_socket_connect(bev, remote->ai_addr,
				remote->ai_addrlen) < 0) {
		/* die */
		bufferevent_free(bev);
		tcp_abort(pcb);
		return ERR_ABRT;
	}

	pcb->flags |= TF_NODELAY;

	if (*data->keep_alive) {
		pcb->so_options |= SOF_KEEPALIVE;
		pcb->keep_intvl = *data->keep_alive;
		pcb->keep_idle = *data->keep_alive;
	}

	tcp_arg(pcb, bev);
	tcp_err(pcb, forward_tcp_err);

	return ERR_OK;
}


int forward_remote(struct event_base *base, const char *remote_port,
	const char *local_host, const char *local_port, int *keep_alive)
{
	u_int16_t port;
	char *endptr;
	struct tcp_pcb *pcb;
	struct tcp_pcb *_pcb;
	struct addrinfo hints;
	struct addrinfo *result;
	struct forward_data *data;
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

	pcb = tcp_new();
	if (!pcb) {
		freeaddrinfo(result);
		return -1;
	}

	pcb->flags |= TF_NODELAY;
	ip_set_option(pcb, SOF_REUSEADDR);

	ret = tcp_bind(pcb, IP_ADDR_ANY, port);
	if (ret < 0) {
		freeaddrinfo(result);
		tcp_abort(pcb);
		return -1;
	}

	_pcb = tcp_listen(pcb);
	if (!_pcb) {
		freeaddrinfo(result);
		tcp_abort(pcb);
		return -1;
	}
	pcb = _pcb;

	data = calloc(1, sizeof(*data));
	data->remote = result;
	data->base = base;
	data->keep_alive = keep_alive;

	tcp_arg(pcb, data);
	tcp_accept(pcb, forward_tcp_accept);

	return 0;
}
