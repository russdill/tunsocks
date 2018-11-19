#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <netdb.h>
#include <string.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>

#include "container_of.h"
#include "pipe.h"
#include "forward_local.h"

struct forward_remote {
	char *host;
	unsigned short port;
	int keep_alive;
};

struct forward_data {
	struct forward_remote *remote;
	struct bufferevent *bev;
	struct tcp_pcb *pcb;
	struct host_data host;
};

static void forward_free(struct forward_data *data)
{
	bufferevent_free(data->bev);
	if (data->pcb) {
		tcp_err(data->pcb, NULL);
		tcp_abort(data->pcb);
	}
	host_abort(&data->host);
	free(data);
}

static void forward_tcp_connect_err(void *ctx, err_t err)
{
	forward_free(ctx);
}

static err_t forward_tcp_connect_ok(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct forward_data *data = ctx;
	pipe_join(pcb, data->bev);
	free(data);
	return ERR_OK;
}

static void forward_host_found(struct host_data *hdata)
{
	struct forward_data *data;
	struct tcp_pcb *pcb;
	err_t ret;

	data = container_of(hdata, struct forward_data, host);

	pcb = tcp_new();
	if (!pcb) {
		forward_free(data);
		return;
	}

	pcb->flags |= TF_NODELAY;
	if (data->remote->keep_alive) {
		pcb->so_options |= SOF_KEEPALIVE;
		pcb->keep_intvl = data->remote->keep_alive;
		pcb->keep_idle = data->remote->keep_alive;
	}

	ret = tcp_connect(pcb, &data->host.ipaddr, data->remote->port,
					forward_tcp_connect_ok);
	if (ret < 0)
		forward_free(data);
	else {
		data->pcb = pcb;
		tcp_arg(pcb, data);
		tcp_err(pcb, forward_tcp_connect_err);
	}
}

static void forward_host_failed(struct host_data *hdata)
{
	struct forward_data *data;
	data = container_of(hdata, struct forward_data, host);
	forward_free(data);
}

static void forward_error(struct bufferevent *bev, short events, void *ctx)
{
	forward_free(ctx);
}

static void forward_local_accept(struct evconnlistener *evl,
	evutil_socket_t new_fd, struct sockaddr *addr, int socklen, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(evl);
	struct forward_remote *remote = ctx;
	struct forward_data *data;

	data = calloc(1, sizeof(*data));
	data->remote = remote;
	data->host.found = forward_host_found;
	data->host.failed = forward_host_failed;
	strncpy(data->host.fqdn, remote->host, sizeof(data->host.fqdn));
	data->host.fqdn[sizeof(data->host.fqdn) - 1] = '\0';

	data->bev = bufferevent_socket_new(base, new_fd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(data->bev, NULL, NULL, forward_error, NULL);

	host_lookup(&data->host);
}

#ifndef LEV_OPT_DEFERRED_ACCEPT
#define LEV_OPT_DEFERRED_ACCEPT 0
#endif

int forward_local(struct event_base *base,
	const char *local_host, const char *local_port,
	const char *remote_host, const char *remote_port, int keep_alive)
{
	struct evconnlistener *evl;
	struct addrinfo hints;
	struct addrinfo *result;
	struct forward_remote *remote;
	u_int16_t port;
	char *endptr;
	int ret;

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

	remote = calloc(1, sizeof(*remote));
	remote->host = strdup(remote_host);
	remote->port = port;
	remote->keep_alive = keep_alive;

	evl = evconnlistener_new_bind(base, forward_local_accept, remote,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC |
		LEV_OPT_REUSEABLE | LEV_OPT_DEFERRED_ACCEPT, 10,
		result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);

	if (!evl) {
		free(remote);
		perror(__func__);
		return -1;
	}

	return 0;
}
