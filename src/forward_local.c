#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <netdb.h>
#include <string.h>
#include <lwip/tcp.h>
#include <lwip/priv/tcp_priv.h>

#include "forward_local.h"
#include "util/lwipevbuf.h"
#include "util/lwipevbuf_bev_join.h"

struct forward_remote {
	char *host;
	unsigned short port;
	int keep_alive;
};

static void forward_local_accept(struct evconnlistener *evl,
	evutil_socket_t new_fd, struct sockaddr *addr, int socklen, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(evl);
	struct forward_remote *remote = ctx;
	struct lwipevbuf *lwipevbuf;
	struct bufferevent *bev;

	lwipevbuf = lwipevbuf_new(NULL);

	if (remote->keep_alive) {
		lwipevbuf->pcb->so_options |= SOF_KEEPALIVE;
		lwipevbuf->pcb->keep_intvl = remote->keep_alive;
		lwipevbuf->pcb->keep_idle = remote->keep_alive;
	}

	if (lwipevbuf_connect_hostname(lwipevbuf, AF_UNSPEC, remote->host, remote->port) < 0) {
		lwipevbuf_free(lwipevbuf);
		return;
	}

	bev = bufferevent_socket_new(base, new_fd, BEV_OPT_CLOSE_ON_FREE);
	lwipevbuf_bev_join(bev, lwipevbuf, 256*1024, NULL, NULL, NULL, NULL, NULL, NULL);
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
