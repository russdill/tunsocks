#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "socks.h"
#include "socks4.h"
#include "socks5.h"
#include "host.h"
#include "container_of.h"

void
socks_kill(struct socks_data *data)
{
	bufferevent_free(data->bev);
	data->bev = NULL;
	host_abort(&data->host);
	if (data->pcb) {
		tcp_err(data->pcb, NULL);
		tcp_abort(data->pcb);
		data->pcb = NULL;
	}
	data->kill(data);
}

static void
socks_flush_fin(struct bufferevent *bev, void *ctx)
{
	socks_kill(ctx);
}

static void
socks_request_error(struct bufferevent *bev, short events, void *ctx)
{
	socks_kill(ctx);
}

void
socks_flush(struct socks_data *data)
{
	struct evbuffer *buf;
	buf = bufferevent_get_output(data->bev);
	if (evbuffer_get_length(buf)) {
		bufferevent_disable(data->bev, EV_READ);
		bufferevent_setwatermark(data->bev, EV_WRITE, 0, 16384);
		bufferevent_setcb(data->bev, NULL, socks_flush_fin,
				socks_request_error, data);
	} else
		socks_flush_fin(data->bev, data);
}

static err_t
socks_tcp_accept(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct socks_data *data = ctx;

	if (err < 0) {
		socks_kill(data);
		return err;
	}

	tcp_abort(data->pcb);
	data->pcb = pcb;

	pcb->flags |= TF_NODELAY;
	if (data->keep_alive) {
		pcb->so_options |= SOF_KEEPALIVE;
		pcb->keep_intvl = data->keep_alive;
		pcb->keep_idle = data->keep_alive;
	}

	data->connect_ok(data);

	return ERR_OK;
}

int
socks_tcp_bind(struct socks_data *data)
{
	struct tcp_pcb *pcb;
	err_t ret;

	pcb = tcp_new();
	if (!pcb)
		return -1;

	pcb->flags |= TF_NODELAY;
	ip_set_option(pcb, SOF_REUSEADDR);

	ret = tcp_bind(pcb, IP_ADDR_ANY, data->port);
	if (ret < 0) {
		tcp_abort(pcb);
		return -1;
	}

	data->pcb = tcp_listen(pcb);
	if (!data->pcb) {
		tcp_abort(pcb);
		return -1;
	}

	tcp_arg(data->pcb, data);
	tcp_accept(data->pcb, socks_tcp_accept);

	return 0;
}

static void
socks_tcp_connect_err(void *ctx, err_t err)
{
	struct socks_data *data = ctx;
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	data->pcb = NULL;
	data->connect_failed(data);
}

static err_t
socks_tcp_connect_ok(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct socks_data *data = ctx;
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	data->connect_ok(data);
	return ERR_OK;
}

void
socks_tcp_connect(struct socks_data *data)
{
	struct tcp_pcb *pcb;
	err_t ret;

	bufferevent_disable(data->bev, EV_READ);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: %s:%d\n", __func__,
				ipaddr_ntoa(&data->ipaddr), data->port));

	pcb = tcp_new();
	if (!pcb)
		data->connect_failed(data);

	pcb->flags |= TF_NODELAY;
	if (data->keep_alive) {
		pcb->so_options |= SOF_KEEPALIVE;
		pcb->keep_intvl = data->keep_alive;
		pcb->keep_idle = data->keep_alive;
	}

	ret = tcp_connect(pcb, &data->ipaddr, data->port, socks_tcp_connect_ok);
	if (ret < 0) {
		tcp_abort(pcb);
		data->connect_failed(data);
	} else {
		data->pcb = pcb;
		tcp_arg(pcb, data);
		tcp_err(pcb, socks_tcp_connect_err);
	}
}

static void
socks_request_cb(struct bufferevent *bev, void *ctx)
{
	struct socks_data *data = ctx;

	if (evbuffer_get_length(bufferevent_get_input(bev)) < data->req_len) {
		bufferevent_enable(bev, EV_READ);
		bufferevent_setwatermark(bev, EV_READ, data->req_len, 2048);
		bufferevent_setcb(bev, socks_request_cb, NULL,
					socks_request_error, ctx);
	} else
		data->req_cb(ctx);
}

void
socks_request(struct socks_data *data, int n, void (*cb)(struct socks_data*))
{
	data->req_len = n;
	data->req_cb = cb;
	socks_request_cb(data->bev, data);
}

static void
socks_version(struct bufferevent *bev, void *ctx)
{
	int keep_alive = (int) ctx;
	u_char version;

	bufferevent_read(bev, &version, 1);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: socks version %d\n", __func__, version));

	switch (version) {
	case 4:
		socks4_start(bev, keep_alive);
		break;
	case 5:
		socks5_start(bev, keep_alive);
		break;
	default:
		bufferevent_free(bev);
	}
}

static void
socks_error(struct bufferevent *bev, short events, void *ctx)
{
	bufferevent_free(bev);
}

static void
socks_accept(struct evconnlistener *evl, evutil_socket_t new_fd,
			struct sockaddr *addr, int socklen, void *ctx)
{
	struct event_base *base = evconnlistener_get_base(evl);
	struct bufferevent *bev;

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Accepting socks connection\n", __func__));

	bev = bufferevent_socket_new(base, new_fd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, socks_version, NULL, socks_error, ctx);
	bufferevent_setwatermark(bev, EV_READ, 1, 2048);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
}

#ifndef LEV_OPT_DEFERRED_ACCEPT
#define LEV_OPT_DEFERRED_ACCEPT 0
#endif

int
socks_listen(struct event_base *base, const char *host, const char *port,
				int keep_alive)
{
	struct evconnlistener *evl;
	struct addrinfo hints;
	struct addrinfo *result;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret < 0) {
		fprintf(stderr, "%s: %s\n", __func__, gai_strerror(ret));
		return ret;
	}

	evl = evconnlistener_new_bind(base, socks_accept, (void *) keep_alive,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC |
		LEV_OPT_REUSEABLE | LEV_OPT_DEFERRED_ACCEPT, 10,
		result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);

	if (!evl) {
		perror(__func__);
		return -1;
	}

	return 0;
}
