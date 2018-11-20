#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>
#include <lwip/priv/tcp_priv.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include "socks.h"
#include "socks4.h"
#include "socks5.h"
#include "util/host.h"
#include "container_of.h"
#include "util/sockaddr.h"
#include "util/lwipevbuf.h"

void
socks_kill(struct socks_data *data)
{
	if (data->bev) {
		bufferevent_free(data->bev);
		data->bev = NULL;
	}
	host_abort(&data->host);
	if (data->lwipevbuf) {
		lwipevbuf_free(data->lwipevbuf);
		data->lwipevbuf = NULL;
	}
#if LWIP_IPV4
	if (data->listen_pcb4) {
		tcp_err(data->listen_pcb4, NULL);
		tcp_abort(data->listen_pcb4);
		data->listen_pcb4 = NULL;
	}
	if (data->upcb4) {
		udp_remove(data->upcb4);
		data->upcb4 = NULL;
	}
#endif
#if LWIP_IPV6
	if (data->listen_pcb6) {
		tcp_err(data->listen_pcb6, NULL);
		tcp_abort(data->listen_pcb6);
		data->listen_pcb6 = NULL;
	}
	if (data->upcb6) {
		udp_remove(data->upcb6);
		data->upcb6 = NULL;
	}
#endif
	if (data->udp_event) {
		event_free(data->udp_event);
		data->udp_event = NULL;
	}
	if (data->udp_pbuf) {
		pbuf_free(data->udp_pbuf);
		data->udp_pbuf = NULL;
	}
	data->kill(data);
}

static void
bufferevent_finish_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *buf = bufferevent_get_output(bev);
	if (!evbuffer_get_length(buf))
		bufferevent_free(bev);
}

static void
bufferevent_finish_eventcb(struct bufferevent *bev, short events, void *ctx)
{
	if (events & (BEV_EVENT_ERROR|BEV_EVENT_EOF))
		bufferevent_free(bev);
}

static void
bufferevent_finish(struct bufferevent *bev)
{
	bufferevent_disable(bev, EV_READ);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	bufferevent_setcb(bev, NULL, bufferevent_finish_writecb,
				bufferevent_finish_eventcb, NULL);
	bufferevent_finish_writecb(bev, NULL);
}

void
socks_flush(struct socks_data *data)
{
	bufferevent_finish(data->bev);
	data->bev = NULL;
	socks_kill(data);
}

static void
socks_udp_recv(void *priv, struct udp_pcb *pcb, struct pbuf *p,
				const ip_addr_t *addr, u16_t port)
{
	struct socks_data *data = priv;
	data->udp_recv(data, p, addr, port);
	pbuf_free(p);
}

static void
socks_udp_read(const int fd, short int method, void *priv)
{
	struct socks_data *data = priv;
	struct pbuf *p = data->udp_pbuf;
	unsigned int offset;
	int len;

	offset = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN +
				PBUF_IP_HLEN + PBUF_TRANSPORT_HLEN;

	/* Reset the pbuf and allocate network header space */
	p->len = p->tot_len = data->udp_pbuf_len;
	p->payload = LWIP_MEM_ALIGN((void *)((u8_t *)p +
			LWIP_MEM_ALIGN_SIZE(sizeof(struct pbuf)) + offset));

	len = recv(fd, p->payload, p->len, 0);
	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: read %d bytes of udp from client\n", __func__, len));
	if (len < 0) {
		if (errno == EAGAIN || errno == EINTR)
			return;
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: UDP read error\n", __func__));
		return;
	}
	p->len = p->tot_len = len;
	data->udp_send(data, p);
}

struct udp_pcb *
socks_udp_bind_pcb(struct socks_data *data, const ip_addr_t *ipaddr)
{
	struct udp_pcb *pcb = udp_new();
	if (!pcb)
		return NULL;

	if (udp_bind(pcb, ipaddr, data->port) < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: udp_bind failed\n", __func__));
		udp_remove(pcb);
		return NULL;
	}

	udp_recv(pcb, socks_udp_recv, data);

	return pcb;
}

int
socks_udp_bind(struct event_base *base, struct socks_data *data)
{
	struct event *event;
	struct sockaddr addr;
	socklen_t addrlen;
	int fd;
	int success = 0;

	memcpy(&addr, &data->server->addr, data->server->addr_len);
	if (addr.sa_family == AF_INET)
		((struct sockaddr_in *) &addr)->sin_port = 0;
	else if (addr.sa_family == AF_INET6)
		((struct sockaddr_in6 *) &addr)->sin6_port = 0;
	else {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: Invalid address family\n", __func__));
		return -1;
	}

	fd = socket(addr.sa_family, SOCK_DGRAM|O_NONBLOCK, IPPROTO_UDP);
	if (fd < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: socket %m\n", __func__));
		return -1;
	}

	if (bind(fd, &addr, data->server->addr_len) < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: bind %m\n", __func__));
		close(fd);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);
	if (getsockname(fd, &addr, &addrlen) < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: getsockname %m\n", __func__));
		close(fd);
		return -1;
	}

	if (addr.sa_family == AF_INET)
		data->udp_port =
			ntohs(((struct sockaddr_in *) &addr)->sin_port);
	else if (addr.sa_family == AF_INET6)
		data->udp_port =
			ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);

	addrlen = sizeof(addr);
	if (ip_addr_to_sockaddr(&data->ipaddr, data->port, &addr, &addrlen) < 0) {
		close(fd);
		return -1;
	}

	if (connect(fd, &addr, addrlen) < 0) {
		LWIP_DEBUGF(SOCKS_DEBUG, ("%s: connect %m\n", __func__));
		close(fd);
		return -1;
	}

	event = event_new(base, fd, EV_READ|EV_PERSIST, socks_udp_read, data);
	event_add(event, NULL);

#if LWIP_IPV4
	data->upcb4 = socks_udp_bind_pcb(data, IP4_ADDR_ANY);
	if (data->upcb4)
		success = 1;
#endif
#if LWIP_IPV6
	data->upcb6 = socks_udp_bind_pcb(data, IP6_ADDR_ANY);
	if (data->upcb6)
		success = 1;
#endif

	if (!success) {
		event_free(event);
		close(fd);
		return -1;
	}

	data->udp_pbuf = pbuf_alloc(PBUF_RAW, 2048, PBUF_RAM);
	data->udp_pbuf_len = 2048;
	data->udp_fd = fd;
	data->udp_event = event;

	return 0;
}

static err_t
socks_tcp_accept(void *ctx, struct tcp_pcb *pcb, err_t err)
{
	struct socks_data *data = ctx;

	if (err < 0) {
		socks_kill(data);
		return err;
	}

#if LWIP_IPV4
	tcp_abort(data->listen_pcb4);
	data->listen_pcb4 = NULL;
#endif
#if LWIP_IPV6
	tcp_abort(data->listen_pcb6);
	data->listen_pcb6 = NULL;
#endif

	data->lwipevbuf = lwipevbuf_new(pcb);

	if (data->server->keep_alive) {
		pcb->so_options |= SOF_KEEPALIVE;
		pcb->keep_intvl = data->server->keep_alive;
		pcb->keep_idle = data->server->keep_alive;
	}

	data->connect_ok(data);

	return ERR_OK;
}

static struct tcp_pcb *
socks_tcp_listen(struct socks_data *data, const ip_addr_t *ipaddr)
{
	struct tcp_pcb *pcb, *listen_pcb;
	err_t ret;

	pcb = tcp_new();
	if (!pcb)
		return NULL;

	ip_set_option(pcb, SOF_REUSEADDR);

	/* FIXME: Listen on both when dual stack */
	ret = tcp_bind(pcb, ipaddr, data->port);
	if (ret < 0) {
		tcp_abort(pcb);
		return NULL;
	}

	listen_pcb = tcp_listen(pcb);
	if (!listen_pcb) {
		tcp_abort(pcb);
		return NULL;
	}

	tcp_arg(listen_pcb, data);
	tcp_accept(listen_pcb, socks_tcp_accept);

	return listen_pcb;
}

int
socks_tcp_bind(struct socks_data *data)
{
	int ret = -1;
#if LWIP_IPV4
	data->listen_pcb4 = socks_tcp_listen(data, IP4_ADDR_ANY);
	if (data->listen_pcb4)
		ret = 0;
#endif
#if LWIP_IPV6
	data->listen_pcb6 = socks_tcp_listen(data, IP6_ADDR_ANY);
	if (data->listen_pcb6)
		ret = 0;
#endif

	return ret;
}

static void
socks_tcp_eventcb(struct lwipevbuf *bev, short what, void *ctx)
{
	struct socks_data *data = ctx;

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));

	if (what & BEV_EVENT_CONNECTED) {
		data->connect_ok(data);
	} else {
		lwipevbuf_free(data->lwipevbuf);
		data->lwipevbuf = NULL;
		data->connect_failed(data);
	}
}

static void
socks_tcp_connect_init(struct socks_data *data)
{
	struct lwipevbuf *lwipevbuf;

	bufferevent_disable(data->bev, EV_READ);
	lwipevbuf = lwipevbuf_new(NULL);
	if (data->server->keep_alive) {
		lwipevbuf->pcb->so_options |= SOF_KEEPALIVE;
		lwipevbuf->pcb->keep_intvl = data->server->keep_alive;
		lwipevbuf->pcb->keep_idle = data->server->keep_alive;
	}
	data->lwipevbuf = lwipevbuf;

	lwipevbuf_setcb(lwipevbuf, NULL, NULL, socks_tcp_eventcb, data);
}

void
socks_tcp_connect(struct socks_data *data)
{
	struct sockaddr addr;
	socklen_t addrlen;

	socks_tcp_connect_init(data);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: %s:%d\n", __func__,
				ipaddr_ntoa(&data->ipaddr), data->port));

	addrlen = sizeof(addr);
	ip_addr_to_sockaddr(&data->ipaddr, data->port, &addr, &addrlen);

	lwipevbuf_connect(data->lwipevbuf, &addr, addrlen);
}

void
socks_tcp_connect_hostname(struct socks_data *data)
{
	socks_tcp_connect_init(data);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: %s:%d\n", __func__,
				data->host.fqdn, data->port));

	lwipevbuf_connect_hostname(data->lwipevbuf, AF_UNSPEC, data->host.fqdn, data->port);
}

static void
socks_request_eventcb(struct bufferevent *bev, short what, void *ctx)
{
	socks_kill(ctx);
}

static void
socks_request_cb(struct bufferevent *bev, void *ctx)
{
	struct socks_data *data = ctx;

	if (evbuffer_get_length(bufferevent_get_input(bev)) < data->req_len) {
		bufferevent_enable(bev, EV_READ);
		bufferevent_setwatermark(bev, EV_READ, data->req_len, 256*1024);
		bufferevent_setcb(bev, socks_request_cb, NULL,
					socks_request_eventcb, ctx);
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
	struct socks_server *s = ctx;
	u_char version;

	bufferevent_read(bev, &version, 1);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s: socks version %d\n", __func__, version));

	switch (version) {
#if LWIP_IPV4
	case 4:
		socks4_start(s, bev);
		break;
#endif
	case 5:
		socks5_start(s, bev);
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
	bufferevent_setwatermark(bev, EV_READ, 1, 262144);
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
	struct socks_server *s;
	int ret;

	s = malloc(sizeof(*s));
	memset(s, 0, sizeof(*s));
	s->keep_alive = keep_alive;

	memset(&hints, 0, sizeof(hints));
	/* Default to IPv4 if host isn't specified */
	hints.ai_family = host ? AF_UNSPEC : AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, port, &hints, &result);
	if (ret < 0) {
		fprintf(stderr, "%s: %s\n", __func__, gai_strerror(ret));
		return ret;
	}

	memcpy(&s->addr, result->ai_addr, result->ai_addrlen);
	s->addr_len = result->ai_addrlen;

	evl = evconnlistener_new_bind(base, socks_accept, (void *) s,
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
