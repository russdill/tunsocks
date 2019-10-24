#ifndef __SOCKS_H__
#define __SOCKS_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "util/host.h"

struct event_base;
struct bufferevent;
struct tcp_pcb;
struct udp_pcb;
struct pbuf;
struct lwipevbuf;

struct socks_server {
	int keep_alive;
	struct sockaddr_storage addr;
	socklen_t addr_len;
};

struct socks_data {
	struct socks_server *server;

	ip_addr_t ipaddr;
	u_int16_t port;
	struct host_data host;
	struct lwipevbuf *lwipevbuf;
	struct bufferevent *bev;
	void (*connect_ok)(struct socks_data*);
	void (*connect_failed)(struct socks_data*);
	void (*kill)(struct socks_data*);
	int req_len;
	void (*req_cb)(struct socks_data*);

#if LWIP_IPV4
	struct tcp_pcb *listen_pcb4;
	struct udp_pcb *upcb4;
#endif
#if LWIP_IPV6
	struct tcp_pcb *listen_pcb6;
	struct udp_pcb *upcb6;
#endif

	int udp_fd;
	u_int16_t udp_port;
	void (*udp_recv)(struct socks_data*, struct pbuf*,
				const ip_addr_t*, u16_t);
	void (*udp_send)(struct socks_data*, struct pbuf*);
	struct event *udp_event; /* Provides notification callbacks for linux side */
	struct pbuf *udp_pbuf;
	int udp_pbuf_len;
};

void socks_kill(struct socks_data *data);
void socks_flush(struct socks_data *data);
int socks_udp_bind(struct event_base *base, struct socks_data *data);
int socks_tcp_bind(struct socks_data *data);
void socks_tcp_connect(struct socks_data *data);
void socks_tcp_connect_hostname(struct socks_data *data);
void socks_request(struct socks_data *data, int n,
				void (*cb)(struct socks_data*));
int socks_listen(struct event_base *base, const char *host,
					const char *port, int keep_alive);

#endif
