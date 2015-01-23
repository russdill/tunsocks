#ifndef __SOCKS_H__
#define __SOCKS_H__

#include <sys/types.h>

#include "host.h"

struct event_base;
struct bufferevent;
struct tcp_pcb;

struct socks_data {
	ip_addr_t ipaddr;
	u_int16_t port;
	struct host_data host;
	struct tcp_pcb *pcb;
	struct bufferevent *bev;
	void (*connect_ok)(struct socks_data*);
	void (*connect_failed)(struct socks_data*);
	void (*kill)(struct socks_data*);
	int req_len;
	void (*req_cb)(struct socks_data*);
	int *keep_alive;
};

void socks_kill(struct socks_data *data);
void socks_flush(struct socks_data *data);
int socks_tcp_bind(struct socks_data *data);
void socks_tcp_connect(struct socks_data *data);
void socks_request(struct socks_data *data, int n,
				void (*cb)(struct socks_data*));
int socks_listen(struct event_base *base, const char *host,
					const char *port, int *keep_alive);

#endif
