#include <stdlib.h>
#include <lwip/tcp.h>
#include <lwip/dns.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include "container_of.h"
#include "socks.h"
#include "socks5.h"
#include "pipe.h"

#define SOCKS5_ATYP_IPV4	0x01
#define SOCKS5_ATYP_FQDN	0x03

#define SOCKS5_CMD_CONNECT	0x01
#define SOCKS5_CMD_BIND		0x02

#define SOCKS5_RESP_GRANTED		0x00
#define SOCKS5_RESP_FAILURE		0x01
#define SOCKS5_RESP_PERM		0x02
#define SOCKS5_RESP_NET_UNREACH		0x03
#define SOCKS5_RESP_HOST_UNREACH	0x04
#define SOCKS5_RESP_REFUSED		0x05
#define SOCKS5_RESP_TTL			0x06
#define SOCKS5_RESP_CMD_UNSUP		0x07
#define SOCKS5_RESP_ADDR_UNSUP		0x08

struct socks5_req {
	u_char	version;
	u_char	cmd;
	u_char	reserved;
	u_char	atyp;
} __attribute__((__packed__));

struct socks5_rep {
	u_char version;
	u_char auth;
} __attribute__((__packed__));

struct socks5_data {
	struct socks_data socks;
	u_char cmd;
};

static void
socks5_kill(struct socks_data *sdata)
{
	struct socks5_data *data;
	data = container_of(sdata, struct socks5_data, socks);
	free(data);
}

static void
socks5_response(struct socks_data *sdata, int code, int connected, int die)
{
	struct socks5_data *data;
	struct socks5_req req = {
		.version = 5,
		.cmd = code,
		.atyp = SOCKS5_ATYP_IPV4
	};
	u_int16_t port;
	u_int16_t addr;

	data = container_of(sdata, struct socks5_data, socks);

        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: code %d, die %d\n", __func__, code, die));
	bufferevent_write(sdata->bev, &req, sizeof(req));
	if (!die) {
		if (connected && data->cmd == SOCKS5_CMD_BIND) {
			addr = sdata->pcb->remote_ip.addr;
			port = htons(sdata->pcb->remote_port);
		} else {
			addr = sdata->pcb->local_ip.addr;
			port = htons(sdata->pcb->local_port);
		}
	} else {
		addr = sdata->ipaddr.addr;
		port = sdata->port;
	}
	bufferevent_write(sdata->bev, &addr, 4);
	bufferevent_write(sdata->bev, &port, 2);
	if (die)
		socks_flush(sdata);
}

static void socks5_connect_ok(struct socks_data *sdata)
{
	struct socks5_data *data;
 	data = container_of(sdata, struct socks5_data, socks);

	socks5_response(sdata, SOCKS5_RESP_GRANTED, 1, 0);

	pipe_join(sdata->pcb, sdata->bev);
	free(data);
}

static void socks5_connect_failed(struct socks_data *sdata)
{
	socks5_response(sdata, SOCKS5_RESP_HOST_UNREACH, 0, 1);
}

static void
socks5_read_port(struct socks_data *sdata)
{
	struct socks5_data *data;
 	data = container_of(sdata, struct socks5_data, socks);

	bufferevent_read(sdata->bev, &sdata->port, 2);
	sdata->port = ntohs(sdata->port);

        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: port %d\n", __func__, sdata->port));

	switch (data->cmd) {
	case SOCKS5_CMD_CONNECT:
		socks_tcp_connect(sdata);
		break;
	case SOCKS5_CMD_BIND:
		if (socks_tcp_bind(sdata) < 0) {
			socks5_response(sdata, SOCKS5_RESP_FAILURE, 0, 1);
		} else {
			/*
			 * If the user sends any input data at this point, it is
			 * an error
			 */
			socks_request(sdata, 1, socks5_kill);
			socks5_response(sdata, SOCKS5_RESP_GRANTED, 0, 0);
		}
		break;
	default:
		socks5_response(sdata, SOCKS5_RESP_CMD_UNSUP, 0, 1);
	}
}

static void
socks5_read_ipv4(struct socks_data *sdata)
{
	bufferevent_read(sdata->bev, &sdata->ipaddr.addr, 4);
	socks_request(sdata, 2, socks5_read_port);
}

static void
socks5_host_found(struct host_data *hdata)
{
	struct socks_data *sdata;
	sdata = container_of(hdata, struct socks_data, host);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	sdata->ipaddr = hdata->ipaddr;
	socks_request(sdata, 2, socks5_read_port);
}

static void
socks5_host_failed(struct host_data *hdata)
{
	struct socks_data *sdata;
	sdata = container_of(hdata, struct socks_data, host);

	LWIP_DEBUGF(SOCKS_DEBUG, ("%s\n", __func__));
	socks5_response(sdata, SOCKS5_RESP_FAILURE, 0, 1);
}

static void
socks5_read_fqdn(struct socks_data *sdata)
{
	bufferevent_read(sdata->bev, sdata->host.fqdn, sdata->req_len);
	sdata->host.fqdn[sdata->req_len] = '\0';
        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: fqdn %s\n", __func__, sdata->host.fqdn));
	bufferevent_disable(sdata->bev, EV_READ);
	host_lookup(&sdata->host);
}

static void
socks5_read_n_fqdn(struct socks_data *sdata)
{
	unsigned char nfqdn;

	bufferevent_read(sdata->bev, &nfqdn, 1);
        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: nfqdn %d\n", __func__, nfqdn));
	if (!nfqdn)
		socks5_response(sdata, SOCKS5_RESP_CMD_UNSUP, 0, 1);
	else
		socks_request(sdata, nfqdn, socks5_read_fqdn);
}

static void
socks5_read_hdr(struct socks_data *sdata)
{
	struct socks5_data *data;
	struct socks5_req req;

	data = container_of(sdata, struct socks5_data, socks);

	bufferevent_read(sdata->bev, &req, sizeof(req));
	if (req.version != 5) {
		socks_kill(sdata);
		return;
	}

	data->cmd = req.cmd;

        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: cmd %d, atyp %d\n", __func__, req.cmd, req.atyp));

	if (req.atyp == SOCKS5_ATYP_IPV4)
		socks_request(sdata, 4, socks5_read_ipv4);
	else if (req.atyp == SOCKS5_ATYP_FQDN)
		socks_request(sdata, 1, socks5_read_n_fqdn);
	else
		socks5_response(sdata, SOCKS5_RESP_ADDR_UNSUP, 0, 1);
}

static void
socks5_read_auth(struct socks_data *sdata)
{
	u_char auth[255];
	struct socks5_rep rep = {5, 0};

	if (sdata->req_len)
		bufferevent_read(sdata->bev, auth, sdata->req_len);

	bufferevent_write(sdata->bev, &rep, sizeof(rep));

	socks_request(sdata, sizeof(struct socks5_req), socks5_read_hdr);
}

static void
socks5_read_n_auth(struct socks_data *sdata)
{
	unsigned char nauth;

	bufferevent_read(sdata->bev, &nauth, 1);

        LWIP_DEBUGF(SOCKS_DEBUG, ("%s: nauth %d\n", __func__, nauth));

	socks_request(sdata, nauth, socks5_read_auth);
}

void
socks5_start(struct bufferevent *bev, int keep_alive)
{
	struct socks5_data *data;
	struct socks_data *sdata;

	data = calloc(1, sizeof(struct socks5_data));
	sdata = &data->socks;
	sdata->host.found = socks5_host_found;
	sdata->host.failed = socks5_host_failed;
	sdata->connect_ok = socks5_connect_ok;
	sdata->connect_failed = socks5_connect_failed;
	sdata->kill = socks5_kill;
	sdata->bev = bev;
	sdata->keep_alive = keep_alive;
	socks_request(sdata, 1, socks5_read_n_auth);
}
