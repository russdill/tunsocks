#define _GNU_SOURCE
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/queue.h>
#include <stdio.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/dns.h>
#include <event2/http_struct.h>
#include <event2/bufferevent.h>
#include <event2/keyvalq_struct.h>

#include <lwip/tcp.h>

#include "http/http.h"

#include "evhttp_extra.h"

#ifndef LIBEVENT_TEST
#include "util/lwipevbuf_bev_join.h"
#include "util/lwipevbuf.h"
#else
#include "bufferevent_join.h"
#endif

#ifndef PACKAGE
#define PACKAGE "util/libevent-http"
#endif
#ifndef VERSION
#define VERSION "0.1"
#endif

struct evhttp_proxy_request {
#ifndef LIBEVENT_TEST
	struct lwipevbuf *server_bev;
#else
	struct bufferevent *server_bev;
#endif
	struct evhttp_request *server_req;
	struct evhttp_request *client_req;
};

struct http_proxy {
#ifdef LIBEVENT_TEST
	struct evdns_base *dnsbase;
#endif
	struct evhttp *evh;
	int keep_alive;
};

static void
client_send_error(struct evhttp_request *req, int error, const char *format, ...)
{
	struct evbuffer *buf = evbuffer_new();
	va_list args;
	evhttp_response_code_(req, error, NULL);

	evbuffer_add_printf(buf, "<html><head><title>%d %s</title></head><body>",
				error, req->response_code_line);
	va_start(args, format);
	evbuffer_add_vprintf(buf, format, args);
	va_end(args);
	evbuffer_add_printf(buf, "</body></html>");

	evhttp_send_page_(req, buf);
	evbuffer_free(buf);
}

static void
client_req_eof(struct bufferevent *bev, void *ctx)
{
	struct evhttp_connection *evcon = ctx;
	evhttp_connection_free(evcon);
}

static void
proxy_req_join(struct evhttp_proxy_request *proxy_req)
{
	struct evhttp_connection *client_evcon = proxy_req->client_req->evcon;
	struct bufferevent *client_bev = evhttp_connection_get_bufferevent(client_evcon);

	evhttp_connection_set_closecb(client_evcon, NULL, NULL);
#ifndef LIBEVENT_TEST
	lwipevbuf_bev_join(client_bev, proxy_req->server_bev, 256*1024,
		client_req_eof, client_evcon, NULL, NULL, NULL, NULL);
#else
	bufferevent_join(client_bev, proxy_req->server_bev, 256*1024,
		client_req_eof, client_evcon, NULL, NULL, NULL, NULL);
#endif

	if (proxy_req->server_req)
		evhttp_request_free(proxy_req->server_req);

	free(proxy_req);
}

static void
remove_headers(struct evkeyvalq *headers, const char *key)
{
	const char *val;
	char *s, *n, *sdup;
	/* remove connection headers */
	val = evhttp_find_header(headers, key);
	if (!val)
		return;

	sdup = strdup(val);
	for (n = sdup, s = sdup; n; s = n + 1) {
		n = strpbrk(s, "()<>@,;:\\\"/[]?={} \t");
		if (n)
			*n = '\0';
		if (*s)
			evhttp_remove_header(headers, s);
	}
	free(sdup);

	evhttp_remove_header(headers, key);
}

static int
proxy_req_server_headers_done(struct evhttp_proxy_request *proxy_req)
{
	struct evhttp_request *client_req = proxy_req->client_req;
	struct bufferevent *client_bev;
	struct evhttp_connection *client_evcon;
	struct evhttp_request *server_req = proxy_req->server_req;
	struct evbuffer *client_output;
	struct evkeyval *header;
	const char *via;
	const char *hostname = "unknown";

	evhttp_response_code_(client_req, server_req->response_code, server_req->response_code_line);

	client_evcon = evhttp_request_get_connection(client_req);
	client_bev = evhttp_connection_get_bufferevent(client_evcon);
	client_output = bufferevent_get_output(client_bev);
	evbuffer_add_printf(client_output,
	    "HTTP/%d.%d %d %s\r\n",
	    client_req->major, client_req->minor, client_req->response_code,
	    client_req->response_code_line);

	remove_headers(client_req->input_headers, "connection");
	remove_headers(client_req->input_headers, "proxy-connection");

	evhttp_remove_header(server_req->input_headers, "keep-alive");
	evhttp_remove_header(server_req->input_headers, "proxy-authenticate");
	evhttp_remove_header(server_req->input_headers, "proxy-authorization");

	/* Add our via header */
	via = evhttp_find_header(server_req->input_headers, "via");
	if (via) {
		evbuffer_add_printf(client_output, "Via: %s, ", via);
		evhttp_remove_header(server_req->input_headers, "via");
	} else
		evbuffer_add_printf(client_output, "Via: ");
	evbuffer_add_printf(client_output, "%d.%d %s (%s/%s)\r\n",
			server_req->major, server_req->minor,
			hostname, PACKAGE, VERSION);

	TAILQ_FOREACH(header, server_req->input_headers, next) {
		evbuffer_add_printf(client_output, "%s: %s\r\n",
		    header->key, header->value);
	}
	evbuffer_add(client_output, "\r\n", 2);

	/* Queue any data the server already sent */
	bufferevent_write_buffer(client_bev, evhttp_request_get_input_buffer(server_req));

	proxy_req_join(proxy_req);

	return 0;
}

static void
proxy_req_client_closecb(struct evhttp_connection *evcon, void *ctx)
{
	struct evhttp_proxy_request *proxy_req = ctx;
#ifndef LIBEVENT_TEST
	lwipevbuf_free(proxy_req->server_bev);
#else
	bufferevent_free(proxy_req->server_bev);
#endif
	if (proxy_req->server_req)
		evhttp_request_free(proxy_req->server_req);
	free(proxy_req);
}

static void
proxy_req_free(struct evhttp_proxy_request *proxy_req)
{
	struct evhttp_connection *client_evcon;

#ifndef LIBEVENT_TEST
	lwipevbuf_free(proxy_req->server_bev);
#else
	bufferevent_free(proxy_req->server_bev);
#endif

	if (proxy_req->server_req)
		evhttp_request_free(proxy_req->server_req);

	client_evcon = evhttp_request_get_connection(proxy_req->client_req);
	evhttp_connection_set_closecb(client_evcon, NULL, NULL);

	if (!proxy_req->client_req->userdone)
		evhttp_connection_free(client_evcon);

	free(proxy_req);
}

static void
#ifndef LIBEVENT_TEST
proxy_req_eventcb(struct lwipevbuf *bev, short what, void *ctx)
#else
proxy_req_eventcb(struct bufferevent *bev, short what, void *ctx)
#endif
{
	struct evhttp_proxy_request *proxy_req = ctx;
	struct evhttp_request *client_req = proxy_req->client_req;

	if (what & BEV_EVENT_TIMEOUT) {
		client_send_error(client_req, 403,
			"Server communication timed out");
	} else if (what & BEV_EVENT_ERROR) {
		const char *str;

#ifndef LIBEVENT_TEST
		str = evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR());
#elif defined(LWIP_DEBUG)
		str = lwip_strerr(bev->tcp_err);
#else
		str = "unspecified";
#endif
		if (what & BEV_EVENT_READING) {
			client_send_error(client_req, 503,
				"Error reading data from server: %s", str);
		} else {
			client_send_error(client_req, 503,
				"Error writing data to server: %s", str);
		}
	} else if (what & BEV_EVENT_EOF) {
		client_send_error(client_req, 500,
			"EOF while establishing communication with server");
	}

	proxy_req_free(proxy_req);
}

static void
#ifndef LIBEVENT_TEST
proxy_req_read_header(struct lwipevbuf *bufev, void *arg)
#else
proxy_req_read_header(struct bufferevent *bufev, void *arg)
#endif
{
	enum message_read_status res;
	struct evhttp_proxy_request *proxy_req = arg;
	struct evhttp_request *req = proxy_req->server_req;
	struct evhttp_request *client_req = proxy_req->client_req;
	struct evbuffer *input;

#ifndef LIBEVENT_TEST
	input = bufev->input_buffer;
#else
	input = bufferevent_get_input(bufev);
#endif

	res = evhttp_parse_headers_(req, input);
	if (res == DATA_CORRUPTED) {
		client_send_error(client_req, 503,
			"Error parsing HTTP headers from server");
		proxy_req_free(proxy_req);
		return;
	} else if (res == DATA_TOO_LONG) {
		/* Error while reading, terminate */
		client_send_error(client_req, 503,
			"HTTP headers from server too long");
		proxy_req_free(proxy_req);
		return;
	} else if (res == MORE_DATA_EXPECTED) {
		/* Need more header lines */
		return;
	}

	proxy_req_server_headers_done(proxy_req);
}

static void
#ifndef LIBEVENT_TEST
proxy_req_read_firstline(struct lwipevbuf *bufev, void *arg)
#else
proxy_req_read_firstline(struct bufferevent *bufev, void *arg)
#endif
{
	enum message_read_status res;
	struct evhttp_proxy_request *proxy_req = arg;
	struct evhttp_request *req = proxy_req->server_req;
	struct evhttp_request *client_req = proxy_req->client_req;
	struct evbuffer *input;

#ifndef LIBEVENT_TEST
	input = bufev->input_buffer;
#else
	input = bufferevent_get_input(bufev);
#endif

	res = evhttp_parse_firstline_(req, input);
	if (res == DATA_CORRUPTED) {
		client_send_error(client_req, 503,
			"Error parsing response line from server");
		proxy_req_free(proxy_req);
		return;
	} else if (res == DATA_TOO_LONG) {
		client_send_error(client_req, 503,
			"Response line from server too long");
		proxy_req_free(proxy_req);
		return;
	} else if (res == MORE_DATA_EXPECTED) {
		/* Need more header lines */
		return;
	}

#ifndef LIBEVENT_TEST
	lwipevbuf_setcb(bufev, proxy_req_read_header, NULL, proxy_req_eventcb, proxy_req);
#else
	bufferevent_setcb(bufev, proxy_req_read_header, NULL, proxy_req_eventcb, proxy_req);
#endif
	proxy_req_read_header(bufev, arg);
}

static void
proxy_req_connected(struct evhttp_proxy_request *proxy_req)
{
#ifndef LIBEVENT_TEST
	struct lwipevbuf *server_bev = proxy_req->server_bev;
	struct evbuffer *server_output = server_bev->output_buffer;
#else
	struct bufferevent *server_bev = proxy_req->server_bev;
	struct evbuffer *server_output = bufferevent_get_output(server_bev);
#endif
	struct evhttp_request *client_req = proxy_req->client_req;
	struct evhttp_connection *client_evcon;

	client_evcon = evhttp_request_get_connection(client_req);

	if (client_req->type != EVHTTP_REQ_CONNECT) {
		struct evhttp_request *server_req;
		struct evkeyval *header;
		const char *hostname = "unknown";
		const char *via;
		const char *url;
		const char *host;

		host = evhttp_request_get_host(client_req);
		url = evhttp_request_get_uri(client_req);

		server_req = evhttp_request_new(NULL, NULL);
		server_req->kind = EVHTTP_RESPONSE;
		server_req->type = client_req->type;
		server_req->uri = strdup(url);
		server_req->major = client_req->major;
		server_req->minor = client_req->minor;
		server_req->evcon = client_evcon; /* For max header length */

		evbuffer_add_printf(server_output,
		    "%s %s HTTP/%d.%d\r\n",
		    evhttp_method(client_req->type), url, client_req->major, client_req->minor);

		/* remove connection headers */
		remove_headers(client_req->input_headers, "connection");
		remove_headers(client_req->input_headers, "proxy-connection");

		/* remove headers we shouldn't forward */
		evhttp_remove_header(client_req->input_headers, "util/host");
		evhttp_remove_header(client_req->input_headers, "keep-alive");
		evhttp_remove_header(client_req->input_headers, "te");
		evhttp_remove_header(client_req->input_headers, "trailers");

		/* Add our via header */
		via = evhttp_find_header(client_req->input_headers, "via");
		if (via) {
			evbuffer_add_printf(server_output, "Via: %s, ", via);
			evhttp_remove_header(client_req->input_headers, "via");
		} else
			evbuffer_add_printf(server_output, "Via: ");
		evbuffer_add_printf(server_output, "%d.%d %s (%s/%s)\r\n",
				client_req->major, client_req->minor,
				hostname, PACKAGE, VERSION);

		TAILQ_FOREACH(header, client_req->input_headers, next) {
			evbuffer_add_printf(server_output, "%s: %s\r\n",
			    header->key, header->value);
		}
		evbuffer_add_printf(server_output, "Host: %s\r\n", host);
		evbuffer_add_printf(server_output, "Connection: %s\r\n", "close");
		evbuffer_add(server_output, "\r\n", 2);

#ifndef LIBEVENT_TEST
		lwipevbuf_output(server_bev);
#endif

		proxy_req->server_req = server_req;
#ifdef LIBEVENT_TEST
		bufferevent_setcb(server_bev, proxy_req_read_firstline, NULL, proxy_req_eventcb, proxy_req);
#else
		lwipevbuf_setcb(server_bev, proxy_req_read_firstline, NULL, proxy_req_eventcb, proxy_req);
#endif
		/* Queue any data the client already sent */
		evbuffer_add_buffer(server_output, evhttp_request_get_input_buffer(client_req));

	} else {
		struct bufferevent *client_bev;
		struct evbuffer *client_output;

		client_bev = evhttp_connection_get_bufferevent(client_evcon);
		client_output = bufferevent_get_output(client_bev);

		evbuffer_add_printf(client_output, "HTTP/1.0 200 Connection established\r\n");
		evbuffer_add_printf(client_output, "Proxy-agent: %s/%s\r\n", PACKAGE, VERSION);
		evbuffer_add(client_output, "\r\n", 2);

		/* Queue any data the client already sent */
		evbuffer_add_buffer(server_output, evhttp_request_get_input_buffer(client_req));

		proxy_req_join(proxy_req);
	}
}

static void
#ifndef LIBEVENT_TEST
proxy_req_connectcb(struct lwipevbuf *bev, short what, void *ctx)
#else
proxy_req_connectcb(struct bufferevent *bev, short what, void *ctx)
#endif
{
	struct evhttp_proxy_request *proxy_req = ctx;
	struct evhttp_request *client_req = proxy_req->client_req;

	if (what & BEV_EVENT_CONNECTED) {
		proxy_req_connected(proxy_req);
		return;
	}

	if (what & BEV_EVENT_TIMEOUT) {
		client_send_error(client_req, 403,
			"Server communication timed out");
	} else if (what & BEV_EVENT_ERROR) {
		int err;
		const char *str;
#ifndef LIBEVENT_TEST
		err = bev->host_err;
#else
		err = bufferevent_socket_get_dns_error(bev);
#endif
		if (err) {
#ifdef LIBEVENT_TEST
			str = evutil_gai_strerror(err);
#elif defined(LWIP_DEBUG)
			str = lwip_strerr(bev->tcp_err);
#else
			str = "unspecified";
#endif
			client_send_error(client_req, 500,
				"DNS lookup failed: %s");
		} else {
#ifndef LIBEVENT_TEST
			err = EVUTIL_SOCKET_ERROR();
			str = evutil_socket_error_to_string(err);
#elif defined(LWIP_DEBUG)
			str = lwip_strerr(bev->tcp_err);
#else
			str = "unspecified";
#endif
			client_send_error(client_req, 500,
				"Connect failed: %s", str);
		}
	}

	proxy_req_free(proxy_req);
}

static void
client_request_cb(struct evhttp_request *client_req, void *ctx)
{
	struct http_proxy *http = ctx;
	const char *scheme;
	const char *host;
	struct evhttp_connection *client_evcon;
#ifndef LIBEVENT_TEST
	struct lwipevbuf *server_bev;
#else
	struct bufferevent *server_bev;
	struct event_base *base;
#endif
	int port;
	struct evhttp_proxy_request *proxy_req;

#ifdef LIBEVENT_TEST
	base = evhttp_connection_get_base(client_req->evcon);
#endif
	scheme = evhttp_uri_get_scheme(client_req->uri_elems);
	client_evcon = evhttp_request_get_connection(client_req);

	port = evhttp_uri_get_port(client_req->uri_elems);
	if (scheme && !strcasecmp(scheme, "http")) {
		host = evhttp_request_get_host(client_req);
		if (port == -1)
			port = 80;
	} else if (client_req->type == EVHTTP_REQ_CONNECT) {
		/* libevent 2.1.8-stable and below do not handle authority strings correctly */
		if (!evhttp_uri_get_host(client_req->uri_elems)) {
			char *auth;
			if (asprintf(&auth, "//%s/", client_req->uri)) {
			}
			evhttp_uri_free(client_req->uri_elems);
			client_req->uri_elems = evhttp_uri_parse(auth);
			free(auth);
			if (client_req->host_cache != NULL) {
				free(client_req->host_cache);
				client_req->host_cache = NULL;
			}
		}
		host = evhttp_request_get_host(client_req);
		if (port == -1)
			port = 443;
	} else {
		client_send_error(client_req, 501, "Method not implemented: %s",
				evhttp_method(client_req->type));
		return;
	}

#ifndef LIBEVENT_TEST
	server_bev = lwipevbuf_new(NULL);
	if (http->keep_alive) {
		server_bev->pcb->so_options |= SOF_KEEPALIVE;
		server_bev->pcb->keep_intvl = http->keep_alive;
		server_bev->pcb->keep_idle = http->keep_alive;
	}
	lwipevbuf_connect_hostname(server_bev, AF_UNSPEC, host, port);
#else
	server_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_socket_connect_hostname(server_bev, http->dnsbase, AF_UNSPEC, host, port);
	bufferevent_enable(server_bev, EV_WRITE|EV_READ);
#endif
	proxy_req = calloc(1, sizeof(*proxy_req));
	proxy_req->server_bev = server_bev;
	proxy_req->client_req = client_req;

	evhttp_connection_set_closecb(client_evcon, proxy_req_client_closecb, proxy_req);
#ifndef LIBEVENT_TEST
	lwipevbuf_setcb(server_bev, NULL, NULL, proxy_req_connectcb, proxy_req);
#else
	bufferevent_setcb(server_bev, NULL, NULL, proxy_req_connectcb, proxy_req);
#endif
}

int http_listen(struct event_base *base, const char *host, const char *port_str, int keep_alive)
{
	struct http_proxy *http;
	char *endptr;
	int port;
	int ret;

	port = strtoul(port_str, &endptr, 0);
	if (*endptr)
		return -1;

	http = calloc(1, sizeof(*http));
	http->evh = evhttp_new(base);
	http->keep_alive = keep_alive;

	evhttp_set_max_headers_size(http->evh, 16*1024);
	/* evhttp_set_timeout(http->evh, 3); */
	evhttp_set_allowed_methods(http->evh,
		EVHTTP_REQ_GET |
		EVHTTP_REQ_POST |
		EVHTTP_REQ_HEAD |
		EVHTTP_REQ_PUT |
		EVHTTP_REQ_DELETE |
		EVHTTP_REQ_OPTIONS |
		EVHTTP_REQ_TRACE |
		EVHTTP_REQ_CONNECT |
		EVHTTP_REQ_PATCH);
	evhttp_set_gencb(http->evh, client_request_cb, http);

	ret = evhttp_bind_socket(http->evh, host, port);
	if (ret < 0) {
		evhttp_free(http->evh);
#ifdef LIBEVENT_TEST
		evdns_free(http->dnsbase);
#endif
		free(http);
	}
	return ret;
}

#ifdef LIBEVENT_TEST
int main(void)
{
	struct event_base *base;
	int ret;
	int port = 8555;

	base = event_base_new();
	ret = http_listen(base, port);
	if (ret < 0)
		return 1;
	event_base_dispatch(base);

	return 0;
}
#endif
