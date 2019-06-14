#define _GNU_SOURCE
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>

#include "http/http_server.h"

static void
file_request_cb(struct evhttp_request *req, void *ctx)
{
	const char *path = ctx;
	struct evbuffer *buffer;
	int fd;
	struct stat st;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			evhttp_send_error(req, HTTP_NOTFOUND, strerror(errno));
		else
			evhttp_send_error(req, HTTP_INTERNAL, strerror(errno));
		return;
	}

	if (fstat(fd, &st) < 0) {
		evhttp_send_error(req, HTTP_INTERNAL, strerror(errno));
		close(fd);
		return;
	}

	buffer = evbuffer_new();
	evbuffer_add_file(buffer, fd, 0, st.st_size);

	evhttp_add_header(evhttp_request_get_output_headers(req),
		"Content-Type", "application/x-ns-proxy-autoconfig");
	evhttp_send_reply(req, HTTP_OK, "OK", buffer);
	evbuffer_free(buffer);
}

int http_server_listen(struct event_base *base, const char *port_str, const char *path)
{
	struct evhttp *evh;
	char *path_copy;
	char *endptr;
	int port;
	int ret;

	port = strtoul(port_str, &endptr, 0);
	if (*endptr)
		return -1;

	evh = evhttp_new(base);
	path_copy = strdup(path);

	evhttp_set_max_headers_size(evh, 16*1024);
	evhttp_set_allowed_methods(evh, EVHTTP_REQ_GET);
	evhttp_set_cb(evh, "/", file_request_cb, path_copy);
	evhttp_set_cb(evh, "/wpad.dat", file_request_cb, path_copy);
	evhttp_set_cb(evh, "/proxy.pac", file_request_cb, path_copy);

	ret = evhttp_bind_socket(evh, "localhost", port);
	if (ret < 0) {
		evhttp_free(evh);
		free(path_copy);
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
	ret = http_server_listen(base, port);
	if (ret < 0)
		return 1;
	event_base_dispatch(base);

	return 0;
}
#endif
