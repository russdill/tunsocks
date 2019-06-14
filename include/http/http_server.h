#ifndef __HTTP_SERVER_H__
#define __HTTP_SERVER_H__

struct event_base;

int http_server_listen(struct event_base *base, const char *port, const char *path);

#endif
