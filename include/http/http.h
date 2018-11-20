#ifndef __HTTP_H__
#define __HTTP_H__

struct event_base;

int http_listen(struct event_base *base, const char *host, const char *port, int keep_alive);

#endif
