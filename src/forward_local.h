#ifndef __FORWARD_LOCAL_H__
#define __FORWARD_LOCAL_H__

struct event_base;

int forward_local(struct event_base *base, const char *host, const char *port,
	const char *local_host, const char *local_port, int keep_alive);

#endif
