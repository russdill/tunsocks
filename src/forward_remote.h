#ifndef __FORWARD_REMOTE_H__
#define __FORWARD_REMOTE_H__

struct event_base;

int forward_remote(struct event_base *base, const char *remote_port,
	const char *local_host, const char *local_port, int keep_alive);

#endif
