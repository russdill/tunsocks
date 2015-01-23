#ifndef __LIBEVENT_H__
#define __LIBEVENT_H__

struct event_base;
void libevent_timeouts_init(struct event_base *base);

#endif
