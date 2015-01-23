#ifndef __SOCKS4_H__
#define __SOCKS4_H__

struct bufferevent;

void socks4_start(struct bufferevent *bev, int *keep_alive);

#endif
