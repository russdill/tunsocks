#ifndef __SOCKS5_H__
#define __SOCKS5_H__

struct bufferevent;

void socks5_start(struct bufferevent *bev, int *keep_alive);

#endif
