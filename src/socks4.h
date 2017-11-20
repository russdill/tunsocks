#ifndef __SOCKS4_H__
#define __SOCKS4_H__

struct bufferevent;
struct socks_server;

void socks4_start(struct socks_server *s, struct bufferevent *bev);

#endif
