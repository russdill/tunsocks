#ifndef __SOCKS5_H__
#define __SOCKS5_H__

struct bufferevent;
struct socks_server;

void socks5_start(struct socks_server *s, struct bufferevent *bev);

#endif
