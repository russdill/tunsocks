#ifndef __PIPE_H__
#define __PIPE_H__

struct bufferevent;
struct tcp_pcb;

void pipe_join(struct tcp_pcb *pcb, struct bufferevent *bev);

#endif
