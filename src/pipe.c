#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <lwip/tcp.h>
#include <lwip/tcp_impl.h>

#include "pipe.h"

struct pipe_data {
	struct tcp_pcb *pcb;
	struct bufferevent *bev;
};

static void pipe_tcp_kill(struct pipe_data *data)
{
	tcp_arg(data->pcb, NULL);
	tcp_err(data->pcb, NULL);
	tcp_recv(data->pcb, NULL);
	tcp_sent(data->pcb, NULL);
	data->pcb = NULL;
}

static void pipe_tcp_free(struct pipe_data *data)
{
	struct tcp_pcb *pcb = data->pcb;
	pipe_tcp_kill(data);
	if (tcp_close(pcb) < 0)
		tcp_abort(pcb);
}

static void pipe_bev_flush_fin(struct bufferevent *bev, void *ctx)
{
	struct pipe_data *data = ctx;
	bufferevent_free(data->bev);
	free(data);
}

static void pipe_bev_err_kill(struct bufferevent *bev, short events, void *ctx)
{
	struct pipe_data *data = ctx;
	bufferevent_free(data->bev);
	free(data);
}

static void pipe_bev_flush(struct pipe_data *data)
{
	struct evbuffer *buf;

	buf = bufferevent_get_output(data->bev);
	if (evbuffer_get_length(buf)) {
		bufferevent_disable(data->bev, EV_READ);
		bufferevent_setwatermark(data->bev, EV_WRITE, 0, 262144);
		bufferevent_setcb(data->bev, NULL, pipe_bev_flush_fin,
					pipe_bev_err_kill, data);
	} else {
		bufferevent_free(data->bev);
		free(data);
	}
}

static void pipe_bev_error(struct bufferevent *bev, short events, void *ctx)
{
	struct pipe_data *data = ctx;

	bufferevent_free(data->bev);
	data->bev = NULL;

	if (!data->pcb)
		/* Dead TCP side */
		free(data);
	else if (tcp_sndbuf(data->pcb) == TCP_SND_BUF) {
		/* Empty TCP buffer */
		pipe_tcp_free(data);
		free(data);
	}

	/* Else, allow TCP to finish writing out */
}

static void pipe_bev_writable(struct bufferevent *bev, void *ctx)
{
	struct pipe_data *data = ctx;
	if (data->pcb && data->pcb->refused_data)
		tcp_process_refused_data(data->pcb);
}

static void pipe_bev_readable(struct bufferevent *bev, void *ctx)
{
	struct pipe_data *data = ctx;
	int avail;
	struct evbuffer *buf;
	struct evbuffer_iovec vec_out;
	err_t ret;
	int wait_for_more = 0;
	u8_t apiflags;

	avail = tcp_sndbuf(data->pcb);
	if (!avail) {
		bufferevent_disable(bev, EV_READ);
		return;
	}

	buf = bufferevent_get_input(data->bev);
	if (avail < evbuffer_get_length(buf))
		wait_for_more = 1;
	else if (avail > evbuffer_get_length(buf))
		avail = evbuffer_get_length(buf);

	if (!avail)
		return;

	evbuffer_pullup(buf, avail);
	evbuffer_peek(buf, avail, NULL, &vec_out, 1);

	apiflags = TCP_WRITE_FLAG_COPY;
	if (wait_for_more)
		apiflags |= TCP_WRITE_FLAG_MORE;
	ret = tcp_write(data->pcb, vec_out.iov_base, avail, apiflags);
	if (ret < 0) {
		bufferevent_disable(bev, EV_READ);
		if (ret != ERR_MEM) {
			pipe_tcp_free(data);
			pipe_bev_flush(data);
		}
	} else {
		evbuffer_drain(buf, avail);
		if (wait_for_more)
			bufferevent_disable(bev, EV_READ);
	}
}

/* Error on the tcp side */
static void pipe_tcp_err(void *ctx, err_t err)
{
	struct pipe_data *data = ctx;

	pipe_tcp_kill(data);

	/* lwIP will free the pcb */

	if (data->bev)
		pipe_bev_flush(data);
	else
		free(data);
}

static err_t pipe_tcp_recv(void *ctx, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	struct pipe_data *data = ctx;
	struct pbuf *curr;
	int len;

	if (!data->bev) {
		pipe_tcp_free(data);
		free(data);
		return ERR_ABRT;
	}

	if (err < 0 || !p) {
		pipe_tcp_kill(data);
		pipe_bev_flush(data);
		return ERR_ABRT;
	}

	if (evbuffer_get_length(bufferevent_get_output(data->bev)) >= 262144)
		return ERR_WOULDBLOCK;

	len = p->tot_len;
	for (curr = p; curr; curr = curr->next)
		bufferevent_write(data->bev, curr->payload, curr->len);
	pbuf_free(p);
	tcp_recved(pcb, len);

	return 0;
}

static err_t pipe_tcp_sent(void *ctx, struct tcp_pcb *pcb, u16_t len)
{
	struct pipe_data *data = ctx;

	if (!data->bev) {
		/* Check for send buffer empty */
		if (tcp_sndbuf(data->pcb) == TCP_SND_BUF) {
			pipe_tcp_free(data);
			free(data);
			return ERR_ABRT;
		}
	} else if (len != 0) {
		/* Get more data if we weren't already */
		bufferevent_enable(data->bev, EV_READ);
		pipe_bev_readable(data->bev, ctx);
	}

	return 0;
}

void pipe_join(struct tcp_pcb *pcb, struct bufferevent *bev)
{
	struct pipe_data *data;

	data = calloc(1, sizeof(*data));

	data->bev = bev;
	data->pcb = pcb;

	tcp_arg(data->pcb, data);
	tcp_err(data->pcb, pipe_tcp_err);
	tcp_recv(data->pcb, pipe_tcp_recv);
	tcp_sent(data->pcb, pipe_tcp_sent);

	bufferevent_setwatermark(data->bev, EV_READ, 1, 262144);
	bufferevent_setwatermark(data->bev, EV_WRITE, 8192, 262144);
	bufferevent_setcb(data->bev, pipe_bev_readable, pipe_bev_writable,
							pipe_bev_error, data);
	bufferevent_enable(data->bev, EV_READ);
	bufferevent_set_timeouts(data->bev, NULL, NULL);
	pipe_bev_readable(data->bev, data);
}
