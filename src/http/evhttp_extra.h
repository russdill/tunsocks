#ifndef __EVHTTP_EXTRA_H__
#define __EVHTTP_EXTRA_H__

enum evhttp_cmd_type;
struct evhttp_request;
struct evbuffer;

enum message_read_status {
	ALL_DATA_READ = 1,
	MORE_DATA_EXPECTED = 0,
	DATA_CORRUPTED = -1,
	REQUEST_CANCELED = -2,
	DATA_TOO_LONG = -3
};


void
evhttp_response_code_(struct evhttp_request *req, int code, const char *reason);

void
evhttp_send_page_(struct evhttp_request *req, struct evbuffer *databuf);

enum message_read_status
evhttp_parse_headers_(struct evhttp_request *req, struct evbuffer* buffer);

enum message_read_status
evhttp_parse_firstline_(struct evhttp_request *req, struct evbuffer *buffer);

const char *evhttp_method(enum evhttp_cmd_type type);

#endif
