#include <event2/http.h>

#include "evhttp_extra.h"

const char *
evhttp_method(enum evhttp_cmd_type type)
{
	const char *method;

	switch (type) {
	case EVHTTP_REQ_GET:
		method = "GET";
		break;
	case EVHTTP_REQ_POST:
		method = "POST";
		break;
	case EVHTTP_REQ_HEAD:
		method = "HEAD";
		break;
	case EVHTTP_REQ_PUT:
		method = "PUT";
		break;
	case EVHTTP_REQ_DELETE:
		method = "DELETE";
		break;
	case EVHTTP_REQ_OPTIONS:
		method = "OPTIONS";
		break;
	case EVHTTP_REQ_TRACE:
		method = "TRACE";
		break;
	case EVHTTP_REQ_CONNECT:
		method = "CONNECT";
		break;
	case EVHTTP_REQ_PATCH:
		method = "PATCH";
		break;
	default:
		method = NULL;
		break;
	}

	return (method);
}
