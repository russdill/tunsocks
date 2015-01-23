#ifndef __HOST_H__
#define __HOST_H__

#include <sys/types.h>

struct host_data_priv;

struct host_data {
	ip_addr_t ipaddr;
	char fqdn[256];
	void (*found)(struct host_data*);
	void (*failed)(struct host_data*);
	struct host_data_priv *priv;
};

void host_lookup(struct host_data *data);
void host_abort(struct host_data *data);

void host_clear_search(void);
void host_add_search(char *search);

#endif
