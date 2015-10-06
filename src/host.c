#include <lwip/ip.h>
#include <lwip/dns.h>

#include "host.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(n)	(sizeof(n) / sizeof((n)[0]))
#endif

struct host_data_priv {
	int search;
	int tried_bare;
	int dot;
	struct host_data *owner;
};

static char *host_search[HOST_SEARCH_SIZE];

void host_clear_search(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(host_search); i++)
		if (host_search[i]) {
			free(host_search[i]);
			host_search[i] = NULL;
		}
}

void host_add_search(char *search)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(host_search); i++)
		if (!host_search[i]) {
			host_search[i] = search;
			return;
		}
	free(search);
}

static const char *host_get_next_fqdn(struct host_data *data)
{
	int i;

	if (data->priv->dot && !data->priv->tried_bare) {
		data->priv->tried_bare = 1;
		return data->fqdn;
	}

	for (i = data->priv->search; i < ARRAY_SIZE(host_search); i++)
		if (host_search[i])
			break;

	if (i < ARRAY_SIZE(host_search)) {
		static char fqdn[DNS_MAX_NAME_LENGTH];
		snprintf(fqdn, DNS_MAX_NAME_LENGTH, "%s.%s", data->fqdn,
					host_search[i]);
		data->priv->search = i + 1;
		return fqdn;
	}

	if (!data->priv->dot && !data->priv->tried_bare) {
		data->priv->tried_bare = 1;
		return data->fqdn;
	}

	return NULL;
}

static void host_found(const char *name, const ip_addr_t *ipaddr, void *ctx)
{
	struct host_data_priv *priv = ctx;
	struct host_data *data = priv->owner;
	const char *fqdn;
	int ret;

	if (!data) {
		LWIP_DEBUGF(HOSTS_DEBUG, ("%s: went away\n", __func__));
		free(priv);
		return;
	}

	if (ipaddr && ipaddr->addr) {
		LWIP_DEBUGF(HOSTS_DEBUG, ("%s: Success\n", __func__));
		data->priv = NULL;
		free(priv);
		data->ipaddr.addr = ipaddr->addr;
		data->found(data);
		return;
	}

	fqdn = host_get_next_fqdn(data);
	if (!fqdn) {
		LWIP_DEBUGF(HOSTS_DEBUG, ("%s: No more options\n", __func__));
		data->priv = NULL;
		free(priv);
		data->failed(data);
		return;
	}

	ret = dns_gethostbyname(fqdn, &data->ipaddr, host_found, priv);
	if (!ret) {
		LWIP_DEBUGF(HOSTS_DEBUG, ("%s: Cached\n", __func__));
		data->priv = NULL;
		free(priv);
		data->found(data);
	}
}

void host_abort(struct host_data *data)
{
	if (data->priv)
		data->priv->owner = NULL;
	data->priv = NULL;
}

void host_lookup(struct host_data *data)
{
	const char *fqdn;
	int ret;

	host_abort(data);

	data->priv = calloc(1, sizeof(*data->priv));

	data->priv->tried_bare = 0;
	data->priv->search = 0;
	data->priv->dot = !!strchr(data->fqdn, '.');
	data->priv->owner = data;

	fqdn = host_get_next_fqdn(data);

	ret = dns_gethostbyname(fqdn, &data->ipaddr, host_found, data->priv);
	if (!ret) {
		LWIP_DEBUGF(HOSTS_DEBUG, ("%s: Cached\n", __func__));
		free(data->priv);
		data->priv = NULL;
		data->found(data);
	}
}

