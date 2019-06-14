AM_CFLAGS=\
	-I$(srcdir)/lwip/src/include \
	-I$(srcdir)/lwip/src/include/ipv4 \
	-I$(srcdir)/lwip/src/include/ipv6 \
	-I$(srcdir)/lwip-libevent/include \
	-I$(srcdir)/lwip-udhcpd \
	-I$(srcdir)/lwip-nat/include \
	-I$(srcdir)/include -Wall -Og -g

tunsocks_LDADD = -ldl

if HAVE_PCAP
AM_CFLAGS += -DUSE_PCAP
tunsocks_LDADD += $(PCAP_LIBS)
endif

tunsocks_SOURCES = \
	lwip/src/api/err.c \
	lwip/src/core/init.c \
	lwip/src/core/def.c \
	lwip/src/core/mem.c \
	lwip/src/core/memp.c \
	lwip/src/core/netif.c \
	lwip/src/core/pbuf.c \
	lwip/src/core/stats.c \
	lwip/src/core/ip.c \
	lwip/src/core/dns.c \
	lwip/src/core/udp.c \
	lwip/src/core/raw.c \
	lwip/src/core/sys.c \
	lwip/src/core/tcp.c \
	lwip/src/core/tcp_in.c \
	lwip/src/core/tcp_out.c \
	lwip/src/core/inet_chksum.c \
	lwip/src/core/ipv4/etharp.c \
	lwip/src/core/ipv4/icmp.c \
	lwip/src/core/ipv4/ip4.c \
	lwip/src/core/ipv4/ip4_addr.c \
	lwip/src/core/ipv4/ip4_frag.c \
	lwip/src/netif/ethernet.c \
	lwip-udhcpd/udhcp_packet.c \
	lwip-udhcpd/udhcp_common.c \
	lwip-udhcpd/dhcpd.c \
	lwip-udhcpd/domain_codec.c \
	lwip-libevent/netif/fdif.c \
	lwip-libevent/netif/slirpif.c \
	lwip-libevent/netif/slirpif_tcp.c \
	lwip-libevent/netif/slirpif_udp.c \
	lwip-libevent/netif/udptapif.c \
	lwip-libevent/netif/tunif.c \
	lwip-libevent/netif/vdeportif.c \
	lwip-libevent/netif/vdeswitchif.c \
	lwip-libevent/util/sockaddr.c \
	lwip-libevent/util/lwipevbuf.c \
	lwip-libevent/util/lwipevbuf_bev_join.c \
	lwip-libevent/util/host.c \
	lwip-libevent/util/pbuf_iovec.c \
	lwip-libevent/util/nettest.c \
	lwip-libevent/libevent.c \
	lwip-nat/ip4_prerouting_hook.c \
	lwip-nat/ip4_input_nat.c \
	lwip-nat/nat_proto_tcp.c \
	lwip-nat/nat_proto_udp.c \
	lwip-nat/nat_proto_icmp4.c \
	lwip-nat/nat_proto_ip4.c \
	lwip-nat/nat.c \
	src/socks4.c \
	src/socks5.c \
	src/socks.c \
	src/forward_local.c \
	src/forward_remote.c \
	src/nat.c \
	src/dhcp_server.c \
	src/http/http.c \
	src/http/server.c \
	src/http/evhttp_extra.c \
	src/main.c

if HAVE_PCAP
tunsocks_SOURCES += lwip-libevent/util/pcap.c
endif

bin_PROGRAMS = tunsocks
