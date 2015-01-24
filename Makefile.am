AM_CFLAGS=\
	-I$(srcdir)/lwip/src/include \
	-I$(srcdir)/lwip/src/include/ipv4 \
	-I$(srcdir)/lwip/src/include/ipv6 \
	-I$(srcdir)/include -Wall -O2 -g

if HAVE_PCAP
AM_CFLAGS += -DUSE_PCAP
tunsocks_LDADD = $(PCAP_LIBS)
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
	lwip/src/core/dns.c \
	lwip/src/core/udp.c \
	lwip/src/core/sys.c \
	lwip/src/core/raw.c \
	lwip/src/core/tcp.c \
	lwip/src/core/tcp_in.c \
	lwip/src/core/tcp_out.c \
	lwip/src/core/inet_chksum.c \
	lwip/src/core/ipv4/icmp.c \
	lwip/src/core/ipv4/ip4.c \
	lwip/src/core/ipv4/ip4_addr.c \
	lwip/src/core/ipv4/ip_frag.c \
	src/libevent.c \
	src/socks4.c \
	src/socks5.c \
	src/socks.c \
	src/forward_local.c \
	src/forward_remote.c \
	src/tunif.c \
	src/pipe.c \
	src/host.c \
	src/main.c

bin_PROGRAMS = tunsocks

