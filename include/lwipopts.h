/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Simon Goldschmidt
 *
 */
#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#include <lwip/arch.h>
#include <lwip/err.h>

#define NO_SYS_NO_TIMERS		1
#define SYS_LIGHTWEIGHT_PROT		0
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS

struct pbuf;
struct netif;
extern int ip4_input_nat(struct pbuf *p, struct netif *inp);
#define LWIP_HOOK_IP4_INPUT		ip4_input_nat

#define MEM_LIBC_MALLOC			1
#define MEMP_MEM_MALLOC			1
#define MEM_ALIGNMENT			4
#define MEM_SIZE                        (16*1024*1024)

#define MEMP_NUM_UDP_PCB		1024
#define MEMP_NUM_TCP_PCB		1024
#define MEMP_NUM_TCP_PCB_LISTEN		1024
#define MEMP_NUM_TCP_SEG		8192
#define MEMP_NUM_REASSDATA		256
#define MEMP_NUM_FRAG_PBUF		1024
#define MEMP_NUM_TCPIP_MSG_API		1024
#define MEMP_NUM_TCPIP_MSG_INPKT	1024

#define LWIP_ARP			1
#define LWIP_RAW			1
#define LWIP_ICMP			1
#define LWIP_TCP_KEEPALIVE		1
#define LWIP_TCP_TIMESTAMPS		1
#define IP_FORWARD			1
#define LWIP_NAT			1
#define LWIP_NAT_ICMP			1
#define LWIP_NAT_ICMP_IP		1
#define LWIP_NAT_USE_OLDEST		1
#define LWIP_ETHERNET			1
#define LWIP_DNS			1
#define LWIP_WND_SCALE			8
#define DNS_TABLE_SIZE			255
#define DNS_MAX_SERVERS			8
#define LWIP_IP_ACCEPT_UDP_PORT(p)	(p == 67)

#define TCP_MSS				1500
#define TCP_WND                         (256*1024)
#define TCP_SND_QUEUELEN                8192
#define TCP_SND_BUF                     65535
#define TCP_RCV_SCALE			8

#define SO_REUSE			1

#define NO_SYS                          1
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0

#define LWIP_NETIF_LINK_CALLBACK	1

#define HOST_SEARCH_SIZE		6

#define LWIP_DEBUG			0
#define NETIF_DEBUG			LWIP_DBG_OFF
#define TAPNAT_DEBUG			LWIP_DBG_OFF
#define NAT_DEBUG			LWIP_DBG_OFF
#define ETHARP_DEBUG			LWIP_DBG_OFF
#define SLIRPIF_DEBUG			LWIP_DBG_OFF
#define SOCKS_DEBUG			LWIP_DBG_OFF
#define UDHCP_DEBUG			LWIP_DBG_OFF
#define HOSTS_DEBUG			LWIP_DBG_OFF
#define MEM_DEBUG			LWIP_DBG_OFF
#define IP_DEBUG			LWIP_DBG_OFF
#define IP_REASS_DEBUG			LWIP_DBG_OFF
#define TCP_DEBUG			LWIP_DBG_OFF
#define TCP_INPUT_DEBUG			LWIP_DBG_OFF
#define TCP_OUTPUT_DEBUG		LWIP_DBG_OFF
#define TCP_CWND_DEBUG			LWIP_DBG_OFF
#define UDP_DEBUG			LWIP_DBG_OFF
#define DNS_DEBUG			LWIP_DBG_OFF
#define LWIPEVBUF_OUTPUT_DEBUG		LWIP_DBG_OFF
#define LWIPEVBUF_INPUT_DEBUG		LWIP_DBG_OFF
#define LWIPEVBUF_DEBUG			LWIP_DBG_OFF
#define LWIPEVBUF_BEV_JOIN_DEBUG	LWIP_DBG_OFF

#endif /* __LWIPOPTS_H__ */
