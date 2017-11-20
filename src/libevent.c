/**
 * @file
 * Stack-internal timers implementation.
 * This file includes timer callbacks for stack-internal timers as well as
 * functions to set up or stop timers and check for expired timers.
 *
 */

/*
 * Copyright (c) 2001-2004 Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *         Simon Goldschmidt
 *
 */

#include "lwip/opt.h"

#include "lwip/timers.h"
#include "lwip/priv/tcp_priv.h"

#include "lwip/def.h"
#include "lwip/memp.h"
#include "lwip/tcpip.h"

#include "lwip/ip_frag.h"
#include "netif/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/autoip.h"
#include "lwip/igmp.h"
#include "lwip/dns.h"
#include "lwip/nd6.h"
#include "lwip/ip6_frag.h"
#include "lwip/mld6.h"
#include "lwip/sys.h"
#include "lwip/pbuf.h"

#include <time.h>
#include <event2/event.h>

#if LWIP_TCP
/** global variable that shows if the tcp timer is currently scheduled or not */
static int tcpip_tcp_timer_active;
static struct event *tcp_ev;

/** Returns the current time in milliseconds,
 * may be the same as sys_jiffies or at least based on it. */
u32_t
sys_now(void)
{
  struct timespec tp;
  /* CLOCK_BOOTTIME includes time spent in suspend */
  clock_gettime(CLOCK_BOOTTIME, &tp);
  return tp.tv_sec * 1000 + tp.tv_nsec / 1000000;
}

/**
 * Timer callback function that calls tcp_tmr() and reschedules itself.
 *
 * @param arg unused argument
 */
static void
tcpip_tcp_timer(void)
{
  /* call TCP timer handler */
  tcp_tmr();
  /* timer still needed? */
  if (!tcp_active_pcbs && !tcp_tw_pcbs) {
    /* disable timer */
    event_del(tcp_ev);
    tcpip_tcp_timer_active = 0;
  }
}

/**
 * Called from TCP_REG when registering a new PCB:
 * the reason is to have the TCP timer only running when
 * there are active (or time-wait) PCBs.
 */
void
tcp_timer_needed(void)
{
  /* timer is off but needed again? */
  if (!tcpip_tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
    struct timeval interval;
    /* enable and start timer */
    tcpip_tcp_timer_active = 1;
    interval.tv_sec = TCP_TMR_INTERVAL / 1000;
    interval.tv_usec = (TCP_TMR_INTERVAL % 1000) * 1000;
    event_add(tcp_ev, &interval);
  }
}
#endif /* LWIP_TCP */

static void interval_cb(evutil_socket_t s, short v, void *unused)
{
  void (*cb)(void) = unused;
  cb();
}

static void sys_timer_add_internal(struct event_base *base, int msec, void (*cb)(void))
{
  struct event *ev;
  struct timeval interval;

  ev = event_new(base, -1, EV_PERSIST, interval_cb, cb);
  interval.tv_sec = msec / 1000;
  interval.tv_usec = (msec % 1000) * 1000;
  event_add(ev, &interval);
}

/** Initialize this module */
void libevent_timeouts_init(struct event_base *base)
{
#if LWIP_TCP
  tcp_ev = event_new(base, -1, EV_PERSIST, interval_cb, tcpip_tcp_timer);
#endif /* LWIP_TCP */
#if IP_REASSEMBLY
  sys_timer_add_internal(base, IP_TMR_INTERVAL, ip_reass_tmr);
#endif /* IP_REASSEMBLY */
#if LWIP_ARP
  sys_timer_add_internal(base, ARP_TMR_INTERVAL, eth_arp_tmr);
#endif /* LWIP_ARP */
#if LWIP_DHCP
  sys_timer_add_internal(base, DHCP_COARSE_TIMER_MSECS, dhcp_coarse_tmr);
  sys_timer_add_internal(base, DHCP_FINE_TIMER_MSECS, dhcp_fine_tmr);
#endif /* LWIP_DHCP */
#if LWIP_AUTOIP
  sys_timer_add_internal(base, AUTOIP_TMR_INTERVAL, autoip_tmr);
#endif /* LWIP_AUTOIP */
#if LWIP_IGMP
  sys_timer_add_internal(base, IGMP_TMR_INTERVAL, igmp_tmr);
#endif /* LWIP_IGMP */
#if LWIP_DNS
  sys_timer_add_internal(base, DNS_TMR_INTERVAL, dns_tmr);
#endif /* LWIP_DNS */
#if LWIP_IPV6
  sys_timer_add_internal(base, ND6_TMR_INTERVAL, nd6_tmr);
#if LWIP_IPV6_REASS
  sys_timer_add_internal(base, IP6_REASS_TMR_INTERVAL, ip6_reass_tmr);
#endif /* LWIP_IPV6_REASS */
#if LWIP_IPV6_MLD
  sys_timer_add_internal(base, MLD6_TMR_INTERVAL, mld6_tmr);
#endif /* LWIP_IPV6_MLD */
#endif /* LWIP_IPV6 */
}
