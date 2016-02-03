/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>

#include <net/ip_buf.h>

#include "sol-log.h"
#include "sol-mainloop.h"
#include "sol-mainloop-zephyr.h"
#include "sol-socket-impl.h"
#include "sol-vector.h"
#include "sol-network-util.h"

struct sol_socket_zephyr {
    struct sol_socket base;

    struct {
        bool (*cb)(void *data, struct sol_socket *s);
        const void *data;
    } read, write;

    struct sol_timeout *write_timeout;

    struct net_context *unicast_context;
    struct sol_ptr_vector mcast_contexts;
    struct sol_ptr_vector bufs;

    bool read_available;
};

static struct sol_ptr_vector bound_sockets = SOL_PTR_VECTOR_INIT;

static void
socket_read_available(void *data)
{
    struct sol_socket_zephyr *s = data;

    s->read_available = false;

    if (s->read.cb)
        while (sol_ptr_vector_get_len(&s->bufs))
            s->read.cb((void *)s->read.data, &s->base);
}

static void
socket_signal_mainloop(struct sol_socket_zephyr *s)
{
    struct mainloop_wake_data wd = {
        .cb = socket_read_available,
        .data = s
    };

    if (s->read_available)
        return;

    sol_mainloop_wakeup(&wd);

    s->read_available = true;
}

#define RECV_STACKSIZE 1024
static char __noinit socket_recv_fiber_stack[RECV_STACKSIZE];
static bool socket_recv_fiber_started;

static void
socket_recv_fiber(int arg1, int arg2)
{
    while (1) {
        struct sol_socket_zephyr *s;
        uint16_t i;

        SOL_PTR_VECTOR_FOREACH_IDX (&bound_sockets, s, i) {
            struct net_context *ctx;
            struct net_buf *buf;
            uint16_t j;

            buf = net_receive(s->unicast_context, 100);
            if (buf) {
                sol_ptr_vector_append(&s->bufs, buf);
                socket_signal_mainloop(s);
            }
            SOL_PTR_VECTOR_FOREACH_IDX (&s->mcast_contexts, ctx, j) {
                buf = net_receive(ctx, 100);
                if (!buf)
                    continue;

                sol_ptr_vector_append(&s->bufs, buf);
                socket_signal_mainloop(s);
            }
        }
    }
}

static struct sol_socket *
sol_socket_zephyr_new(int domain, enum sol_socket_type type, int protocol)
{
    struct sol_socket_zephyr *socket;

    SOL_INT_CHECK_GOTO(domain, != SOL_NETWORK_FAMILY_INET6,
        unsupported_family);

    socket = calloc(1, sizeof(*socket));
    SOL_NULL_CHECK_GOTO(socket, socket_error);

    return &socket->base;

socket_error:
    errno = ENOMEM;
    return NULL;

unsupported_family:
    errno = EAFNOSUPPORT;
    return NULL;
}

static void
sol_socket_zephyr_del(struct sol_socket *s)
{
    struct sol_socket_zephyr *socket = (struct sol_socket_zephyr *)s;
    struct net_context *ctx;
    struct net_buf *buf;
    uint16_t idx;

    sol_ptr_vector_del_element(&bound_sockets, socket);

    SOL_PTR_VECTOR_FOREACH_IDX (&socket->bufs, buf, idx)
        ip_buf_unref(buf);
    sol_ptr_vector_clear(&socket->bufs);

    net_context_put(socket->unicast_context);
    SOL_PTR_VECTOR_FOREACH_IDX (&socket->mcast_contexts, ctx, idx)
        net_context_put(ctx);
    sol_ptr_vector_clear(&socket->mcast_contexts);

    free(socket);
}

static int
sol_socket_zephyr_set_on_read(struct sol_socket *s, bool (*cb)(void *data, struct sol_socket *s), const void *data)
{
    struct sol_socket_zephyr *socket = (struct sol_socket_zephyr *)s;

    socket->read.cb = cb;
    socket->read.data = data;

    return 0;
}

static bool
write_timeout_cb(void *data)
{
    struct sol_socket_zephyr *socket = data;

    if (socket->write.cb((void *)socket->write.data, &socket->base))
        return true;

    socket->write_timeout = NULL;
    return false;
}

static int
sol_socket_zephyr_set_on_write(struct sol_socket *s, bool (*cb)(void *data, struct sol_socket *s), const void *data)
{
    struct sol_socket_zephyr *socket = (struct sol_socket_zephyr *)s;

    if (cb && !socket->write_timeout) {
        socket->write_timeout = sol_timeout_add(0, write_timeout_cb, socket);
        SOL_NULL_CHECK(socket->write_timeout, -ENOMEM);
    } else if (!cb && socket->write_timeout) {
        sol_timeout_del(socket->write_timeout);
        socket->write_timeout = NULL;
    }

    socket->write.cb = cb;
    socket->write.data = data;

    return 0;
}

static int
sol_socket_zephyr_recvmsg(struct sol_socket *s, void *buf, size_t len, struct sol_network_link_addr *cliaddr)
{
    struct sol_socket_zephyr *socket = (struct sol_socket_zephyr *)s;
    struct net_buf *netbuf;
    size_t buflen;

    netbuf = sol_ptr_vector_take(&socket->bufs, 0);
    if (!netbuf)
        return -EAGAIN;

    buflen = ip_buf_appdatalen(netbuf);
    if (buflen > len)
        buflen = len;

    if (cliaddr) {
        cliaddr->family = SOL_NETWORK_FAMILY_INET6;
        cliaddr->port = uip_ntohs(NET_BUF_UDP(netbuf)->srcport);
        memcpy(cliaddr->addr.in6, &NET_BUF_IP(netbuf)->srcipaddr, sizeof(cliaddr->addr.in6));
    }

    memcpy(buf, ip_buf_appdata(netbuf), buflen);

    ip_buf_unref(netbuf);

    return buflen;
}

#include <ip/simple-udp.h>

static int
sol_socket_zephyr_sendmsg(struct sol_socket *s, const void *buf, size_t len, const struct sol_network_link_addr *cliaddr)
{
    struct sol_socket_zephyr *socket = (struct sol_socket_zephyr *)s;
    struct net_context *ctx;
    struct net_tuple *tuple;
    struct net_buf *netbuf;
    uint8_t *ptr;

    ctx = socket->unicast_context;
    SOL_NULL_CHECK(ctx, -ENOTCONN);

    tuple = net_context_get_tuple(ctx);

    netbuf = ip_buf_get_tx(ctx);
    SOL_NULL_CHECK(netbuf, -ENOMEM);

    /* We set address and port on the packet as if we had received this from
     * the client we want to send to because net_reply() will revert them
     * before sending */
    memcpy(&NET_BUF_IP(netbuf)->srcipaddr, cliaddr->addr.in6, sizeof(cliaddr->addr.in6));
    memcpy(&NET_BUF_IP(netbuf)->destipaddr, &tuple->local_addr->in6_addr, sizeof(tuple->local_addr->in6_addr));
    NET_BUF_UDP(netbuf)->srcport = uip_htons(cliaddr->port);
    NET_BUF_UDP(netbuf)->destport = uip_htons(tuple->local_port);
    uip_set_udp_conn(netbuf) = net_context_get_udp_connection(ctx)->udp_conn;

    ptr = net_buf_add(netbuf, len);
    memcpy(ptr, buf, len);
    ip_buf_appdatalen(netbuf) = len;

    if (net_reply(ctx, netbuf) < 0) {
        ip_buf_unref(netbuf);
        return -EIO;
    }

    return len;
}

static int
sol_socket_zephyr_join_group(struct sol_socket *s, int ifindex, const struct sol_network_link_addr *group)
{
    struct sol_socket_zephyr *socket = (struct sol_socket_zephyr *)s;
    struct net_context *ctx;
    struct net_tuple *tuple;
    struct net_addr bindaddr;

    if (group->family != SOL_NETWORK_FAMILY_INET6)
        return -EAFNOSUPPORT;

    tuple = net_context_get_tuple(socket->unicast_context);
    SOL_NULL_CHECK(tuple, -EINVAL);

    bindaddr.family = sol_network_sol_to_af(group->family);
    memcpy(&bindaddr.in6_addr, group->addr.in6, sizeof(bindaddr.in6_addr));

    ctx = net_context_get(IPPROTO_UDP, NULL, 0, &bindaddr, tuple->local_port);
    SOL_NULL_CHECK(ctx, -ENOBUFS);

    sol_ptr_vector_append(&socket->mcast_contexts, ctx);

    return 0;
}

static int
sol_socket_zephyr_bind(struct sol_socket *s, const struct sol_network_link_addr *addr)
{
    struct sol_socket_zephyr *socket = (struct sol_socket_zephyr *)s;
    struct net_context *ctx;
    struct net_addr bindaddr;

    if (addr->family != SOL_NETWORK_FAMILY_INET6)
        return -EAFNOSUPPORT;

    if (socket->unicast_context)
        return -EALREADY;

    bindaddr.family = sol_network_sol_to_af(addr->family);
    memcpy(&bindaddr.in6_addr, addr->addr.in6, sizeof(bindaddr.in6_addr));

    ctx = net_context_get(IPPROTO_UDP, NULL, 0, &bindaddr, addr->port);
    SOL_NULL_CHECK(ctx, -ENOBUFS);

    socket->unicast_context = ctx;

    sol_ptr_vector_append(&bound_sockets, socket);

    if (!socket_recv_fiber_started) {
        socket_recv_fiber_started = true;
        fiber_start(socket_recv_fiber_stack, RECV_STACKSIZE, socket_recv_fiber,
            0, 0, 7, 0);
    }

    return 0;
}

const struct sol_socket_impl *
sol_socket_zephyr_get_impl(void)
{
    static struct sol_socket_impl impl = {
        .bind = sol_socket_zephyr_bind,
        .join_group = sol_socket_zephyr_join_group,
        .sendmsg = sol_socket_zephyr_sendmsg,
        .recvmsg = sol_socket_zephyr_recvmsg,
        .set_on_write = sol_socket_zephyr_set_on_write,
        .set_on_read = sol_socket_zephyr_set_on_read,
        .del = sol_socket_zephyr_del,
        .new = sol_socket_zephyr_new
    };

    return &impl;
}
