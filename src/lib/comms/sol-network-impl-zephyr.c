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

#include <net/net_core.h>

#include "sol-log.h"
#include "sol-mainloop.h"
#include "sol-util.h"
#include "sol-vector.h"

#include "sol-network.h"

static struct sol_vector links = SOL_VECTOR_INIT(struct sol_network_link);

static inline char
to_hex(uint8_t num)
{
    return num > 9 ? (num - 10) + 'a' : num + '0';
}

SOL_API const char *
sol_network_addr_to_str(const struct sol_network_link_addr *addr,
    char *buf, uint32_t len)
{
    char *p;
    int i;

    SOL_NULL_CHECK(addr, NULL);
    SOL_NULL_CHECK(buf, NULL);

    if (addr->family != SOL_NETWORK_FAMILY_INET6)
        return NULL;

    if (len < 40)
        return NULL;

    for (i = 0, p = buf; i < 16; i++) {
        uint8_t num;

        if (i && i % 2 == 0)
            *p++ = ':';
        num = addr->addr.in6[i];
        *p++ = to_hex(num >> 4);
        *p++ = to_hex(num & 0xf);
    }
    *p = 0;

    return buf;
}

SOL_API const struct sol_network_link_addr *
sol_network_addr_from_str(struct sol_network_link_addr *addr, const char *buf)
{
    SOL_NULL_CHECK(addr, NULL);
    SOL_NULL_CHECK(buf, NULL);

    if (addr->family != SOL_NETWORK_FAMILY_INET6)
        return NULL;

    return NULL;
}

static bool
get_local_address(struct sol_network_link_addr *addr)
{
    struct net_context *empty_ctx;
    struct net_tuple *tuple;

    empty_ctx = net_context_get(IPPROTO_UDP, NULL, 0, NULL, 0);
    SOL_NULL_CHECK(empty_ctx, false);

    tuple = net_context_get_tuple(empty_ctx);

    addr->family = SOL_NETWORK_FAMILY_INET6;
    addr->port = 0;
    memcpy(&addr->addr.in6, &tuple->local_addr->in6_addr, sizeof(addr->addr.in6));

    net_context_put(empty_ctx);

    return true;
}

SOL_API int
sol_network_init(void)
{
    struct sol_network_link *iface;
    struct sol_network_link_addr *addr;
    static uint8_t fake_mac[] = { 0x84, 0x3a, 0x4b, 0x8c, 0xf6, 0x65 };

    net_init();

    net_set_mac(fake_mac, sizeof(fake_mac));

    iface = sol_vector_append(&links);
    SOL_NULL_CHECK(iface, -ENOMEM);

    sol_vector_init(&iface->addrs, sizeof(struct sol_network_link_addr));

    addr = sol_vector_append(&iface->addrs);
    SOL_NULL_CHECK_GOTO(addr, addr_append_error);

    if (!get_local_address(addr))
        goto get_address_error;

    SOL_SET_API_VERSION(iface->api_version = SOL_NETWORK_LINK_API_VERSION; )
    iface->index = 0;
    iface->flags = SOL_NETWORK_LINK_UP | SOL_NETWORK_LINK_RUNNING;

    return 0;

get_address_error:
    sol_vector_del(&iface->addrs, 0);
addr_append_error:
    sol_vector_del(&links, 0);
    return -ENOMEM;
}

SOL_API void
sol_network_shutdown(void)
{
    struct sol_network_link *link;
    uint16_t i;

    SOL_VECTOR_FOREACH_REVERSE_IDX (&links, link, i) {
        sol_vector_clear(&link->addrs);
    }

    sol_vector_clear(&links);

    return;
}

SOL_API bool
sol_network_subscribe_events(void (*cb)(void *data, const struct sol_network_link *link,
    enum sol_network_event event),
    const void *data)
{
    return false;
}

SOL_API bool
sol_network_unsubscribe_events(void (*cb)(void *data, const struct sol_network_link *link,
    enum sol_network_event event),
    const void *data)
{
    return false;
}

SOL_API const struct sol_vector *
sol_network_get_available_links(void)
{
    return &links;
}

SOL_API char *
sol_network_link_get_name(const struct sol_network_link *link)
{
    return NULL;
}
