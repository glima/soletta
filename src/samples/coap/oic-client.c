/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2015 Intel Corporation. All rights reserved.
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

#include <stdio.h>

#include "sol-log.h"
#include "sol-mainloop.h"

#include "sol-oic-client.h"

static void
got_get_response(sol_coap_responsecode_t response_code, struct sol_oic_client *cli, const struct sol_network_link_addr *srv_addr, const struct sol_oic_map_reader *map_reader, void *data)
{
    struct sol_oic_repr_field field;
    enum sol_oic_map_loop_reason end_reason;
    struct sol_oic_map_reader iterator;
    char addr[SOL_INET_ADDR_STRLEN];

    if (!srv_addr) {
        SOL_WRN("Response timeout");
        return;
    }

    if (!map_reader) {
        SOL_WRN("Empty Response");
        return;
    }

    if (!sol_network_addr_to_str(srv_addr, addr, sizeof(addr))) {
        SOL_WRN("Could not convert network address to string");
        return;
    }

    printf("Dumping payload received from addr %s {\n", addr);
    SOL_OIC_MAP_LOOP(map_reader, &field, &iterator, end_reason) {
        printf("\tkey: '%s', value: ", field.key);

        switch (field.type) {
        case SOL_OIC_REPR_TYPE_UINT:
            printf("uint(%" PRIu64 ")\n", field.v_uint);
            break;
        case SOL_OIC_REPR_TYPE_INT:
            printf("int(%" PRIi64 ")\n", field.v_int);
            break;
        case SOL_OIC_REPR_TYPE_SIMPLE:
            printf("simple(%d)\n", field.v_simple);
            break;
        case SOL_OIC_REPR_TYPE_TEXT_STRING:
            printf("str(%.*s)\n", (int)field.v_slice.len, field.v_slice.data);
            break;
        case SOL_OIC_REPR_TYPE_BYTE_STRING:
            printf("bytestr() [not dumping]\n");
            break;
        case SOL_OIC_REPR_TYPE_HALF_FLOAT:
            printf("hfloat(%p)\n", field.v_voidptr);
            break;
        case SOL_OIC_REPR_TYPE_FLOAT:
            printf("float(%f)\n", field.v_float);
            break;
        case SOL_OIC_REPR_TYPE_DOUBLE:
            printf("float(%g)\n", field.v_double);
            break;
        case SOL_OIC_REPR_TYPE_BOOLEAN:
            printf("boolean(%s)\n", field.v_boolean ? "true" : "false");
            break;
        default:
            printf("unknown(%d)\n", field.type);
        }
    }
    printf("}\n\n");
}

static bool
found_resource(struct sol_oic_client *cli, struct sol_oic_resource *res, void *data)
{
    static const char digits[] = "0123456789abcdef";
    struct sol_str_slice *slice;
    uint16_t idx;
    char addr[SOL_INET_ADDR_STRLEN];

    if (!res)
        return false;

#ifndef SOL_NO_API_VERSION
    if (SOL_UNLIKELY(res->api_version != SOL_OIC_RESOURCE_API_VERSION)) {
        SOL_WRN("Couldn't add resource_type with "
            "version '%u'. Expected version '%u'.",
            res->api_version, SOL_OIC_RESOURCE_API_VERSION);
        return NULL;
    }
#endif

    if (!sol_network_addr_to_str(&res->addr, addr, sizeof(addr))) {
        SOL_WRN("Could not convert network address to string");
        return false;
    }

    printf("Found resource: coap://%s%.*s\n", addr,
        SOL_STR_SLICE_PRINT(res->href));

    printf("Flags:\n"
        " - observable: %s\n"
        " - secure: %s\n",
        res->observable ? "yes" : "no",
        res->secure ? "yes" : "no");

    printf("Device ID: ");
    for (idx = 0; idx < 16; idx++) {
        unsigned int digit = res->device_id.data[idx];
        putchar(digits[(digit >> 4) & 0x0f]);
        putchar(digits[digit & 0x0f]);
    }
    putchar('\n');

    printf("Resource types:\n");
    SOL_VECTOR_FOREACH_IDX (&res->types, slice, idx)
        printf("\t\t%.*s\n", SOL_STR_SLICE_PRINT(*slice));

    printf("Resource interfaces:\n");
    SOL_VECTOR_FOREACH_IDX (&res->interfaces, slice, idx)
        printf("\t\t%.*s\n", SOL_STR_SLICE_PRINT(*slice));

    printf("Issuing GET %.*s on resource...\n", SOL_STR_SLICE_PRINT(res->href));
    sol_oic_client_resource_request(cli, res, SOL_COAP_METHOD_GET, NULL,
        NULL, got_get_response, data);

    printf("\n");

    return false;
}

int
main(int argc, char *argv[])
{
    struct sol_oic_client client = {
        SOL_SET_API_VERSION(.api_version = SOL_OIC_CLIENT_API_VERSION)
    };
    struct sol_network_link_addr srv_addr =
    { .family = SOL_NETWORK_FAMILY_INET6,
      .port = 5683 };
    const char *resource_type;

    sol_init();

    if (argc < 2) {
        SOL_INF("Usage: %s <address> [resource_type]\n", argv[0]);
        return 0;
    }

    if (!strchr(argv[1], ':'))
        srv_addr.family = SOL_NETWORK_FAMILY_INET;

    if (!sol_network_addr_from_str(&srv_addr, argv[1])) {
        printf("Could not convert IP address to sockaddr_in\n");
        return 1;
    }

    client.server = sol_coap_server_new(0);
    client.dtls_server = sol_coap_secure_server_new(0);

    printf("DTLS support %s\n",
        client.dtls_server ? "available" : "unavailable");

    if (argc < 3) {
        printf("No rt filter specified, assuming everything\n");
        resource_type = NULL;
    } else {
        printf("Finding resources with resource type %s\n", argv[2]);
        resource_type = argv[2];
    }

    sol_oic_client_find_resource(&client, &srv_addr,
        resource_type, found_resource, NULL);

    sol_run();

    return 0;
}
