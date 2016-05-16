/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2015 Intel Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <zephyr.h>
#include <flash.h>
#include <device.h>

#include "sol-memmap-storage-impl.h"

#include "sol-buffer.h"
#include "sol-mainloop.h"
#include "sol-str-slice.h"
#include "sol-str-table.h"
#include "sol-util-file.h"
#include "sol-util-internal.h"
#include "sol-vector.h"

static struct device *flash_dev = NULL;

int
sol_memmap_impl_read_raw(struct map_internal *map_internal,
    const struct sol_memmap_entry *entry,
    uint64_t mask,
    struct sol_buffer *buffer)
{
    uint64_t value = 0;
    uint32_t i, j;
    int r;

    r = sol_buffer_ensure(buffer, entry->size);
    SOL_INT_CHECK(r, < 0, r);

    r = flash_read(flash_dev, FLASH_MEM_REGION_OFFSET, buf->data, entry->size);
    if (r < 0) {
        sol_buffer_fini(buffer);
        SOL_WRN("Flash read failed");
        return r;
    }

    if (mask) {
        for (i = 0, j = 0; i < entry->size; i++, j += 8)
            value |= (uint64_t)((uint8_t *)buffer->data)[i] << j;

        value &= mask;
        value >>= entry->bit_offset;

        memset(buffer->data, 0, buffer->capacity);
        for (i = 0; i < entry->size; i++, value >>= 8)
            ((uint8_t *)buffer->data)[i] = value & 0xff;
    }

    return 0;
}

int
sol_memmap_impl_write_raw(struct map_internal *map_internal,
    const char *name,
    const struct sol_memmap_entry *entry,
    uint64_t mask,
    struct sol_blob *blob,
    void (*cb)(void *data, const char *name, struct sol_blob *blob, int status),
    const void *data)
{
    int r = 0;

    if (!sol_blob_ref(blob))
        return -errno;

    if (mask) {
        uint64_t value = 0, old_value;
        uint32_t i, j;

        /* entry->size > 8 implies that no mask should be used */
        assert(entry->size <= 8);

        for (i = 0, j = 0; i < entry->size; i++, j += 8)
            value |= (uint64_t)((uint8_t *)blob->mem)[i] << j;

        r = flash_read(flash_dev, FLASH_MEM_REGION_OFFSET, &old_value,
            entry->size);
        if (r < 0) {
            SOL_WRN("Flash read failed");
            goto error;
        }

        value <<= entry->bit_offset;
        value &= mask;
        value |= (old_value & ~mask);

        r = flash_write(flash_dev, FLASH_MEM_REGION_OFFSET, &value,
            entry->size);
        if (r < 0)
            SOL_WRN("Flash write failed");
    } else {
        r = flash_write(flash_dev, FLASH_MEM_REGION_OFFSET, blob->mem,
            sol_util_min(entry->size, blob->size));
        if (r < 0)
            SOL_WRN("Flash write failed");
    }

    if (cb)
        cb((void *)data, name, blob, r);

    sol_blob_unref(blob);

    return r;

error:
    SOL_DBG("Error writing to memmap: %s", sol_util_strerrora(-r));

    if (cb)
        cb((void *)data, name, blob, r);

    sol_blob_unref(blob);

    return r;
}

bool
sol_memmap_impl_perform_pending_writes(void *data)
{
    struct map_internal *map_internal = data;
    struct pending_write_data *pending;
    struct sol_vector tmp_vector;
    int i, r;

    map_internal->base.timeout = NULL;

    tmp_vector = map_internal->base.pending_writes;
    sol_vector_init(&map_internal->base.pending_writes,
        sizeof(struct pending_write_data));

    SOL_VECTOR_FOREACH_IDX (&tmp_vector, pending, i) {
        sol_memmap_impl_write_raw((struct map_internal *)map_internal,
            pending->name, pending->entry, pending->mask, pending->blob,
            pending->cb, pending->data);
        free(pending->name);
        sol_blob_unref(pending->blob);
    }
    sol_vector_clear(&tmp_vector);

    SOL_DBG("Performed pending writes");

    return false;
}

int
sol_memmap_impl_init(void)
{
    if (flash_dev)
        return 0;

    flash_dev = device_get_binding("W25QXXDV");

    if (!flash_dev) {
        SOL_WRN("SPI flash driver was not found!\n");
        return -ENOSYS;
    }

    r = flash_write_protection_set(flash_dev, false);
    SOL_INT_CHECK(r, < 0, r);

    return r;
}

struct map_internal *
sol_memmap_impl_map_new(const struct sol_memmap_map *map)
{
    struct map_internal *map_internal;

    SOL_NULL_CHECK_ERRNO(map, EINVAL, NULL);

    map_internal = calloc(1, sizeof(*map_internal));
    SOL_NULL_CHECK_ERRNO(map, ENOMEM, NULL);

    map_internal->base.map = map;

    return (struct map_internal *)map_internal;
}

void
sol_memmap_impl_map_del(struct map_internal *map_internal)
{
    SOL_NULL_CHECK(map_internal);
    free(map_internal);
}
