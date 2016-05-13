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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sol-memmap-storage-impl.h"

#include "sol-buffer.h"
#include "sol-mainloop.h"
#include "sol-str-slice.h"
#include "sol-str-table.h"
#include "sol-util-file.h"
#include "sol-util-internal.h"
#include "sol-vector.h"

#ifdef USE_I2C
#include <sol-i2c.h>
#endif

#define REL_PATH_IDX 2
#define DEV_NUMBER_IDX 3
#define DEV_NAME_IDX 4

struct map_internal_linux {
    struct map_internal base;
    char *resolved_path;
    FILE *file;
};

int
sol_memmap_impl_read_raw(struct map_internal *map,
    const struct sol_memmap_entry *entry,
    uint64_t mask,
    struct sol_buffer *buffer)
{
    struct map_internal_linux *map_internal = (struct map_internal_linux *)map;
    uint64_t value = 0;
    int fd, ret = 0;
    uint32_t i, j;

    fd = open(map_internal->resolved_path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        SOL_WRN("Could not open memory file [%s]: %s",
            map_internal->resolved_path, sol_util_strerrora(errno));
        return -errno;
    }

    if (lseek(fd, entry->offset, SEEK_SET) < 0)
        goto error;

    if ((ret = sol_util_fill_buffer_exactly(fd, buffer, entry->size)) < 0)
        goto error;

    if (mask) {
        for (i = 0, j = 0; i < entry->size; i++, j += 8)
            value |= (uint64_t)((uint8_t *)buffer->data)[i] << j;

        value &= mask;
        value >>= entry->bit_offset;

        memset(buffer->data, 0, buffer->capacity);
        for (i = 0; i < entry->size; i++, value >>= 8)
            ((uint8_t *)buffer->data)[i] = value & 0xff;
    }

    if (close(fd) < 0)
        return -errno;

    return 0;

error:
    if (!ret)
        ret = -errno;
    close(fd);

    return ret;
}

int
sol_memmap_impl_write_raw(struct map_internal *map,
    const char *name,
    const struct sol_memmap_entry *entry,
    uint64_t mask,
    struct sol_blob *blob,
    void (*cb)(void *data, const char *name, struct sol_blob *blob, int status),
    const void *data)
{
    struct map_internal_linux *map_internal = (struct map_internal_linux *)map;
    FILE *file = NULL;
    int ret = 0;

    if (!sol_blob_ref(blob))
        return -ENOMEM;

    if (map_internal->file) {
        file = map_internal->file;
    } else {
        file = fopen(map_internal->resolved_path, "r+e");
        if (!file) {
            SOL_WRN("Could not open memory file [%s]: %s",
                map_internal->resolved_path, sol_util_strerrora(errno));
            goto error;
        }
    }

    if (fseek(file, entry->offset, SEEK_SET) < 0)
        goto error;

    if (mask) {
        uint64_t value = 0, old_value;
        uint32_t i, j;

        /* entry->size > 8 implies that no mask should be used */
        assert(entry->size <= 8);

        for (i = 0, j = 0; i < entry->size; i++, j += 8)
            value |= (uint64_t)((uint8_t *)blob->mem)[i] << j;

        ret = fread(&old_value, entry->size, 1, file);
        if (!ret || ferror(file) || feof(file)) {
            errno = EIO;
            goto error;
        }

        /* We just read from file, let's rewind */
        if (fseek(file, entry->offset, SEEK_SET) < 0)
            goto error;

        value <<= entry->bit_offset;
        value &= mask;
        value |= (old_value & ~mask);
        fwrite(&value, entry->size, 1, file);
    } else {
        fwrite(blob->mem, sol_util_min(entry->size, blob->size), 1, file);
    }

    if (ferror(file)) {
        errno = EIO;
        goto error;
    }

    errno = 0;
    if (!map_internal->file)
        fclose(file);

    if (cb)
        cb((void *)data, name, blob, -errno);

    sol_blob_unref(blob);

    return -errno;

error:
    SOL_DBG("Error writing to file [%s]: %s", map_internal->resolved_path,
        sol_util_strerrora(errno));
    ret = -errno;
    if (file && !map_internal->file)
        fclose(file);

    if (cb)
        cb((void *)data, name, blob, ret);

    sol_blob_unref(blob);

    return ret;
}

bool
sol_memmap_impl_perform_pending_writes(void *data)
{
    struct map_internal_linux *map_internal = data;
    struct pending_write_data *pending;
    struct sol_vector tmp_vector;
    int i, r;

    map_internal->base.timeout = NULL;

    map_internal->file = fopen(map_internal->resolved_path, "r+e");
    if (!map_internal->file) {
        SOL_WRN("Error opening file [%s]: %s",
            map_internal->resolved_path, sol_util_strerrora(errno));
        return false;
    }

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

    r = fclose(map_internal->file);
    if (r == EOF)
        SOL_WRN("Error closing file [%s]: %s",
            map_internal->resolved_path, sol_util_strerrora(errno));

    map_internal->file = NULL;
    SOL_DBG("Performed pending writes on [%s]",
        map_internal->resolved_path);

    return false;
}

#ifdef USE_I2C
static int
resolve_i2c_path(const char *path, char **resolved_path)
{
    char *rel_path = NULL, *dev_number_s = NULL, *dev_name = NULL, *end_ptr;
    struct sol_str_slice command = sol_str_slice_from_str(path);
    struct sol_buffer result_path = SOL_BUFFER_INIT_EMPTY;
    struct sol_vector instructions;
    unsigned int dev_number;
    int ret = -EINVAL;

    instructions = sol_str_slice_split(command, ",", 5);
    if (instructions.len < 5) {
        SOL_WRN("Invalid create device path. Expected 'create,i2c,<rel_path>,"
            "<devnumber>,<devname>'");
        goto end;
    }

    rel_path = sol_str_slice_to_string(
        *(const struct sol_str_slice *)sol_vector_get(&instructions,
        REL_PATH_IDX));
    if (!rel_path) {
        ret = -EINVAL;
        goto end;
    }

    dev_number_s = sol_str_slice_to_string(
        *(const struct sol_str_slice *)sol_vector_get(&instructions,
        DEV_NUMBER_IDX));
    if (!dev_number_s) {
        ret = -EINVAL;
        goto end;
    }

    errno = 0;
    dev_number = strtoul(dev_number_s, &end_ptr, 0);
    if (errno || *end_ptr != '\0') {
        ret = -errno;
        goto end;
    }

    dev_name = sol_str_slice_to_string(
        *(const struct sol_str_slice *)sol_vector_get(&instructions,
        DEV_NAME_IDX));
    if (!dev_name) {
        ret = -EINVAL;
        goto end;
    }

    ret = sol_i2c_create_device(rel_path, dev_name, dev_number,
        &result_path);

    if (ret >= 0 || ret == -EEXIST) {
        const struct sol_str_slice ending = SOL_STR_SLICE_LITERAL("/eeprom");

        ret = sol_buffer_append_slice(&result_path, ending);
        if (ret < 0)
            goto end;

        *resolved_path = sol_buffer_steal(&result_path, NULL);

        ret = 0;
        /* Let's wait up to one second for it to be created */
        if (!sol_util_busy_wait_file(*resolved_path, SOL_UTIL_NSEC_PER_SEC)) {
            ret = -ENODEV;
            free(*resolved_path);
            goto end;
        }
    }

end:
    free(rel_path);
    free(dev_number_s);
    free(dev_name);
    sol_vector_clear(&instructions);

    errno = -ret;
    return ret;
}
#endif

static char *
resolve_map_path(const struct sol_memmap_map *map)
{
    int r;
#ifdef USE_I2C
    char *resolved_path = NULL;

    if (strstartswith(map->path, "create,i2c,")) {
        r = resolve_i2c_path(map->path, &resolved_path);
        if (r < 0) {
            SOL_WRN("Could not create i2c EEPROM device using command [%s]",
                map->path);
            errno = -r;
            goto error;
        }

        return resolved_path;
    }

    return strdup(map->path);

error:
    return NULL;
#else
    return strdup(map->path);
#endif
}

int
sol_memmap_impl_init(void)
{
    return 0;
}

struct map_internal *
sol_memmap_impl_map_new(const struct sol_memmap_map *map)
{
    struct map_internal_linux *map_internal;

    SOL_NULL_CHECK_ERRNO(map, EINVAL, NULL);

    map_internal = calloc(1, sizeof(*map_internal));
    SOL_NULL_CHECK_ERRNO(map, ENOMEM, NULL);

    map_internal->base.map = map;
    map_internal->resolved_path = resolve_map_path(map_internal->base.map);
    if (!map_internal->resolved_path) {
        free(map_internal);
        return NULL;
    }

    return (struct map_internal *)map_internal;
}

void
sol_memmap_impl_map_del(struct map_internal *map)
{
    struct map_internal_linux *map_internal = (struct map_internal_linux *)map;

    SOL_NULL_CHECK(map_internal);
    free(map_internal->resolved_path);
    free(map_internal);
}
