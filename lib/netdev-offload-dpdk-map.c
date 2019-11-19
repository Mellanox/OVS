/*
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <config.h>

#include <rte_flow.h>

#include "dpif-netdev.h"
#include "netdev-offload-provider.h"
#include "netdev-offload-dpdk-private.h"
#include "openvswitch/vlog.h"
#include "id-pool.h"
#include "cmap.h"
#include "hash.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk_map);

struct context_metadata {
    const char *name;
    struct ds *(*ds_put_context_data)(struct ds *s, void *data);
    struct cmap d2i_cmap;
    struct cmap i2d_cmap;
    struct id_pool *pool;
    struct ovs_mutex mutex;
};

struct context_data {
    struct cmap_node d2i_node;
    struct cmap_node i2d_node;
    void *data;
    size_t data_size;
    uint32_t id;
    uint32_t refcnt;
};

static int
get_context_data_id_by_data(struct context_metadata *md,
                            struct context_data *data_req,
                            uint32_t *id)
{
    struct context_data *data_cur;
    size_t dhash, ihash;
    struct ds s;

    ds_init(&s);
    dhash = hash_bytes(data_req->data, data_req->data_size, 0);
    ovs_mutex_lock(&md->mutex);
    CMAP_FOR_EACH_WITH_HASH (data_cur, d2i_node, dhash, &md->d2i_cmap) {
        if (!memcmp(data_req->data, data_cur->data, data_req->data_size)) {
            data_cur->refcnt++;
            VLOG_DBG("%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                     ds_cstr(md->ds_put_context_data(&s, data_cur->data)),
                     data_cur->refcnt, data_cur->id);
            ds_destroy(&s);
            *id = data_cur->id;
            ovs_mutex_unlock(&md->mutex);
            return 0;
        }
    }

    data_cur = xzalloc(sizeof *data_cur);
    if (!data_cur) {
        goto err;
    }
    data_cur->data = xmalloc(data_req->data_size);
    if (!data_cur->data) {
        goto err_data_alloc;
    }
    memcpy(data_cur->data, data_req->data, data_req->data_size);
    data_cur->data_size = data_req->data_size;
    data_cur->refcnt = 1;
    if (!id_pool_alloc_id(md->pool, &data_cur->id)) {
        goto err_id_alloc;
    }
    cmap_insert(&md->d2i_cmap,
                CONST_CAST(struct cmap_node *, &data_cur->d2i_node), dhash);
    ihash = hash_add(0, data_cur->id);
    cmap_insert(&md->i2d_cmap,
                CONST_CAST(struct cmap_node *, &data_cur->i2d_node), ihash);
    VLOG_DBG("%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
             ds_cstr(md->ds_put_context_data(&s, data_cur->data)),
             data_cur->refcnt, data_cur->id);
    *id = data_cur->id;
    ovs_mutex_unlock(&md->mutex);
    ds_destroy(&s);
    return 0;

err_id_alloc:
    free(data_cur->data);
err_data_alloc:
    free(data_cur);
err:
    VLOG_ERR("%s: %s: error. '%s'", __func__, md->name,
             ds_cstr(md->ds_put_context_data(&s, data_cur->data)));
    ovs_mutex_unlock(&md->mutex);
    ds_destroy(&s);
    return -1;
}

static struct context_data *
get_context_data_by_id(struct context_metadata *md, uint32_t id)
{
    size_t ihash = hash_add(0, id);
    struct context_data *data_cur;
    struct ds s;

    ds_init(&s);
    CMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_cmap) {
        if (data_cur->id == id) {
            VLOG_DBG("%s: %s: id=%d found. '%s'", __func__, md->name, id,
                     ds_cstr(md->ds_put_context_data(&s, data_cur->data)));
            ds_destroy(&s);
            return data_cur;
        }
    }

    VLOG_DBG("%s: %s: id=%d was not found", __func__, md->name, id);
    ds_destroy(&s);
    return NULL;
}

static void
put_context_data_by_id(struct context_metadata *md, uint32_t id)
{
    struct context_data *data_cur;
    size_t dhash, ihash;
    struct ds s;

    ihash = hash_add(0, id);
    ovs_mutex_lock(&md->mutex);
    CMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_cmap) {
        if (data_cur->id == id) {
            data_cur->refcnt--;
            ds_init(&s);
            VLOG_DBG("%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                     ds_cstr(md->ds_put_context_data(&s, data_cur->data)),
                     data_cur->refcnt, data_cur->id);
            ds_destroy(&s);
            if (data_cur->refcnt == 0) {
                cmap_remove(&md->i2d_cmap,
                            CONST_CAST(struct cmap_node *,
                                       &data_cur->i2d_node), ihash);
                dhash = hash_bytes(data_cur->data, data_cur->data_size, 0);
                cmap_remove(&md->d2i_cmap,
                            CONST_CAST(struct cmap_node *,
                                       &data_cur->d2i_node), dhash);
                free(data_cur);
                id_pool_free_id(md->pool, id);
            }
            ovs_mutex_unlock(&md->mutex);
            return;
        }
    }
    VLOG_ERR("%s: %s: error. id=%d not found", __func__, md->name, id);
    ovs_mutex_unlock(&md->mutex);
}

static struct ds *
ds_put_table_id(struct ds *s, void *data)
{
    int *table_id_data = data;

    ds_put_format(s, "vport=%d", table_id_data[0]);
    return s;
}

static struct context_metadata table_id_md = {
    .name = "table_id",
    .ds_put_context_data = ds_put_table_id,
    .d2i_cmap = CMAP_INITIALIZER,
    .i2d_cmap = CMAP_INITIALIZER,
    .pool = NULL,
    .mutex = OVS_MUTEX_INITIALIZER,
};

#define ROOT_TABLE_ID    0
#define MIN_TABLE_ID     1
#define MAX_TABLE_ID     0xFFFF

int
get_table_id(odp_port_t vport, uint32_t *table_id)
{
    odp_port_t table_id_data[] = { vport };
    struct context_data table_id_context = {
        .data = table_id_data,
        .data_size = sizeof table_id_data,
    };

    if (!table_id_md.pool) {
        /* Haven't initiated yet, do it here */
        table_id_md.pool = id_pool_create(MIN_TABLE_ID, MAX_TABLE_ID);
    }

    if (vport == 0) {
        return ROOT_TABLE_ID;
    }
    return get_context_data_id_by_data(&table_id_md, &table_id_context,
                                       table_id);
}

void
put_table_id(uint32_t table_id)
{
    if (table_id == ROOT_TABLE_ID) {
        return;
    }
    put_context_data_by_id(&table_id_md, table_id);
}

static struct ds *
ds_put_flow_ctx_id(struct ds *s, void *data)
{
    struct flow_miss_ctx *flow_ctx_data = data;

    ds_put_format(s, "vport=%d", flow_ctx_data->vport);
    return s;
}

static struct context_metadata flow_miss_ctx_md = {
    .name = "flow_miss_ctx",
    .ds_put_context_data = ds_put_flow_ctx_id,
    .d2i_cmap = CMAP_INITIALIZER,
    .i2d_cmap = CMAP_INITIALIZER,
    .pool = NULL,
    .mutex = OVS_MUTEX_INITIALIZER,
};

int
get_flow_miss_ctx_id(struct flow_miss_ctx *flow_ctx_data,
                         uint32_t *miss_ctx_id)
{
    struct context_data flow_ctx = {
        .data = flow_ctx_data,
        .data_size = sizeof flow_ctx_data,
    };

    if (!flow_miss_ctx_md.pool) {
        /* Haven't initiated yet, do it here */
        flow_miss_ctx_md.pool = netdev_offload_get_mark_pool();
    }

    return get_context_data_id_by_data(&flow_miss_ctx_md, &flow_ctx,
                                       miss_ctx_id);
}

void
put_flow_miss_ctx_id(uint32_t flow_ctx_id)
{
    if (flow_ctx_id == 0) {
        return;
    }
    put_context_data_by_id(&flow_miss_ctx_md, flow_ctx_id);
}

struct flow_miss_ctx *
find_flow_miss_ctx(int flow_ctx_id)
{
    struct context_data *ctx_data;

    ctx_data = get_context_data_by_id(&flow_miss_ctx_md, flow_ctx_id);
    if (!ctx_data) {
        return NULL;
    }

    return (struct flow_miss_ctx *)ctx_data->data;
}
