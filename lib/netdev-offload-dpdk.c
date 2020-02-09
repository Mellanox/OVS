/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
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

#include <sys/types.h>
#include <netinet/ip6.h>
#include <rte_flow.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"
#include "id-pool.h"
#include "odp-util.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Thread-safety
 * =============
 *
 * Below API is NOT thread safe in following terms:
 *
 *  - The caller must be sure that none of these functions will be called
 *    simultaneously.  Even for different 'netdev's.
 *
 *  - The caller must be sure that 'netdev' will not be destructed/deallocated.
 *
 *  - The caller must be sure that 'netdev' configuration will not be changed.
 *    For example, simultaneous call of 'netdev_reconfigure()' for the same
 *    'netdev' is forbidden.
 *
 * For current implementation all above restrictions could be fulfilled by
 * taking the datapath 'port_mutex' in lib/dpif-netdev.c.  */

/*
 * A mapping from ufid to dpdk rte_flow.
 */
static struct cmap ufid_to_rte_flow = CMAP_INITIALIZER;

struct act_resources {
    uint32_t next_table_id;
    uint32_t self_table_id;
    uint32_t flow_miss_ctx_id;
    uint32_t tnl_id;
    uint32_t ct_table_id;
    uint32_t post_ct_table_id;
    uint32_t flow_id;
    bool associated_flow_id;
    uint32_t ct_miss_ctx_id;
    uint32_t ct_nat_table_id;
};

#define NUM_RTE_FLOWS_PER_PORT 2
struct flow_item {
    const char *devargs;
    struct rte_flow *rte_flow[NUM_RTE_FLOWS_PER_PORT];
    bool has_count[NUM_RTE_FLOWS_PER_PORT];
};

struct flows_handle {
    struct flow_item *items;
    int cnt;
    int current_max;
};

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct flows_handle flows;
    bool actions_offloaded;
    struct dpif_flow_stats stats;
    struct act_resources act_resources;
};

static void
free_flow_handle(struct flows_handle *flows)
{
    int i;

    for (i = 0; i < flows->cnt; i++) {
        if (flows->items[i].devargs) {
            free(CONST_CAST(void *, flows->items[i].devargs));
        }
    }
    free(flows->items);
    flows->items = NULL;
    flows->cnt = 0;
}

static void
add_flow_item(struct flows_handle *flows,
              struct flow_item *item)
{
    int cnt = flows->cnt;

    if (cnt == 0) {
        flows->current_max = 1;
        flows->items = xcalloc(flows->current_max, sizeof *flows->items);
    } else if (cnt == flows->current_max) {
        flows->current_max *= 2;
        flows->items = xrealloc(flows->items, flows->current_max *
                                sizeof *flows->items);
    }

    memcpy(&flows->items[cnt], item, sizeof flows->items[cnt]);
    flows->items[cnt].devargs = nullable_xstrdup(item->devargs);
    flows->cnt++;
}

/* Find rte_flow_data with @ufid. */
static struct ufid_to_rte_flow_data *
ufid_to_rte_flow_data_find(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static inline void
ufid_to_rte_flow_associate(const ovs_u128 *ufid,
                           struct flows_handle *flows, bool actions_offloaded,
                           struct act_resources *act_resources)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data = xzalloc(sizeof *data);
    struct ufid_to_rte_flow_data *data_prev;

    /*
     * We should not simply overwrite an existing rte flow.
     * We should have deleted it first before re-adding it.
     * Thus, if following assert triggers, something is wrong:
     * the rte_flow is not destroyed.
     */
    data_prev = ufid_to_rte_flow_data_find(ufid);
    if (data_prev) {
        ovs_assert(data_prev->flows.cnt == 0);
    }

    data->ufid = *ufid;
    data->actions_offloaded = actions_offloaded;
    memcpy(&data->flows, flows, sizeof data->flows);
    memcpy(&data->act_resources, act_resources, sizeof data->act_resources);

    cmap_insert(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

static inline void
ufid_to_rte_flow_disassociate(struct ufid_to_rte_flow_data *data)
{
    size_t hash;

    hash = hash_bytes(&data->ufid, sizeof data->ufid, 0);
    cmap_remove(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
    ovsrcu_postpone(free, data);
}

/* A generic data structure used for mapping data to id and id to data. The
 * elements are reference coutned. As changes are done only from the single
 * offload thread, no locks are required.
 * "name" and "dump_context_data" are used for log messages.
 * "d2i_hmap" is the data-to-id map.
 * "i2d_hmap" is the id-to-data map.
 * "associated_i2d_cmap" is a id-to-data map used to associate already
 *      allocated ids.
 * "has_associated_map" is true if this metadata has an associated map.
 * "id_alloc" is used to allocate an id for a new data.
 * "id_free" is used to free an id for the last data release.
 * "data_size" is the size of the data in the elements.
 */
struct context_metadata {
    const char *name;
    struct ds *(*dump_context_data)(struct ds *s, void *data);
    struct hmap d2i_hmap;
    struct hmap i2d_hmap;
    struct hmap associated_i2d_hmap;
    bool has_associated_map;
    uint32_t (*id_alloc)(void);
    void (*id_free)(uint32_t id);
    size_t data_size;
};

struct context_data {
    struct hmap_node d2i_node;
    struct hmap_node i2d_node;
    struct hmap_node associated_i2d_node;
    void *data;
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
    dhash = hash_bytes(data_req->data, md->data_size, 0);
    HMAP_FOR_EACH_WITH_HASH (data_cur, d2i_node, dhash, &md->d2i_hmap) {
        if (!memcmp(data_req->data, data_cur->data, md->data_size)) {
            data_cur->refcnt++;
            VLOG_DBG_RL(&rl,
                        "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                        ds_cstr(md->dump_context_data(&s, data_cur->data)),
                        data_cur->refcnt, data_cur->id);
            ds_destroy(&s);
            *id = data_cur->id;
            return 0;
        }
    }

    data_cur = xzalloc(sizeof *data_cur);
    if (!data_cur) {
        goto err;
    }
    data_cur->data = xmalloc(md->data_size);
    if (!data_cur->data) {
        goto err_data_alloc;
    }
    memcpy(data_cur->data, data_req->data, md->data_size);
    data_cur->refcnt = 1;
    data_cur->id = md->id_alloc();
    if (data_cur->id == 0) {
        goto err_id_alloc;
    }
    hmap_insert(&md->d2i_hmap, &data_cur->d2i_node, dhash);
    ihash = hash_add(0, data_cur->id);
    hmap_insert(&md->i2d_hmap, &data_cur->i2d_node, ihash);
    VLOG_DBG_RL(&rl, "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                ds_cstr(md->dump_context_data(&s, data_cur->data)),
                data_cur->refcnt, data_cur->id);
    *id = data_cur->id;
    ds_destroy(&s);
    return 0;

err_id_alloc:
    free(data_cur->data);
err_data_alloc:
    free(data_cur);
err:
    VLOG_ERR_RL(&rl, "%s: %s: error. '%s'", __func__, md->name,
                ds_cstr(md->dump_context_data(&s, data_cur->data)));
    ds_destroy(&s);
    return -1;
}

static int
get_context_data_by_id(struct context_metadata *md, uint32_t id, void *data)
{
    size_t ihash = hash_add(0, id);
    struct context_data *data_cur;
    struct ds s;

    ds_init(&s);
    if (md->has_associated_map) {
        HMAP_FOR_EACH_WITH_HASH (data_cur, associated_i2d_node, ihash,
                                 &md->associated_i2d_hmap) {
            if (data_cur->id == id) {
                memcpy(data, data_cur->data, md->data_size);
                ds_destroy(&s);
                return 0;
            }
        }
    }
    HMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_hmap) {
        if (data_cur->id == id) {
            memcpy(data, data_cur->data, md->data_size);
            ds_destroy(&s);
            return 0;
        }
    }

    ds_destroy(&s);
    return -1;
}

static void
put_context_data_by_id(struct context_metadata *md, uint32_t id)
{
    struct context_data *data_cur;
    size_t ihash;
    struct ds s;

    if (id == 0) {
        return;
    }
    ihash = hash_add(0, id);
    HMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_hmap) {
        if (data_cur->id == id) {
            data_cur->refcnt--;
            ds_init(&s);
            VLOG_DBG_RL(&rl,
                        "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                        ds_cstr(md->dump_context_data(&s, data_cur->data)),
                        data_cur->refcnt, data_cur->id);
            ds_destroy(&s);
            if (data_cur->refcnt == 0) {
                hmap_remove(&md->i2d_hmap, &data_cur->i2d_node);
                hmap_remove(&md->d2i_hmap, &data_cur->d2i_node);
                free(data_cur);
                md->id_free(id);
            }
            return;
        }
    }
    VLOG_ERR_RL(&rl,
                "%s: %s: error. id=%d not found", __func__, md->name, id);
}

static int
associate_id_data(struct context_metadata *md,
                  struct context_data *data_req)
{
    struct context_data *data_cur;
    size_t ihash;
    struct ds s;

    ds_init(&s);
    data_cur = xzalloc(sizeof *data_cur);
    if (!data_cur) {
        goto err;
    }
    data_cur->data = xmalloc(md->data_size);
    if (!data_cur->data) {
        goto err_data_alloc;
    }
    memcpy(data_cur->data, data_req->data, md->data_size);
    data_cur->refcnt = 1;
    data_cur->id = data_req->id;
    ihash = hash_add(0, data_cur->id);
    hmap_insert(&md->associated_i2d_hmap, &data_cur->associated_i2d_node,
                ihash);
    VLOG_DBG_RL(&rl, "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                ds_cstr(md->dump_context_data(&s, data_cur->data)),
                data_cur->refcnt, data_cur->id);
    ds_destroy(&s);
    return 0;

err_data_alloc:
    free(data_cur);
err:
    VLOG_ERR_RL(&rl, "%s: %s: error. '%s'", __func__, md->name,
                ds_cstr(md->dump_context_data(&s, data_cur->data)));
    ds_destroy(&s);
    return -1;
}

static int
disassociate_id_data(struct context_metadata *md, uint32_t id)
{
    struct context_data *data_cur;
    size_t ihash;
    struct ds s;

    ihash = hash_add(0, id);
    HMAP_FOR_EACH_WITH_HASH (data_cur, associated_i2d_node, ihash,
                             &md->associated_i2d_hmap) {
        if (data_cur->id == id) {
            ds_init(&s);
            VLOG_DBG_RL(&rl, "%s: %s: '%s', id=%d", __func__, md->name,
                        ds_cstr(md->dump_context_data(&s, data_cur->data)),
                        data_cur->id);
            ds_destroy(&s);
            hmap_remove(&md->associated_i2d_hmap,
                        &data_cur->associated_i2d_node);
            free(data_cur);
            return 0;
        }
    }
    VLOG_DBG_RL(&rl, "%s: %s: error. id=%d not found", __func__, md->name, id);
    return -1;
}

enum {
    REG_FIELD_CT_STATE,
    REG_FIELD_CT_ZONE,
    REG_FIELD_CT_MARK,
    REG_FIELD_CT_LABEL0,
    REG_FIELD_CT_LABEL1,
    REG_FIELD_CT_LABEL2,
    REG_FIELD_CT_LABEL3,
    REG_FIELD_TUN_INFO,
    REG_FIELD_CT_CTX,
    REG_FIELD_NUM,
};

enum reg_type {
    REG_TYPE_TAG,
    REG_TYPE_META,
};

struct reg_field {
    enum reg_type type;
    uint8_t index;
    uint32_t offset;
    uint32_t mask;
};

static struct reg_field reg_fields[] = {
    [REG_FIELD_CT_STATE] = {
        .type = REG_TYPE_TAG,
        .index = 0,
        .offset = 0,
        .mask = 0x000000FF,
    },
    [REG_FIELD_CT_ZONE] = {
        .type = REG_TYPE_TAG,
        .index = 0,
        .offset = 8,
        .mask = 0x000000FF,
    },
    [REG_FIELD_TUN_INFO] = {
        .type = REG_TYPE_TAG,
        .index = 0,
        .offset = 16,
        .mask = 0x0000FFFF,
    },
    [REG_FIELD_CT_MARK] = {
        .type = REG_TYPE_TAG,
        .index = 1,
        .offset = 0,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_LABEL0] = {
        .type = REG_TYPE_TAG,
        .index = 2,
        .offset = 0,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_LABEL1] = {
        .type = REG_TYPE_TAG,
        .index = 3,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_LABEL2] = {
        .type = REG_TYPE_TAG,
        .index = 4,
        .offset = 0,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_LABEL3] = {
        .type = REG_TYPE_TAG,
        .index = 5,
        .offset = 0,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_CTX] = {
        .type = REG_TYPE_META,
        .index = 0,
        .offset = 0,
        .mask = 0x0000FFFF,
    },
};

enum table_type {
    TABLE_TYPE_FLOW,
    TABLE_TYPE_CT,
    TABLE_TYPE_CT_NAT,
    TABLE_TYPE_POST_CT,
};

struct table_id_data {
    odp_port_t vport;
    uint32_t recirc_id;
    enum table_type table_type;
};

static struct ds *
dump_table_id(struct ds *s, void *data)
{
    struct table_id_data *table_id_data = data;
    char *table_type_str;

    switch (table_id_data->table_type) {
    case TABLE_TYPE_FLOW:
        table_type_str = "flow";
        break;
    case TABLE_TYPE_CT:
        table_type_str = "ct";
        break;
    case TABLE_TYPE_CT_NAT:
        table_type_str = "ct-nat";
        break;
    case TABLE_TYPE_POST_CT:
        table_type_str = "post-ct";
        break;
    default:
        OVS_NOT_REACHED();
    }

    ds_put_format(s, "(%s): vport=%"PRIu32", recirc_id=%"PRIu32,
                  table_type_str, table_id_data->vport,
                  table_id_data->recirc_id);
    return s;
}

#define MIN_TABLE_ID     1
#define MAX_TABLE_ID     0xFFFF

static struct id_pool *table_id_pool = NULL;
static uint32_t
table_id_alloc(void)
{
    uint32_t id;

    if (!table_id_pool) {
        /* Haven't initiated yet, do it here */
        table_id_pool = id_pool_create(MIN_TABLE_ID, MAX_TABLE_ID);
    }

    if (id_pool_alloc_id(table_id_pool, &id)) {
        return id;
    }

    return 0;
}

static void
table_id_free(uint32_t id)
{
    id_pool_free_id(table_id_pool, id);
}

static struct context_metadata table_id_md = {
    .name = "table_id",
    .dump_context_data = dump_table_id,
    .d2i_hmap = HMAP_INITIALIZER(&table_id_md.d2i_hmap),
    .i2d_hmap = HMAP_INITIALIZER(&table_id_md.i2d_hmap),
    .id_alloc = table_id_alloc,
    .id_free = table_id_free,
    .data_size = sizeof(struct table_id_data),
};

static int
get_table_id(odp_port_t vport, uint32_t recirc_id, enum table_type table_type,
             uint32_t *table_id)
{
    struct table_id_data table_id_data = {
        .vport = vport,
        .recirc_id = recirc_id,
        .table_type = table_type,
    };
    struct context_data table_id_context = {
        .data = &table_id_data,
    };

    if (vport == ODPP_NONE && recirc_id == 0 &&
        table_type == TABLE_TYPE_FLOW) {
        *table_id = 0;
        return 0;
    }

    return get_context_data_id_by_data(&table_id_md, &table_id_context,
                                       table_id);
}

static void
put_table_id(uint32_t table_id)
{
    put_context_data_by_id(&table_id_md, table_id);
}

#define MIN_CT_CTX_ID 1
#define MAX_CT_CTX_ID reg_fields[REG_FIELD_CT_CTX].mask

static struct id_pool *ct_ctx_pool = NULL;

static uint32_t
ct_ctx_id_alloc(void)
{
    uint32_t id;

    if (!ct_ctx_pool) {
        /* Haven't initiated yet, do it here */
        ct_ctx_pool = id_pool_create(MIN_CT_CTX_ID, MAX_CT_CTX_ID);
    }

    if (id_pool_alloc_id(ct_ctx_pool, &id)) {
        return id;
    }

    return 0;
}

static void
ct_ctx_id_free(uint32_t id)
{
    id_pool_free_id(ct_ctx_pool, id);
}

struct ct_miss_ctx {
    uint8_t state;
    uint16_t zone;
    uint32_t mark;
    ovs_u128 label;
};

static struct ds *
dump_ct_ctx_id(struct ds *s, void *data)
{
    struct ct_miss_ctx *ct_ctx_data = data;

    ds_put_format(s, "ct_state=0x%"PRIx8", zone=%d", ct_ctx_data->state,
                  ct_ctx_data->zone);
    return s;
}

static struct context_metadata ct_miss_ctx_md = {
    .name = "ct_miss_ctx",
    .dump_context_data = dump_ct_ctx_id,
    .d2i_hmap = HMAP_INITIALIZER(&ct_miss_ctx_md.d2i_hmap),
    .i2d_hmap = HMAP_INITIALIZER(&ct_miss_ctx_md.i2d_hmap),
    .id_alloc = ct_ctx_id_alloc,
    .id_free = ct_ctx_id_free,
    .data_size = sizeof(struct ct_miss_ctx),
};

static int
get_ct_ctx_id(struct ct_miss_ctx *ct_miss_ctx_data, uint32_t *ct_ctx_id)
{
    struct context_data ct_ctx = {
        .data = ct_miss_ctx_data,
    };

    return get_context_data_id_by_data(&ct_miss_ctx_md, &ct_ctx, ct_ctx_id);
}

static void
put_ct_ctx_id(uint32_t ct_ctx_id)
{
    put_context_data_by_id(&ct_miss_ctx_md, ct_ctx_id);
}

static int
find_ct_miss_ctx(int ct_ctx_id, struct ct_miss_ctx *ctx)
{
    return get_context_data_by_id(&ct_miss_ctx_md, ct_ctx_id, ctx);
}

#define MIN_TUNNEL_ID 1
#define MAX_TUNNEL_ID reg_fields[REG_FIELD_TUN_INFO].mask

static struct id_pool *tnl_id_pool = NULL;

static uint32_t
tnl_id_alloc(void)
{
    uint32_t id;

    if (!tnl_id_pool) {
        /* Haven't initiated yet, do it here */
        tnl_id_pool = id_pool_create(MIN_TUNNEL_ID, MAX_TUNNEL_ID);
    }

    if (id_pool_alloc_id(tnl_id_pool, &id)) {
        return id;
    }

    return 0;
}

static void
tnl_id_free(uint32_t id)
{
    id_pool_free_id(tnl_id_pool, id);
}

static struct ds *
dump_tnl_id(struct ds *s, void *data)
{
    struct flow_tnl *tnl = data;

    ds_put_format(s, IP_FMT" -> "IP_FMT", tun_id=%"PRIu64,
                  IP_ARGS(tnl->ip_src), IP_ARGS(tnl->ip_dst),
                  ntohll(tnl->tun_id));
    return s;
}

static struct context_metadata tnl_md = {
    .name = "tunnel",
    .dump_context_data = dump_tnl_id,
    .d2i_hmap = HMAP_INITIALIZER(&tnl_md.d2i_hmap),
    .i2d_hmap = HMAP_INITIALIZER(&tnl_md.i2d_hmap),
    .id_alloc = tnl_id_alloc,
    .id_free = tnl_id_free,
    .data_size = 2 * sizeof(struct flow_tnl),
};

static void
get_tnl_masked(struct flow_tnl *dst_key, struct flow_tnl *dst_mask,
               struct flow_tnl *src_key, struct flow_tnl *src_mask)
{
    char *psrc_key, *psrc_mask;
    char *pdst_key;
    int i;

    if (dst_mask) {
        memcpy(dst_mask, src_mask, sizeof *dst_mask);

        pdst_key = (char *)dst_key;
        psrc_key = (char *)src_key;
        psrc_mask = (char *)src_mask;
        for (i = 0; i < sizeof *dst_key; i++) {
            *pdst_key++ = *psrc_key++ & *psrc_mask++;
        }
    } else {
        memcpy(dst_key, src_key, sizeof *dst_key);
    }
}

static int
get_tnl_id(struct flow_tnl *tnl_key, struct flow_tnl *tnl_mask,
           uint32_t *tnl_id)
{
    struct flow_tnl tnl_tmp[2];
    struct context_data tnl_ctx = {
        .data = tnl_tmp,
    };

    get_tnl_masked(&tnl_tmp[0], &tnl_tmp[1], tnl_key, tnl_mask);
    if (is_all_zeros(&tnl_tmp, sizeof tnl_tmp)) {
        *tnl_id = 0;
        return 0;
    }
    return get_context_data_id_by_data(&tnl_md, &tnl_ctx, tnl_id);
}

static void
put_tnl_id(uint32_t tnl_id)
{
    put_context_data_by_id(&tnl_md, tnl_id);
}

struct flow_miss_ctx {
    odp_port_t vport;
    uint32_t recirc_id;
    struct flow_tnl tnl;
};

static struct ds *
dump_flow_ctx_id(struct ds *s, void *data)
{
    struct flow_miss_ctx *flow_ctx_data = data;

    ds_put_format(s, "vport=%"PRIu32", recirc_id=%"PRIu32", ",
                  flow_ctx_data->vport, flow_ctx_data->recirc_id);
    dump_tnl_id(s, &flow_ctx_data->tnl);

    return s;
}

static struct context_metadata flow_miss_ctx_md = {
    .name = "flow_miss_ctx",
    .dump_context_data = dump_flow_ctx_id,
    .d2i_hmap = HMAP_INITIALIZER(&flow_miss_ctx_md.d2i_hmap),
    .i2d_hmap = HMAP_INITIALIZER(&flow_miss_ctx_md.i2d_hmap),
    .associated_i2d_hmap =
        HMAP_INITIALIZER(&flow_miss_ctx_md.associated_i2d_hmap),
    .has_associated_map = true,
    .id_alloc = netdev_offload_flow_mark_alloc,
    .id_free = netdev_offload_flow_mark_free,
    .data_size = sizeof(struct flow_miss_ctx),
};

static int
get_flow_miss_ctx_id(struct flow_miss_ctx *flow_ctx_data,
                     uint32_t *miss_ctx_id)
{
    struct context_data flow_ctx = {
        .data = flow_ctx_data,
    };

    return get_context_data_id_by_data(&flow_miss_ctx_md, &flow_ctx,
                                       miss_ctx_id);
}

static void
put_flow_miss_ctx_id(uint32_t flow_ctx_id)
{
    put_context_data_by_id(&flow_miss_ctx_md, flow_ctx_id);
}

static int
find_flow_miss_ctx(int flow_ctx_id, struct flow_miss_ctx *ctx)
{
    return get_context_data_by_id(&flow_miss_ctx_md, flow_ctx_id, ctx);
}

static int
associate_flow_id(uint32_t flow_id, struct flow_miss_ctx *flow_ctx_data)
{
    struct context_data flow_ctx = {
        .data = flow_ctx_data,
        .id = flow_id,
    };

    flow_miss_ctx_md.data_size = sizeof *flow_ctx_data;

    return associate_id_data(&flow_miss_ctx_md, &flow_ctx);
}

static int
disassociate_flow_id(uint32_t flow_id)
{
    return disassociate_id_data(&flow_miss_ctx_md, flow_id);
}

static void
put_action_resources(struct act_resources *act_resources)
{
    put_table_id(act_resources->self_table_id);
    put_table_id(act_resources->next_table_id);
    put_flow_miss_ctx_id(act_resources->flow_miss_ctx_id);
    put_tnl_id(act_resources->tnl_id);
    put_table_id(act_resources->ct_table_id);
    put_table_id(act_resources->post_ct_table_id);
    if (act_resources->associated_flow_id) {
        disassociate_flow_id(act_resources->flow_id);
    }
    put_ct_ctx_id(act_resources->ct_miss_ctx_id);
    put_table_id(act_resources->ct_nat_table_id);
}

/*
 * To avoid individual xrealloc calls for each new element, a 'curent_max'
 * is used to keep track of current allocated number of elements. Starts
 * by 8 and doubles on each xrealloc call.
 */
struct flow_patterns {
    struct rte_flow_item *items;
    int cnt;
    int current_max;
};

struct flow_actions {
    struct rte_flow_action *actions;
    int cnt;
    int current_max;
};

static void
dump_flow_attr(struct ds *s, struct ds *s1, const struct rte_flow_attr *attr)
{
    ds_put_format(s,
                  "  Attributes: "
                  "ingress=%d, egress=%d, prio=%d, group=%d, transfer=%d\n",
                  attr->ingress, attr->egress, attr->priority, attr->group,
                  attr->transfer);
    ds_put_format(s1, "%s%spriority %d group %d %s",
                  attr->ingress ? "ingress " : "",
                  attr->egress ? "egress " : "", attr->priority, attr->group,
                  attr->transfer ? "transfer " : "");
}

static void
dump_flow_pattern(struct ds *s, struct ds *_s1,
                  const struct rte_flow_item *item)
{
    struct ds *s1, s1tmp;

    if (!_s1) {
        s1 = &s1tmp;
        ds_init(s1);
    } else {
        s1 = _s1;
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        ds_put_cstr(s, "rte flow eth pattern:\n");
        ds_put_cstr(s1, "eth ");
        if (eth_spec) {
            ds_put_format(s,
                          "  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04" PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                          ntohs(eth_spec->type));
            ds_put_format(s1,
                          "src spec "ETH_ADDR_FMT" dst spec "ETH_ADDR_FMT" "
                          "type spec 0x%04"PRIx16" ",
                          ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                          ntohs(eth_spec->type));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (eth_mask) {
            ds_put_format(s,
                          "  Mask: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04"PRIx16"\n",
                          ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                          ntohs(eth_mask->type));
            ds_put_format(s1,
                          "src mask "ETH_ADDR_FMT" dst mask "ETH_ADDR_FMT" "
                          "type mask 0x%04"PRIx16" ",
                          ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                          ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                          ntohs(eth_mask->type));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        ds_put_cstr(s, "rte flow vlan pattern:\n");
        if (vlan_spec) {
            ds_put_format(s,
                          "  Spec: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_spec->inner_type), ntohs(vlan_spec->tci));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }

        if (vlan_mask) {
            ds_put_format(s,
                          "  Mask: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                          ntohs(vlan_mask->inner_type), ntohs(vlan_mask->tci));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        ds_put_cstr(s, "rte flow ipv4 pattern:\n");
        ds_put_cstr(s1, "ipv4 ");
        if (ipv4_spec) {
            ds_put_format(s,
                          "  Spec: tos=0x%"PRIx8", ttl=%"PRIx8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_spec->hdr.type_of_service,
                          ipv4_spec->hdr.time_to_live,
                          ipv4_spec->hdr.next_proto_id,
                          IP_ARGS(ipv4_spec->hdr.src_addr),
                          IP_ARGS(ipv4_spec->hdr.dst_addr));
            ds_put_format(s1,
                          "tos spec 0x%"PRIx8" ttl spec 0x%"PRIx8" "
                          "proto spec 0x%"PRIx8" "
                          "src spec "IP_FMT" dst spec "IP_FMT" ",
                          ipv4_spec->hdr.type_of_service,
                          ipv4_spec->hdr.time_to_live,
                          ipv4_spec->hdr.next_proto_id,
                          IP_ARGS(ipv4_spec->hdr.src_addr),
                          IP_ARGS(ipv4_spec->hdr.dst_addr));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (ipv4_mask) {
            ds_put_format(s,
                          "  Mask: tos=0x%"PRIx8", ttl=%"PRIx8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_mask->hdr.type_of_service,
                          ipv4_mask->hdr.time_to_live,
                          ipv4_mask->hdr.next_proto_id,
                          IP_ARGS(ipv4_mask->hdr.src_addr),
                          IP_ARGS(ipv4_mask->hdr.dst_addr));
            ds_put_format(s1,
                          "tos mask 0x%"PRIx8" ttl mask 0x%"PRIx8" "
                          "proto mask 0x%"PRIx8" "
                          "src mask "IP_FMT" dst mask "IP_FMT" ",
                          ipv4_mask->hdr.type_of_service,
                          ipv4_mask->hdr.time_to_live,
                          ipv4_mask->hdr.next_proto_id,
                          IP_ARGS(ipv4_mask->hdr.src_addr),
                          IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(s, "rte flow udp pattern:\n");
        ds_put_cstr(s1, "udp ");
        if (udp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(udp_spec->hdr.src_port),
                          ntohs(udp_spec->hdr.dst_port));
            ds_put_format(s1,
                          "src spec %"PRIu16" dst spec %"PRIu16" ",
                          ntohs(udp_spec->hdr.src_port),
                          ntohs(udp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (udp_mask) {
            ds_put_format(s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(udp_mask->hdr.src_port),
                          ntohs(udp_mask->hdr.dst_port));
            ds_put_format(s1,
                          "src mask %"PRIu16" dst mask %"PRIu16" ",
                          ntohs(udp_mask->hdr.src_port),
                          ntohs(udp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        ds_put_cstr(s, "rte flow sctp pattern:\n");
        if (sctp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                          ntohs(sctp_spec->hdr.src_port),
                          ntohs(sctp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (sctp_mask) {
            ds_put_format(s,
                          "  Mask: src_port=0x%"PRIx16
                          ", dst_port=0x%"PRIx16"\n",
                          ntohs(sctp_mask->hdr.src_port),
                          ntohs(sctp_mask->hdr.dst_port));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        ds_put_cstr(s, "rte flow icmp pattern:\n");
        if (icmp_spec) {
            ds_put_format(s,
                          "  Spec: icmp_type=%"PRIu8", icmp_code=%"PRIu8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (icmp_mask) {
            ds_put_format(s,
                          "  Mask: icmp_type=0x%"PRIx8
                          ", icmp_code=0x%"PRIx8"\n",
                          icmp_spec->hdr.icmp_type,
                          icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        ds_put_cstr(s, "rte flow tcp pattern:\n");
        ds_put_cstr(s1, "tcp ");
        if (tcp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_spec->hdr.src_port),
                          ntohs(tcp_spec->hdr.dst_port),
                          tcp_spec->hdr.data_off,
                          tcp_spec->hdr.tcp_flags);
            ds_put_format(s1,
                          "src spec %"PRIu16" dst spec %"PRIu16" "
                          "flags spec 0x%"PRIx8" ",
                          ntohs(tcp_spec->hdr.src_port),
                          ntohs(tcp_spec->hdr.dst_port),
                          tcp_spec->hdr.tcp_flags);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (tcp_mask) {
            ds_put_format(s,
                          "  Mask: src_port=%"PRIx16", dst_port=%"PRIx16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_mask->hdr.src_port),
                          ntohs(tcp_mask->hdr.dst_port),
                          tcp_mask->hdr.data_off,
                          tcp_mask->hdr.tcp_flags);
            ds_put_format(s1,
                          "src mask %"PRIu16" dst mask %"PRIu16" "
                          "flags mask 0x%"PRIx8" ",
                          ntohs(tcp_mask->hdr.src_port),
                          ntohs(tcp_mask->hdr.dst_port),
                          tcp_mask->hdr.tcp_flags);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV6) {
        const struct rte_flow_item_ipv6 *ipv6_spec = item->spec;
        const struct rte_flow_item_ipv6 *ipv6_mask = item->mask;

        char src_addr_str[INET6_ADDRSTRLEN];
        char dst_addr_str[INET6_ADDRSTRLEN];

        ds_put_cstr(s, "rte flow ipv6 pattern:\n");
        ds_put_cstr(s1, "ipv6 ");
        if (ipv6_spec) {
            ipv6_string_mapped(src_addr_str,
                               (struct in6_addr *)&ipv6_spec->hdr.src_addr);
            ipv6_string_mapped(dst_addr_str,
                               (struct in6_addr *)&ipv6_spec->hdr.dst_addr);

            ds_put_format(s, "  Spec:  vtc_flow=%#"PRIx32",  proto=%"PRIu8","
                          "  hlim=%"PRIu8",  src=%s,  dst=%s\n",
                          ntohl(ipv6_spec->hdr.vtc_flow), ipv6_spec->hdr.proto,
                          ipv6_spec->hdr.hop_limits, src_addr_str,
                          dst_addr_str);
            ds_put_format(s1, "tc spec 0x%#"PRIx32" proto spec 0x%"PRIu8" "
                          "hop spec 0x%"PRIu8" src spec %s dst spec %s ",
                          ntohl(ipv6_spec->hdr.vtc_flow), ipv6_spec->hdr.proto,
                          ipv6_spec->hdr.hop_limits, src_addr_str,
                          dst_addr_str);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (ipv6_mask) {
            ipv6_string_mapped(src_addr_str,
                               (struct in6_addr *)&ipv6_mask->hdr.src_addr);
            ipv6_string_mapped(dst_addr_str,
                               (struct in6_addr *)&ipv6_mask->hdr.dst_addr);

            ds_put_format(s, "  Mask:  vtc_flow=%#"PRIx32",  proto=%#"PRIx8","
                          "  hlim=%#"PRIx8",  src=%s,  dst=%s\n",
                          ntohl(ipv6_mask->hdr.vtc_flow), ipv6_mask->hdr.proto,
                          ipv6_mask->hdr.hop_limits, src_addr_str,
                          dst_addr_str);
            ds_put_format(s1, "tc mask 0x%#"PRIx32" proto mask 0x%"PRIu8" "
                          "hop mask 0x%"PRIu8" src mask %s dst mask %s ",
                          ntohl(ipv6_mask->hdr.vtc_flow), ipv6_mask->hdr.proto,
                          ipv6_mask->hdr.hop_limits, src_addr_str,
                          dst_addr_str);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_VXLAN) {
        const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
        const struct rte_flow_item_vxlan *vxlan_mask = item->mask;

        ds_put_cstr(s, "rte flow vxlan pattern:\n");
        ds_put_cstr(s, "vxlan ");
        if (vxlan_spec) {
            ds_put_format(s, "  Spec: flags=0x%x, vni=%d\n",
                          vxlan_spec->flags,
                          ntohl(*(ovs_be32 *)vxlan_spec->vni) >> 8);
            ds_put_format(s1, "vni spec %d ",
                          ntohl(*(ovs_be32 *)vxlan_spec->vni) >> 8);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (vxlan_mask) {
            ds_put_format(s, "  Mask: flags=0x%x, vni=0x%06x\n",
                          vxlan_mask->flags,
                          ntohl(*(ovs_be32 *)vxlan_mask->vni) >> 8);
            ds_put_format(s1, "vni mask 0x%06x ",
                          ntohl(*(ovs_be32 *)vxlan_mask->vni) >> 8);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_TAG) {
        const struct rte_flow_item_tag *tag_spec = item->spec;
        const struct rte_flow_item_tag *tag_mask = item->mask;

        ds_put_cstr(s, "rte flow tag pattern:\n");
        ds_put_cstr(s1, "tag ");
        if (tag_spec) {
            ds_put_format(s, "  Spec: index=%u, data=0x%08x\n",
                          tag_spec->index, tag_spec->data);
            ds_put_format(s1, "index is %u data spec 0x%08x ",
                          tag_spec->index, tag_spec->data);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (tag_mask) {
            ds_put_format(s, "  Mask: index=%u, data=0x%08x\n",
                          tag_mask->index, tag_mask->data);
            ds_put_format(s1, "data mask 0x%08x ",tag_mask->data);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_META) {
        const struct rte_flow_item_meta *meta_spec = item->spec;
        const struct rte_flow_item_meta *meta_mask = item->mask;

        ds_put_cstr(s, "rte flow meta pattern:\n");
        ds_put_cstr(s1, "meta ");
        if (meta_spec) {
            ds_put_format(s, "  Spec: data=%08x\n", meta_spec->data);
            ds_put_format(s1, "data spec %08x ", meta_spec->data);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (meta_mask) {
            ds_put_format(s, "  Mask: data=%08x\n", meta_mask->data);
            ds_put_format(s1, "data mask %08x ", meta_mask->data);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_MARK) {
        const struct rte_flow_item_mark *mark_spec = item->spec;
        const struct rte_flow_item_mark *mark_mask = item->mask;

        ds_put_cstr(s, "rte flow mark pattern:\n");
        ds_put_cstr(s1, "mark ");
        if (mark_spec) {
            ds_put_format(s, "  Spec: id=%d\n", mark_spec->id);
            ds_put_format(s1, "id spec %d ", mark_spec->id);
        } else {
            ds_put_cstr(s, "  Spec = null\n");
        }
        if (mark_mask) {
            ds_put_format(s, "  Mask: id=%d\n", mark_mask->id);
            ds_put_format(s1, "id mask %d ", mark_mask->id);
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else {
        ds_put_format(s, "unknown rte flow pattern (%d)\n", item->type);
    }

    if (!_s1) {
        ds_destroy(s1);
    }
}

static void
dump_flow_action(struct ds *s, struct ds *s1,
                 const struct rte_flow_action *actions)
{
    if (actions->type == RTE_FLOW_ACTION_TYPE_MARK) {
        const struct rte_flow_action_mark *mark = actions->conf;

        ds_put_cstr(s, "rte flow mark action:\n");
        ds_put_cstr(s1, "mark ");
        if (mark) {
            ds_put_format(s, "  Mark: id=%d\n", mark->id);
            ds_put_format(s1, "id %d ", mark->id);
        } else {
            ds_put_cstr(s, "  Mark = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RSS) {
        const struct rte_flow_action_rss *rss = actions->conf;

        ds_put_cstr(s, "rte flow RSS action:\n");
        if (rss) {
            ds_put_format(s, "  RSS: queue_num=%d\n", rss->queue_num);
        } else {
            ds_put_cstr(s, "  RSS = null\n");
        }
        ds_put_cstr(s1, "rss / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_COUNT) {
        const struct rte_flow_action_count *count = actions->conf;

        ds_put_cstr(s, "rte flow count action:\n");
        if (count) {
            ds_put_format(s, "  Count: shared=%d, id=%d\n", count->shared,
                          count->id);
        } else {
            ds_put_cstr(s, "  Count = null\n");
        }
        ds_put_cstr(s1, "count / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
        const struct rte_flow_action_port_id *port_id = actions->conf;

        ds_put_cstr(s, "rte flow port-id action:\n");
        ds_put_cstr(s1, "port_id ");
        if (port_id) {
            ds_put_format(s, "  Port-id: original=%d, id=%d\n",
                          port_id->original, port_id->id);
            ds_put_format(s1, "original %d id %d ",
                          port_id->original, port_id->id);
        } else {
            ds_put_cstr(s, "  Port-id = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_DROP) {
        ds_put_cstr(s, "rte flow drop action\n");
        ds_put_cstr(s1, "drop / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
        const struct rte_flow_action_set_mac *set_mac = actions->conf;

        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST
                       ? "dst" : "src";

        ds_put_format(s, "rte flow set-mac-%s action:\n", dirstr);
        if (set_mac) {
            ds_put_format(s,
                          "  Set-mac-%s: "ETH_ADDR_FMT"\n", dirstr,
                          ETH_ADDR_BYTES_ARGS(set_mac->mac_addr));
        } else {
            ds_put_format(s, "  Set-mac-%s = null\n", dirstr);
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST) {
        const struct rte_flow_action_set_ipv4 *set_ipv4 = actions->conf;
        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST
                       ? "dst" : "src";

        ds_put_format(s, "rte flow set-ipv4-%s action:\n", dirstr);
        if (set_ipv4) {
            ds_put_format(s,
                          "  Set-ipv4-%s: "IP_FMT"\n", dirstr,
                          IP_ARGS(set_ipv4->ipv4_addr));
        } else {
            ds_put_format(s, "  Set-ipv4-%s = null\n", dirstr);
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TTL) {
        const struct rte_flow_action_set_ttl *set_ttl = actions->conf;

        ds_put_cstr(s, "rte flow set-ttl action:\n");
        if (set_ttl) {
            ds_put_format(s, "  Set-ttl: %d\n", set_ttl->ttl_value);
        } else {
            ds_put_cstr(s, "  Set-ttl = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST) {
        const struct rte_flow_action_set_tp *set_tp = actions->conf;
        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST
                       ? "dst" : "src";

        ds_put_format(s, "rte flow set-tcp/udp-port-%s action:\n", dirstr);
        if (set_tp) {
            ds_put_format(s, "  Set-%s-tcp/udp-port: %"PRIu16"\n", dirstr,
                          ntohs(set_tp->port));
        } else {
            ds_put_format(s, "  Set-%s-tcp/udp-port = null\n", dirstr);
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
        const struct rte_flow_action_raw_encap *raw_encap = actions->conf;

        ds_put_cstr(s, "rte flow raw-encap action:\n");
        if (raw_encap) {
            ds_put_format(s, "  Raw-encap: size=%ld\n", raw_encap->size);
            ds_put_format(s, "  Raw-encap: encap=\n");
            ds_put_hex_dump(s, raw_encap->data, raw_encap->size, 0, false);
        } else {
            ds_put_cstr(s, "  Raw-encap = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
        const struct rte_flow_action_vxlan_encap *vxlan_encap = actions->conf;
        const struct rte_flow_item *items = vxlan_encap->definition;

        ds_put_cstr(s, "rte flow vxlan-encap action:\n");
        ds_put_cstr(s, "vxlan_encap / ");
        while (items && items->type != RTE_FLOW_ITEM_TYPE_END) {
            dump_flow_pattern(s, NULL, items++);
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_JUMP) {
        const struct rte_flow_action_jump *jump = actions->conf;

        ds_put_cstr(s, "rte flow jump action\n");
        ds_put_cstr(s1, "jump ");
        if (jump) {
            ds_put_format(s, "  Jump: group=%"PRIu32"\n", jump->group);
            ds_put_format(s1, "group %"PRIu32" ", jump->group);
        }
        ds_put_cstr(s1, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) {
        ds_put_cstr(s, "rte flow vxlan-decap action\n");
        ds_put_cstr(s1, "vxlan_decap / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TAG) {
        const struct rte_flow_action_set_tag *set_tag = actions->conf;

        ds_put_cstr(s, "rte flow set-tag action:\n");
        ds_put_cstr(s1, "set_tag ");
        if (set_tag) {
            ds_put_format(s, "  Set-tag: index=%u, data=0x%08x, mask=0x%08x\n",
                          set_tag->index, set_tag->data, set_tag->mask);
            ds_put_format(s1, "index %u data 0x%08x mask 0x%08x ",
                          set_tag->index, set_tag->data, set_tag->mask);
        } else {
            ds_put_cstr(s, "  Set-tag = null\n");
        }
        ds_put_cstr(s1, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_META) {
            const struct rte_flow_action_set_meta *meta = actions->conf;

            ds_put_cstr(s, "rte flow meta action:\n");
            ds_put_cstr(s1, "set_meta ");
            if (meta) {
                ds_put_format(s, "  meta: data=0x%08x mask=0x%08x\n",
                              meta->data, meta->mask);
                ds_put_format(s1, "data 0x%08x mask 0x%08x ",
                              meta->data, meta->mask);
            } else {
                ds_put_cstr(s, "  meta = null\n");
            }
            ds_put_cstr(s1, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST) {
        const struct rte_flow_action_set_ipv6 *set_ipv6 = actions->conf;

        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST
                       ? "dst" : "src";

        ds_put_format(s, "rte flow set-ipv6-%s action:\n", dirstr);
        if (set_ipv6) {
            char addr_str[INET6_ADDRSTRLEN];

            ipv6_string_mapped(addr_str,
                               (struct in6_addr *)&set_ipv6->ipv6_addr);
            ds_put_format(s, "  Set-ipv6-%s: %s\n", dirstr, addr_str);
        } else {
            ds_put_format(s, "  Set-ipv6-%s = null\n", dirstr);
        }
    } else {
        ds_put_format(s, "unknown rte flow action (%d)\n", actions->type);
    }
}

static struct ds *
dump_flow(struct ds *s, struct ds *s1,
          const struct rte_flow_attr *attr,
          const struct rte_flow_item *items,
          const struct rte_flow_action *actions)
{
    if (attr) {
        dump_flow_attr(s, s1, attr);
    }
    ds_put_cstr(s1, "pattern ");
    while (items && items->type != RTE_FLOW_ITEM_TYPE_END) {
        dump_flow_pattern(s, s1, items++);
    }
    ds_put_cstr(s1, "end actions ");
    while (actions && actions->type != RTE_FLOW_ACTION_TYPE_END) {
        dump_flow_action(s, s1, actions++);
    }
    ds_put_cstr(s1, "end");
    return s;
}

enum ct_mode {
    CT_MODE_NONE,
    CT_MODE_CT,
    CT_MODE_CT_NAT,
    CT_MODE_CT_CONN,
};

struct act_vars {
    enum ct_mode ct_mode;
    bool pre_ct_tuple_rewrite;
    odp_port_t vport;
    uint32_t recirc_id;
    struct flow_tnl *tnl_key;
    struct flow_tnl tnl_mask;
};

static int
create_rte_flow(struct netdev *netdev,
                const struct rte_flow_attr *attr,
                const struct rte_flow_item *items,
                const struct rte_flow_action *actions,
                struct rte_flow_error *error,
                struct flow_item *fi,
                int pos)
{
    struct ds s, s1;

    fi->rte_flow[pos] = netdev_dpdk_rte_flow_create(netdev, attr, items,
                                                    actions, error);
    if (fi->rte_flow[pos]) {
        if (!VLOG_DROP_DBG(&rl)) {
            ds_init(&s);
            ds_init(&s1);
            ds_put_format(&s1, "flow create %d ",
                          netdev_dpdk_get_port_id(netdev));
            dump_flow(&s, &s1, attr, items, actions);
            VLOG_DBG_RL(&rl, "%s: rte_flow 0x%"PRIxPTR" created:\n%s",
                        netdev_get_name(netdev), (intptr_t) fi->rte_flow[pos],
                        ds_cstr(&s));
            VLOG_DBG_RL(&rl, "%s: testpmd rte_flow 0x%"PRIxPTR" %s",
                        netdev_get_name(netdev), (intptr_t) fi->rte_flow[pos],
                        ds_cstr(&s1));
            ds_destroy(&s1);
            ds_destroy(&s);
        }
    } else {
        enum vlog_level level = VLL_WARN;

        if (error->type == RTE_FLOW_ERROR_TYPE_ACTION) {
            level = VLL_DBG;
        }
        VLOG_RL(&rl, level, "%s: rte_flow creation failed: %d (%s).",
                netdev_get_name(netdev), error->type, error->message);
        if (!vlog_should_drop(&this_module, level, &rl)) {
            ds_init(&s);
            ds_init(&s1);
            dump_flow(&s, &s1, attr, items, actions);
            VLOG_RL(&rl, level, "Failed flow:\n%s", ds_cstr(&s));
            ds_destroy(&s1);
            ds_destroy(&s);
        }
    }
    return fi->rte_flow[pos] ? 0 : -1;
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask)
{
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof *patterns->items);
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof *patterns->items);
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = NULL;
    patterns->cnt++;
}

static void
add_flow_action(struct flow_actions *actions, enum rte_flow_action_type type,
                const void *conf)
{
    int cnt = actions->cnt;

    if (cnt == 0) {
        actions->current_max = 8;
        actions->actions = xcalloc(actions->current_max,
                                   sizeof *actions->actions);
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof *actions->actions);
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
}

static void
free_flow_patterns(struct flow_patterns *patterns)
{
    int i;

    for (i = 0; i < patterns->cnt; i++) {
        if (patterns->items[i].spec) {
            free(CONST_CAST(void *, patterns->items[i].spec));
        }
        if (patterns->items[i].mask) {
            free(CONST_CAST(void *, patterns->items[i].mask));
        }
    }
    free(patterns->items);
    patterns->items = NULL;
    patterns->cnt = 0;
}

static void
free_flow_actions(struct flow_actions *actions, bool free_confs)
{
    int i;

    for (i = 0; free_confs && i < actions->cnt; i++) {
        if (actions->actions[i].conf) {
            free(CONST_CAST(void *, actions->actions[i].conf));
        }
    }
    free(actions->actions);
    actions->actions = NULL;
    actions->cnt = 0;
}

static int
netdev_offload_dpdk_destroy_flow(struct netdev *netdev,
                                 struct rte_flow *rte_flow,
                                 const ovs_u128 *ufid)
{
    struct uuid ufid0 = UUID_ZERO;
    struct rte_flow_error error;
    int ret;

    ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);
    if (!ret) {
        VLOG_DBG("%s: removed rte flow %p associated with ufid "
                 UUID_FMT "\n", netdev_get_name(netdev), rte_flow,
                 UUID_ARGS(ufid ? (struct uuid *)ufid : &ufid0));
        VLOG_DBG_RL(&rl, "%s: testpmd rte_flow %p flow destroy %d rule ",
                    netdev_get_name(netdev), rte_flow,
                    netdev_dpdk_get_port_id(netdev));
    } else {
        VLOG_ERR("%s: Failed to destroy flow: %s (%u)\n",
                 netdev_get_name(netdev), error.message,
                 error.type);
        return -1;
    }

    return ret;
}

static int
parse_tnl_ip_match(struct flow_patterns *patterns,
                   struct match *match,
                   uint8_t proto)
{
    struct flow *consumed_masks;

    consumed_masks = &match->wc.masks;
    /* IP v4 */
    if (match->wc.masks.tunnel.ip_src || match->wc.masks.tunnel.ip_dst) {
        struct rte_flow_item_ipv4 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.type_of_service = match->flow.tunnel.ip_tos;
        spec->hdr.time_to_live    = match->flow.tunnel.ip_ttl;
        spec->hdr.next_proto_id   = proto;
        spec->hdr.src_addr        = match->flow.tunnel.ip_src;
        spec->hdr.dst_addr        = match->flow.tunnel.ip_dst;

        mask->hdr.type_of_service = match->wc.masks.tunnel.ip_tos;
        mask->hdr.time_to_live    = match->wc.masks.tunnel.ip_ttl;
        mask->hdr.next_proto_id   = UINT8_MAX;
        mask->hdr.src_addr        = match->wc.masks.tunnel.ip_src;
        mask->hdr.dst_addr        = match->wc.masks.tunnel.ip_dst;

        consumed_masks->tunnel.ip_tos = 0;
        consumed_masks->tunnel.ip_ttl = 0;
        consumed_masks->tunnel.ip_src = 0;
        consumed_masks->tunnel.ip_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask);
    } else if (!is_all_zeros(&match->wc.masks.tunnel.ipv6_src,
                             sizeof(struct in6_addr)) ||
               !is_all_zeros(&match->wc.masks.tunnel.ipv6_dst,
                             sizeof(struct in6_addr))) {
        /* IP v6 */
        struct rte_flow_item_ipv6 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.proto = proto;
        spec->hdr.hop_limits = match->flow.tunnel.ip_ttl;
        spec->hdr.vtc_flow = htonl((uint32_t)match->flow.tunnel.ip_tos <<
                                   RTE_IPV6_HDR_TC_SHIFT);
        memcpy(spec->hdr.src_addr, &match->flow.tunnel.ipv6_src,
               sizeof spec->hdr.src_addr);
        memcpy(spec->hdr.dst_addr, &match->flow.tunnel.ipv6_dst,
               sizeof spec->hdr.dst_addr);

        mask->hdr.proto = UINT8_MAX;
        mask->hdr.hop_limits = match->wc.masks.tunnel.ip_ttl;
        mask->hdr.vtc_flow = htonl((uint32_t)match->wc.masks.tunnel.ip_tos <<
                                   RTE_IPV6_HDR_TC_SHIFT);
        memcpy(mask->hdr.src_addr, &match->wc.masks.tunnel.ipv6_src,
               sizeof mask->hdr.src_addr);
        memcpy(mask->hdr.dst_addr, &match->wc.masks.tunnel.ipv6_dst,
               sizeof mask->hdr.dst_addr);

        consumed_masks->tunnel.ip_tos = 0;
        consumed_masks->tunnel.ip_ttl = 0;
        memset(&consumed_masks->tunnel.ipv6_src, 0,
               sizeof consumed_masks->tunnel.ipv6_src);
        memset(&consumed_masks->tunnel.ipv6_dst, 0,
               sizeof consumed_masks->tunnel.ipv6_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6, spec, mask);
    } else {
        VLOG_ERR_RL(&rl, "Tunnel L3 protocol is neither IPv4 nor IPv6");
        return -1;
    }

    return 0;
}

static void
parse_tnl_udp_match(struct flow_patterns *patterns,
                    struct match *match)
{
    struct flow *consumed_masks;
    struct rte_flow_item_udp *spec, *mask;

    consumed_masks = &match->wc.masks;

    spec = xzalloc(sizeof *spec);
    mask = xzalloc(sizeof *mask);

    spec->hdr.src_port = match->flow.tunnel.tp_src;
    spec->hdr.dst_port = match->flow.tunnel.tp_dst;

    mask->hdr.src_port = match->wc.masks.tunnel.tp_src;
    mask->hdr.dst_port = match->wc.masks.tunnel.tp_dst;

    consumed_masks->tunnel.tp_src = 0;
    consumed_masks->tunnel.tp_dst = 0;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask);
}

static int
parse_vxlan_match(struct flow_patterns *patterns,
                  struct match *match)
{
    struct rte_flow_item_vxlan *vx_spec, *vx_mask;
    struct flow *consumed_masks;
    int ret;

    if (is_all_zeros(&match->wc.masks.tunnel, sizeof match->wc.masks.tunnel)) {
        return 0;
    }

    ret = parse_tnl_ip_match(patterns, match, IPPROTO_UDP);
    if (ret) {
        return -1;
    }
    parse_tnl_udp_match(patterns, match);

    consumed_masks = &match->wc.masks;
    /* VXLAN */
    vx_spec = xzalloc(sizeof *vx_spec);
    vx_mask = xzalloc(sizeof *vx_mask);

    put_unaligned_be32((ovs_be32 *)vx_spec->vni,
                       htonl(ntohll(match->flow.tunnel.tun_id) << 8));
    put_unaligned_be32((ovs_be32 *)vx_mask->vni,
                       htonl(ntohll(match->wc.masks.tunnel.tun_id) << 8));

    consumed_masks->tunnel.tun_id = 0;
    consumed_masks->tunnel.flags = 0;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VXLAN, vx_spec, vx_mask);
    return 0;
}

OVS_UNUSED
static int
get_packet_reg_field(struct dp_packet *packet, uint8_t reg_field_id,
                     uint32_t *val)
{
    struct reg_field *reg_field;
    uint32_t meta;

    if (reg_field_id >= REG_FIELD_NUM) {
        VLOG_ERR("unkonwn reg id %d", reg_field_id);
        return -1;
    }
    reg_field = &reg_fields[reg_field_id];
    if (reg_field->type != REG_TYPE_META) {
        VLOG_ERR("reg id %d is not meta", reg_field_id);
        return -1;
    }
    if (!dp_packet_get_meta(packet, &meta)) {
        return -1;
    }

    meta >>= reg_field->offset;
    meta &= reg_field->mask;

    if (meta == 0) {
        VLOG_ERR_RL(&rl, "packet reg field id %d is 0", reg_field_id);
        return -1;
    }

    *val = meta;
    return 0;
}

static int
add_pattern_match_reg_field(struct flow_patterns *patterns,
                            uint8_t reg_field_id, uint32_t val, uint32_t mask)
{
    struct rte_flow_item_meta *meta_spec, *meta_mask;
    struct rte_flow_item_tag *tag_spec, *tag_mask;
    struct reg_field *reg_field;
    uint32_t reg_spec, reg_mask;

    if (reg_field_id >= REG_FIELD_NUM) {
        VLOG_ERR("unkonwn reg id %d", reg_field_id);
        return -1;
    }
    reg_field = &reg_fields[reg_field_id];
    if (val != (val & reg_field->mask)) {
        VLOG_ERR("value 0x%"PRIx32" is out of range for reg id %d", val,
                 reg_field_id);
        return -1;
    }

    reg_spec = (val & reg_field->mask) << reg_field->offset;
    reg_mask = (mask & reg_field->mask) << reg_field->offset;
    switch (reg_field->type) {
    case REG_TYPE_TAG:
        tag_spec = xzalloc(sizeof *tag_spec);
        tag_spec->index = reg_field->index;
        tag_spec->data = reg_spec;

        tag_mask = xzalloc(sizeof *tag_mask);
        tag_mask->index = 0xFF;
        tag_mask->data = reg_mask;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TAG, tag_spec, tag_mask);
        break;
    case REG_TYPE_META:
        meta_spec = xzalloc(sizeof *meta_spec);
        meta_spec->data = reg_spec;

        meta_mask = xzalloc(sizeof *meta_mask);
        meta_mask->data = reg_mask;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_META, meta_spec,
                         meta_mask);
        break;
    default:
        VLOG_ERR("unkonwn reg type (%d) for reg field %d", reg_field->type,
                 reg_field_id);
        return -1;
    }

    return 0;
}

static int
add_action_set_reg_field(struct flow_actions *actions,
                         uint8_t reg_field_id, uint32_t val, uint32_t mask)
{
    struct rte_flow_action_set_meta *set_meta;
    struct rte_flow_action_set_tag *set_tag;
    struct reg_field *reg_field;
    uint32_t reg_spec, reg_mask;

    if (reg_field_id >= REG_FIELD_NUM) {
        VLOG_ERR("unkonwn reg id %d", reg_field_id);
        return -1;
    }
    reg_field = &reg_fields[reg_field_id];
    if (val != (val & reg_field->mask)) {
        VLOG_ERR_RL(&rl, "value 0x%"PRIx32" is out of range for reg id %d",
                          val, reg_field_id);
        return -1;
    }

    reg_spec = (val & reg_field->mask) << reg_field->offset;
    reg_mask = (mask & reg_field->mask) << reg_field->offset;
    switch (reg_field->type) {
    case REG_TYPE_TAG:
        set_tag = xzalloc(sizeof *set_tag);
        set_tag->index = reg_field->index;
        set_tag->data = reg_spec;
        set_tag->mask = reg_mask;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_TAG, set_tag);
        break;
    case REG_TYPE_META:
        set_meta = xzalloc(sizeof *set_meta);
        set_meta->data = reg_spec;
        set_meta->mask = reg_mask;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_META, set_meta);
        break;
    default:
        VLOG_ERR("unkonwn reg type (%d) for reg field %d", reg_field->type,
                 reg_field_id);
        return -1;
    }

    return 0;
}

static int
parse_tnl_match_recirc(struct flow_patterns *patterns,
                       struct match *match,
                       struct act_resources *act_resources)
{
    if (get_tnl_id(&match->flow.tunnel, &match->wc.masks.tunnel,
                   &act_resources->tnl_id)) {
        return -1;
    }
    if (add_pattern_match_reg_field(patterns, REG_FIELD_TUN_INFO,
                                    act_resources->tnl_id, 0xFFFFFFFF)) {
        return -1;
    }
    memset(&match->wc.masks.tunnel, 0, sizeof match->wc.masks.tunnel);
    return 0;
}

static int
parse_flow_match(struct netdev *netdev,
                 struct flow_patterns *patterns,
                 struct match *match,
                 struct act_resources *act_resources,
                 struct act_vars *act_vars)
{
    uint8_t *next_proto_mask = NULL;
    struct flow *consumed_masks;
    uint8_t proto = 0;
    int ret = 0;

    consumed_masks = &match->wc.masks;

    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        act_vars->vport = match->flow.in_port.odp_port;
        act_vars->tnl_key = &match->flow.tunnel;
        act_vars->tnl_mask = match->wc.masks.tunnel;
        if (match->flow.recirc_id &&
            parse_tnl_match_recirc(patterns, match, act_resources)) {
            ret = -1;
            goto out;
        }
    }

    if (!strcmp(netdev_get_type(netdev), "vxlan") &&
        parse_vxlan_match(patterns, match)) {
        ret = -1;
        goto out;
    }

    ret = get_table_id(act_vars->vport, match->flow.recirc_id, TABLE_TYPE_FLOW,
                       &act_resources->self_table_id);
    if (ret) {
        goto out;
    }
    act_vars->recirc_id = match->flow.recirc_id;

    memset(&consumed_masks->in_port, 0, sizeof consumed_masks->in_port);
    consumed_masks->recirc_id = 0;
    consumed_masks->packet_type = 0;

    /* Eth */
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        struct rte_flow_item_eth *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        memcpy(&spec->dst, &match->flow.dl_dst, sizeof spec->dst);
        memcpy(&spec->src, &match->flow.dl_src, sizeof spec->src);
        spec->type = match->flow.dl_type;

        memcpy(&mask->dst, &match->wc.masks.dl_dst, sizeof mask->dst);
        memcpy(&mask->src, &match->wc.masks.dl_src, sizeof mask->src);
        mask->type = match->wc.masks.dl_type;

        memset(&consumed_masks->dl_dst, 0, sizeof consumed_masks->dl_dst);
        memset(&consumed_masks->dl_src, 0, sizeof consumed_masks->dl_src);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, spec, mask);
    } else {
        /*
         * If user specifies a flow (like UDP flow) without L2 patterns,
         * OVS will at least set the dl_type. Normally, it's enough to
         * create an eth pattern just with it. Unluckily, some Intel's
         * NIC (such as XL710) doesn't support that. Below is a workaround,
         * which simply matches any L2 pkts.
         */
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
    }
    consumed_masks->dl_type = 0;

    /* VLAN */
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        struct rte_flow_item_vlan *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->tci = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask->tci = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* Match any protocols. */
        mask->inner_type = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VLAN, spec, mask);
    }
    memset(&consumed_masks->vlans[0], 0, sizeof consumed_masks->vlans[0]);

    /* IP v4 */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        struct rte_flow_item_ipv4 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.type_of_service = match->flow.nw_tos;
        spec->hdr.time_to_live    = match->flow.nw_ttl;
        spec->hdr.next_proto_id   = match->flow.nw_proto;
        spec->hdr.src_addr        = match->flow.nw_src;
        spec->hdr.dst_addr        = match->flow.nw_dst;

        mask->hdr.type_of_service = match->wc.masks.nw_tos;
        mask->hdr.time_to_live    = match->wc.masks.nw_ttl;
        mask->hdr.next_proto_id   = match->wc.masks.nw_proto;
        mask->hdr.src_addr        = match->wc.masks.nw_src;
        mask->hdr.dst_addr        = match->wc.masks.nw_dst;

        consumed_masks->nw_tos = 0;
        consumed_masks->nw_ttl = 0;
        consumed_masks->nw_proto = 0;
        consumed_masks->nw_src = 0;
        consumed_masks->nw_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask);

        /* Save proto for L4 protocol setup. */
        proto = spec->hdr.next_proto_id &
                mask->hdr.next_proto_id;
        next_proto_mask = &mask->hdr.next_proto_id;
    }
    /* do not attempt to offload frags. */
    if (match->flow.nw_frag != OVS_FRAG_TYPE_NONE && match->wc.masks.nw_frag) {
        VLOG_DBG_RL(&rl, "Frag (%d/%d) not supported", match->flow.nw_frag,
                    match->wc.masks.nw_frag);
        ret = -1;
        goto out;
    }
    consumed_masks->nw_frag = 0;

    /* IP v6 */
    if (match->flow.dl_type == htons(ETH_TYPE_IPV6)) {
        struct rte_flow_item_ipv6 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.proto = match->flow.nw_proto;
        spec->hdr.hop_limits = match->flow.nw_ttl;
        spec->hdr.vtc_flow = htonl((uint32_t)match->flow.nw_tos <<
                                   RTE_IPV6_HDR_TC_SHIFT);
        memcpy(spec->hdr.src_addr, &match->flow.ipv6_src,
               sizeof spec->hdr.src_addr);
        memcpy(spec->hdr.dst_addr, &match->flow.ipv6_dst,
               sizeof spec->hdr.dst_addr);

        mask->hdr.proto = match->wc.masks.nw_proto;
        mask->hdr.hop_limits = match->wc.masks.nw_ttl;
        mask->hdr.vtc_flow = htonl((uint32_t)match->wc.masks.nw_tos <<
                                   RTE_IPV6_HDR_TC_SHIFT);
        memcpy(mask->hdr.src_addr, &match->wc.masks.ipv6_src,
               sizeof mask->hdr.src_addr);
        memcpy(mask->hdr.dst_addr, &match->wc.masks.ipv6_dst,
               sizeof mask->hdr.dst_addr);

        consumed_masks->nw_proto = 0;
        consumed_masks->nw_ttl = 0;
        consumed_masks->nw_tos = 0;
        memset(&consumed_masks->ipv6_src, 0, sizeof consumed_masks->ipv6_src);
        memset(&consumed_masks->ipv6_dst, 0, sizeof consumed_masks->ipv6_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6, spec, mask);

        /* Save proto for L4 protocol setup */
        proto = spec->hdr.proto & mask->hdr.proto;
        next_proto_mask = &mask->hdr.proto;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        ret = -1;
        goto out;
    }

    if ((match->wc.masks.tp_src && match->wc.masks.tp_src != OVS_BE16_MAX) ||
        (match->wc.masks.tp_dst && match->wc.masks.tp_dst != OVS_BE16_MAX)) {
        ret = -1;
        goto out;
    }

    if (proto == IPPROTO_TCP) {
        struct rte_flow_item_tcp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port  = match->flow.tp_src;
        spec->hdr.dst_port  = match->flow.tp_dst;
        spec->hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        spec->hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        mask->hdr.src_port  = match->wc.masks.tp_src;
        mask->hdr.dst_port  = match->wc.masks.tp_dst;
        mask->hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        mask->hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;
        consumed_masks->tcp_flags = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP, spec, mask);

        /* proto == TCP and ITEM_TYPE_TCP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    } else if (proto == IPPROTO_UDP) {
        struct rte_flow_item_udp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    } else if (proto == IPPROTO_SCTP) {
        struct rte_flow_item_sctp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_SCTP, spec, mask);

        /* proto == SCTP and ITEM_TYPE_SCTP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    } else if (proto == IPPROTO_ICMP) {
        struct rte_flow_item_icmp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec->hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask->hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask->hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ICMP, spec, mask);

        /* proto == ICMP and ITEM_TYPE_ICMP, thus no need for proto match. */
        if (next_proto_mask) {
            *next_proto_mask = 0;
        }
    }

    /* ct-state */
    if (match->wc.masks.ct_state &&
        !(match->wc.masks.ct_state & match->flow.ct_state & CS_NEW) &&
        !add_pattern_match_reg_field(patterns, REG_FIELD_CT_STATE,
                                     match->flow.ct_state,
                                     match->wc.masks.ct_state)) {
        consumed_masks->ct_state = 0;
    }
    /* ct-zone */
    if (match->wc.masks.ct_zone &&
        !add_pattern_match_reg_field(patterns, REG_FIELD_CT_ZONE,
                                     match->flow.ct_zone,
                                     match->wc.masks.ct_zone)) {
        consumed_masks->ct_zone = 0;
    }
    /* ct-mark */
    if (match->wc.masks.ct_mark &&
        !add_pattern_match_reg_field(patterns, REG_FIELD_CT_MARK,
                                     match->flow.ct_mark,
                                     match->wc.masks.ct_mark)) {
        consumed_masks->ct_mark = 0;
    }
    /* ct-label */
    if (match->wc.masks.ct_label.u32[0] &&
        !add_pattern_match_reg_field(patterns, REG_FIELD_CT_LABEL0,
                                     match->flow.ct_label.u32[0],
                                     match->wc.masks.ct_label.u32[0])) {
        consumed_masks->ct_label.u32[0] = 0;
    }
    if (match->wc.masks.ct_label.u32[1] &&
        !add_pattern_match_reg_field(patterns, REG_FIELD_CT_LABEL1,
                                     match->flow.ct_label.u32[1],
                                     match->wc.masks.ct_label.u32[1])) {
        consumed_masks->ct_label.u32[1] = 0;
    }
    if (match->wc.masks.ct_label.u32[2] &&
        !add_pattern_match_reg_field(patterns, REG_FIELD_CT_LABEL2,
                                     match->flow.ct_label.u32[2],
                                     match->wc.masks.ct_label.u32[2])) {
        consumed_masks->ct_label.u32[2] = 0;
    }
    if (match->wc.masks.ct_label.u32[3] &&
        !add_pattern_match_reg_field(patterns, REG_FIELD_CT_LABEL3,
                                     match->flow.ct_label.u32[3],
                                     match->wc.masks.ct_label.u32[3])) {
        consumed_masks->ct_label.u32[3] = 0;
    }

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    if (!is_all_zeros(consumed_masks, sizeof *consumed_masks)) {
        VLOG_DBG_RL(&rl,
                    "Cannot match all matches. dl_type=0x%04x",
                    ntohs(match->flow.dl_type));
        ret = -1;
    }
out:
    return ret;
}

static void
add_flow_mark_rss_actions(struct flow_actions *actions,
                          uint32_t flow_mark,
                          const struct netdev *netdev)
{
    struct rte_flow_action_mark *mark;
    struct action_rss_data {
        struct rte_flow_action_rss conf;
        uint16_t queue[0];
    } *rss_data;
    BUILD_ASSERT_DECL(offsetof(struct action_rss_data, conf) == 0);
    int i;

    mark = xzalloc(sizeof *mark);

    mark->id = flow_mark;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);

    rss_data = xmalloc(sizeof *rss_data +
                       netdev_n_rxq(netdev) * sizeof rss_data->queue[0]);
    *rss_data = (struct action_rss_data) {
        .conf = (struct rte_flow_action_rss) {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = 0,
            .queue_num = netdev_n_rxq(netdev),
            .queue = rss_data->queue,
            .key_len = 0,
            .key  = NULL
        },
    };

    /* Override queue array with default. */
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
       rss_data->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
}

static struct rte_flow *
netdev_offload_dpdk_mark_rss(struct flow_patterns *patterns,
                             struct netdev *netdev,
                             uint32_t flow_mark)
{
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct flow_item flow_item = { .devargs = NULL };
    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct rte_flow_error error;

    add_flow_mark_rss_actions(&actions, flow_mark, netdev);

    create_rte_flow(netdev, &flow_attr, patterns->items, actions.actions,
                    &error, &flow_item, 0);

    free_flow_actions(&actions, true);
    return flow_item.rte_flow[0];
}

static void
add_count_action(struct flow_actions *actions)
{
    struct rte_flow_action_count *count = xzalloc(sizeof *count);

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, count);
}

static int
add_port_id_action(struct flow_actions *actions,
                   struct netdev *outdev)
{
    struct rte_flow_action_port_id *port_id;
    int outdev_id;

    outdev_id = netdev_dpdk_get_port_id(outdev);
    if (outdev_id < 0) {
        return -1;
    }
    port_id = xzalloc(sizeof *port_id);
    port_id->id = outdev_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_PORT_ID, port_id);
    return 0;
}

static int
add_output_action(struct netdev *netdev,
                  struct flow_actions *actions,
                  const struct nlattr *nla)
{
    struct netdev *outdev;
    odp_port_t port;
    int ret = 0;

    port = nl_attr_get_odp_port(nla);
    outdev = netdev_ports_get(port, netdev->dpif_type);
    if (outdev == NULL) {
        VLOG_DBG_RL(&rl, "Cannot find netdev for odp port %"PRIu32, port);
        return -1;
    }
    if (!netdev_flow_api_equals(netdev, outdev) ||
        add_port_id_action(actions, outdev)) {
        VLOG_DBG_RL(&rl, "%s: Output to port \'%s\' cannot be offloaded.",
                    netdev_get_name(netdev), netdev_get_name(outdev));
        ret = -1;
    }
    netdev_close(outdev);
    return ret;
}

static int
add_set_flow_action__(struct flow_actions *actions,
                      const void *value, void *mask,
                      const size_t size, const int attr)
{
    void *spec;

    if (mask) {
        /* DPDK does not support partially masked set actions. In such
         * case, fail the offload.
         */
        if (is_all_zeros(mask, size)) {
            return 0;
        }
        if (!is_all_ones(mask, size)) {
            VLOG_DBG_RL(&rl, "Partial mask is not supported");
            return -1;
        }
    }

    spec = xzalloc(size);
    memcpy(spec, value, size);
    add_flow_action(actions, attr, spec);

    /* Clear used mask for later checking. */
    if (mask) {
        memset(mask, 0, size);
    }
    return 0;
}

BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_mac) ==
                  MEMBER_SIZEOF(struct ovs_key_ethernet, eth_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_mac) ==
                  MEMBER_SIZEOF(struct ovs_key_ethernet, eth_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv4) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv4) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ttl) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_ttl));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_tcp, tcp_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_tcp, tcp_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_udp, udp_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_udp, udp_dst));

static int
parse_set_actions(struct flow_actions *actions,
                  const struct nlattr *set_actions,
                  const size_t set_actions_len,
                  bool masked,
                  struct act_vars *act_vars)
{
    const struct nlattr *sa;
    unsigned int sleft;

#define add_set_flow_action(field, type)                                      \
    if (add_set_flow_action__(actions, &key->field,                           \
                              mask ? CONST_CAST(void *, &mask->field) : NULL, \
                              sizeof key->field, type)) {                     \
        return -1;                                                            \
    }

    NL_ATTR_FOR_EACH_UNSAFE (sa, sleft, set_actions, set_actions_len) {
        if (nl_attr_type(sa) == OVS_KEY_ATTR_ETHERNET) {
            const struct ovs_key_ethernet *key = nl_attr_get(sa);
            const struct ovs_key_ethernet *mask = masked ? key + 1 : NULL;

            add_set_flow_action(eth_src, RTE_FLOW_ACTION_TYPE_SET_MAC_SRC);
            add_set_flow_action(eth_dst, RTE_FLOW_ACTION_TYPE_SET_MAC_DST);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported ETHERNET set action");
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV4) {
            const struct ovs_key_ipv4 *key = nl_attr_get(sa);
            const struct ovs_key_ipv4 *mask = masked ? key + 1 : NULL;

            add_set_flow_action(ipv4_src, RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC);
            add_set_flow_action(ipv4_dst, RTE_FLOW_ACTION_TYPE_SET_IPV4_DST);
            add_set_flow_action(ipv4_ttl, RTE_FLOW_ACTION_TYPE_SET_TTL);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported IPv4 set action");
                return -1;
            }
            act_vars->pre_ct_tuple_rewrite = act_vars->ct_mode == CT_MODE_NONE;
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_TCP) {
            const struct ovs_key_tcp *key = nl_attr_get(sa);
            const struct ovs_key_tcp *mask = masked ? key + 1 : NULL;

            add_set_flow_action(tcp_src, RTE_FLOW_ACTION_TYPE_SET_TP_SRC);
            add_set_flow_action(tcp_dst, RTE_FLOW_ACTION_TYPE_SET_TP_DST);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported TCP set action");
                return -1;
            }
            act_vars->pre_ct_tuple_rewrite = act_vars->ct_mode == CT_MODE_NONE;
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_UDP) {
            const struct ovs_key_udp *key = nl_attr_get(sa);
            const struct ovs_key_udp *mask = masked ? key + 1 : NULL;

            add_set_flow_action(udp_src, RTE_FLOW_ACTION_TYPE_SET_TP_SRC);
            add_set_flow_action(udp_dst, RTE_FLOW_ACTION_TYPE_SET_TP_DST);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported UDP set action");
                return -1;
            }
            act_vars->pre_ct_tuple_rewrite = act_vars->ct_mode == CT_MODE_NONE;
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV6) {
            const struct ovs_key_ipv6 *key = nl_attr_get(sa);
            const struct ovs_key_ipv6 *mask = masked ? key + 1 : NULL;

            add_set_flow_action(ipv6_src, RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC);
            add_set_flow_action(ipv6_dst, RTE_FLOW_ACTION_TYPE_SET_IPV6_DST);
            add_set_flow_action(ipv6_hlimit, RTE_FLOW_ACTION_TYPE_SET_TTL);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported IPv6 set action");
                return -1;
            }
            act_vars->pre_ct_tuple_rewrite = act_vars->ct_mode == CT_MODE_NONE;
        } else {
            VLOG_DBG_RL(&rl,
                        "Unsupported set action type %d", nl_attr_type(sa));
            return -1;
        }
    }

    return 0;
}

/* Maximum number of items in struct rte_flow_action_vxlan_encap.
 * ETH / IPv4(6) / UDP / VXLAN / END
 */
#define ACTION_VXLAN_ENCAP_ITEMS_NUM 5

static int
add_vxlan_encap_action(struct flow_actions *actions,
                       const void *header)
{
    const struct eth_header *eth;
    const struct udp_header *udp;
    struct vxlan_data {
        struct rte_flow_action_vxlan_encap conf;
        struct rte_flow_item items[0];
    } *vxlan_data;
    BUILD_ASSERT_DECL(offsetof(struct vxlan_data, conf) == 0);
    const void *vxlan;
    const void *l3;
    const void *l4;
    int field;

    vxlan_data = xzalloc(sizeof *vxlan_data +
                         sizeof(struct rte_flow_item) *
                         ACTION_VXLAN_ENCAP_ITEMS_NUM);
    field = 0;

    eth = header;
    /* Ethernet */
    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_ETH;
    vxlan_data->items[field].spec = eth;
    vxlan_data->items[field].mask = &rte_flow_item_eth_mask;
    field++;

    l3 = eth + 1;
    /* IP */
    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* IPv4 */
        const struct ip_header *ip = l3;

        vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_IPV4;
        vxlan_data->items[field].spec = ip;
        vxlan_data->items[field].mask = &rte_flow_item_ipv4_mask;

        if (ip->ip_proto != IPPROTO_UDP) {
            goto err;
        }
        l4 = (ip + 1);
    } else if (eth->eth_type == htons(ETH_TYPE_IPV6)) {
        const struct ovs_16aligned_ip6_hdr *ip6 = l3;

        vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_IPV6;
        vxlan_data->items[field].spec = ip6;
        vxlan_data->items[field].mask = &rte_flow_item_ipv6_mask;

        if (ip6->ip6_nxt != IPPROTO_UDP) {
            goto err;
        }
        l4 = (ip6 + 1);
    } else {
        goto err;
    }
    field++;

    udp = (const struct udp_header *)l4;
    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_UDP;
    vxlan_data->items[field].spec = udp;
    vxlan_data->items[field].mask = &rte_flow_item_udp_mask;
    field++;

    vxlan = (udp + 1);
    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    vxlan_data->items[field].spec = vxlan;
    vxlan_data->items[field].mask = &rte_flow_item_vxlan_mask;
    field++;

    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_END;

    vxlan_data->conf.definition = vxlan_data->items;

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP, vxlan_data);

    return 0;
err:
    free(vxlan_data);
    return -1;
}

static int
parse_clone_actions(struct netdev *netdev,
                    struct flow_actions *actions,
                    const struct nlattr *clone_actions,
                    const size_t clone_actions_len)
{
    const struct nlattr *ca;
    unsigned int cleft;

    NL_ATTR_FOR_EACH_UNSAFE (ca, cleft, clone_actions, clone_actions_len) {
        int clone_type = nl_attr_type(ca);

        if (clone_type == OVS_ACTION_ATTR_TUNNEL_PUSH) {
            const struct ovs_action_push_tnl *tnl_push = nl_attr_get(ca);
            struct rte_flow_action_raw_encap *raw_encap;

            if (tnl_push->tnl_type == OVS_VPORT_TYPE_VXLAN &&
                !add_vxlan_encap_action(actions, tnl_push->header)) {
                continue;
            }

            raw_encap = xzalloc(sizeof *raw_encap);
            raw_encap->data = (uint8_t *)tnl_push->header;
            raw_encap->preserve = NULL;
            raw_encap->size = tnl_push->header_len;

            add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
                            raw_encap);
        } else if (clone_type == OVS_ACTION_ATTR_OUTPUT) {
            if (add_output_action(netdev, actions, ca)) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&rl,
                        "Unsupported nested action inside clone(), "
                        "action type: %d", clone_type);
            return -1;
        }
    }

    return 0;
}

static void
add_mark_action(struct flow_actions *actions,
                uint32_t mark_id)
{
    struct rte_flow_action_mark *mark = xzalloc(sizeof *mark);

    mark->id = mark_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);
}

static void
add_jump_action(struct flow_actions *actions, uint32_t group)
{
    struct rte_flow_action_jump *jump = xzalloc (sizeof *jump);

    jump->group = group;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump);
}

static int
add_tnl_pop_action(struct flow_actions *actions,
                   const struct nlattr *nla,
                   struct act_resources *act_resources)
{
    struct flow_miss_ctx miss_ctx;
    odp_port_t port;

    port = nl_attr_get_odp_port(nla);
    miss_ctx.vport = port;
    miss_ctx.recirc_id = 0;
    memset(&miss_ctx.tnl, 0, sizeof miss_ctx.tnl);
    if (get_flow_miss_ctx_id(&miss_ctx, &act_resources->flow_miss_ctx_id)) {
        return -1;
    }
    add_mark_action(actions, act_resources->flow_miss_ctx_id);
    if (get_table_id(port, 0, TABLE_TYPE_FLOW,
                     &act_resources->next_table_id)) {
        return -1;
    }
    add_jump_action(actions, act_resources->next_table_id);
    return 0;
}

static int
add_recirc_action(struct flow_actions *actions,
                  const struct nlattr *nla,
                  struct act_resources *act_resources,
                  struct act_vars *act_vars)
{
    struct flow_miss_ctx miss_ctx;

    miss_ctx.vport = act_vars->vport;
    miss_ctx.recirc_id = nl_attr_get_u32(nla);
    if (act_vars->vport != ODPP_NONE) {
        get_tnl_masked(&miss_ctx.tnl, NULL, act_vars->tnl_key,
                       &act_vars->tnl_mask);
    } else {
        memset(&miss_ctx.tnl, 0, sizeof miss_ctx.tnl);
    }
    if (get_flow_miss_ctx_id(&miss_ctx, &act_resources->flow_miss_ctx_id)) {
        return -1;
    }
    add_mark_action(actions, act_resources->flow_miss_ctx_id);
    if (get_table_id(act_vars->vport, miss_ctx.recirc_id, TABLE_TYPE_FLOW,
        &act_resources->next_table_id)) {
        return -1;
    }
    if (act_vars->vport != ODPP_NONE && act_vars->recirc_id == 0) {
        if (get_tnl_id(act_vars->tnl_key, &act_vars->tnl_mask,
                       &act_resources->tnl_id)) {
            return -1;
        }
        if (add_action_set_reg_field(actions, REG_FIELD_TUN_INFO,
                                     act_resources->tnl_id, 0xFFFFFFFF)) {
            return -1;
        }
    }
    add_jump_action(actions, act_resources->next_table_id);
    return 0;
}

static void
add_vxlan_decap_action(struct flow_actions *actions)
{
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP, NULL);
}

static int
parse_ct_actions(struct flow_actions *actions,
                 const struct nlattr *ct_actions,
                 const size_t ct_actions_len,
                 struct act_resources *act_resources,
                 struct act_vars *act_vars)
{
    struct ct_miss_ctx ct_miss_ctx;
    const struct nlattr *cta;
    unsigned int ctleft;

    memset(&ct_miss_ctx, 0, sizeof ct_miss_ctx);
    act_vars->ct_mode = CT_MODE_CT;
    NL_ATTR_FOR_EACH_UNSAFE (cta, ctleft, ct_actions, ct_actions_len) {
        if (nl_attr_type(cta) == OVS_CT_ATTR_COMMIT ||
            nl_attr_type(cta) == OVS_CT_ATTR_FORCE_COMMIT) {
            VLOG_DBG_RL(&rl,
                        "Don't support ct-commit action, action type: %d",
                        nl_attr_type(cta));
            return -1;
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_ZONE) {
            add_action_set_reg_field(actions, REG_FIELD_CT_ZONE,
                                     nl_attr_get_u16(cta), 0xFFFF);
            ct_miss_ctx.zone = nl_attr_get_u16(cta);
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_MARK) {
            const uint32_t *key = nl_attr_get(cta);
            const uint32_t *mask = key + 1;

            add_action_set_reg_field(actions, REG_FIELD_CT_MARK, *key, *mask);
            ct_miss_ctx.mark = *key;
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_LABELS) {
            const ovs_32aligned_u128 *key = nl_attr_get(cta);
            const ovs_32aligned_u128 *mask = key + 1;

            if (mask->u32[0]) {
                add_action_set_reg_field(actions, REG_FIELD_CT_LABEL0,
                                         key->u32[0], mask->u32[0]);
            }
            if (mask->u32[1]) {
                add_action_set_reg_field(actions, REG_FIELD_CT_LABEL1,
                                         key->u32[1], mask->u32[1]);
            }
            if (mask->u32[2]) {
                add_action_set_reg_field(actions, REG_FIELD_CT_LABEL2,
                                         key->u32[2], mask->u32[2]);
            }
            if (mask->u32[3]) {
                add_action_set_reg_field(actions, REG_FIELD_CT_LABEL3,
                                         key->u32[3], mask->u32[3]);
            }
            ct_miss_ctx.label.u32[0] = key->u32[0];
            ct_miss_ctx.label.u32[1] = key->u32[1];
            ct_miss_ctx.label.u32[2] = key->u32[2];
            ct_miss_ctx.label.u32[3] = key->u32[3];
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_NAT) {
            act_vars->ct_mode = CT_MODE_CT_NAT;
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_HELPER) {
            const char *helper = nl_attr_get(cta);

            if (strncmp(helper, "offload", strlen("offload"))) {
                continue;
            }

            if (!ovs_scan(helper, "offload, ct_state(0x%"SCNx8")",
                          &ct_miss_ctx.state)) {
                VLOG_ERR("Invalid offload helper: '%s'", helper);
                return -1;
            }

            act_vars->ct_mode = CT_MODE_CT_CONN;
            act_vars->pre_ct_tuple_rewrite = false;
            if (get_table_id(act_vars->vport, 0, TABLE_TYPE_POST_CT,
                             &act_resources->next_table_id)) {
                return -1;
            }
            if (get_ct_ctx_id(&ct_miss_ctx, &act_resources->ct_miss_ctx_id)) {
                return -1;
            }
            add_action_set_reg_field(actions, REG_FIELD_CT_STATE,
                                     ct_miss_ctx.state, 0xFF);
            add_action_set_reg_field(actions, REG_FIELD_CT_CTX,
                                     act_resources->ct_miss_ctx_id, 0xFFFFFFFF);
            add_jump_action(actions, act_resources->next_table_id);
        } else {
            VLOG_DBG_RL(&rl,
                        "Ignored nested action inside ct(), action type: %d",
                        nl_attr_type(cta));
            continue;
        }
    }
    return 0;
}

static void
split_ct_conn_actions(const struct rte_flow_action *actions,
                      struct flow_actions *ct_actions,
                      struct flow_actions *nat_actions)
{
    for (; actions && actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
        if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) {
            continue;
        }
        if (actions->type != RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC &&
            actions->type != RTE_FLOW_ACTION_TYPE_SET_IPV4_DST &&
            actions->type != RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC &&
            actions->type != RTE_FLOW_ACTION_TYPE_SET_IPV6_DST &&
            actions->type != RTE_FLOW_ACTION_TYPE_SET_TP_SRC &&
            actions->type != RTE_FLOW_ACTION_TYPE_SET_TP_DST) {
            add_flow_action(ct_actions, actions->type, actions->conf);
        }
        add_flow_action(nat_actions, actions->type, actions->conf);
    }
    add_flow_action(ct_actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    add_flow_action(nat_actions, RTE_FLOW_ACTION_TYPE_END, NULL);
}

static int
create_ct_conn(struct netdev *netdev,
               const struct rte_flow_item *items,
               const struct rte_flow_action *actions,
               struct rte_flow_error *error,
               struct act_resources *act_resources,
               struct act_vars *act_vars,
               struct flow_item *fi)
{
    struct flow_actions nat_actions = { .actions = NULL, .cnt = 0 };
    struct flow_actions ct_actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow_attr attr = { .ingress = 1, .transfer = 1 };
    int ret = -1;

    if (get_table_id(act_vars->vport, 0, TABLE_TYPE_CT_NAT,
                     &act_resources->ct_nat_table_id)) {
        return -1;
    }
    split_ct_conn_actions(actions, &ct_actions, &nat_actions);
    attr.group = act_resources->ct_nat_table_id;
    fi->has_count[0] = true;
    ret = create_rte_flow(netdev, &attr, items, nat_actions.actions, error, fi,
                          1);
    if (ret) {
        goto out;
    }

    put_table_id(act_resources->self_table_id);
    act_resources->self_table_id = 0;
    if (get_table_id(act_vars->vport, 0, TABLE_TYPE_CT,
                     &act_resources->self_table_id)) {
        ret = -1;
        goto ct_err;
    }
    attr.group = act_resources->self_table_id;
    fi->has_count[1] = true;
    ret = create_rte_flow(netdev, &attr, items, ct_actions.actions, error, fi,
                          0);
    if (ret) {
        goto ct_err;
    }
    goto out;

ct_err:
    netdev_offload_dpdk_destroy_flow(netdev, fi->rte_flow[1], NULL);
out:
    free_flow_actions(&ct_actions, false);
    free_flow_actions(&nat_actions, false);
    return ret;
}

static void
split_pre_post_ct_actions(const struct rte_flow_action *actions,
                          struct flow_actions *pre_ct_actions,
                          struct flow_actions *post_ct_actions)
{
    while (actions && actions->type != RTE_FLOW_ACTION_TYPE_END) {
        if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP ||
            actions->type == RTE_FLOW_ACTION_TYPE_SET_TAG ||
            actions->type == RTE_FLOW_ACTION_TYPE_SET_META) {
            add_flow_action(pre_ct_actions, actions->type, actions->conf);
        } else {
            add_flow_action(post_ct_actions, actions->type, actions->conf);
        }
        actions++;
    }
}

static int
create_pre_post_ct(struct netdev *netdev,
                   const struct rte_flow_attr *attr,
                   const struct rte_flow_item *items,
                   const struct rte_flow_action *actions,
                   struct rte_flow_error *error,
                   struct act_resources *act_resources,
                   struct act_vars *act_vars,
                   struct flow_item *fi)
{
    struct flow_actions post_ct_actions = { .actions = NULL, .cnt = 0 };
    struct flow_actions pre_ct_actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow_item_mark post_ct_mark;
    struct rte_flow_item post_ct_items[] = {
        { .type = RTE_FLOW_ITEM_TYPE_MARK, .spec = &post_ct_mark, },
        { .type = RTE_FLOW_ITEM_TYPE_END, } };
    struct rte_flow_action_mark pre_ct_mark;
    struct rte_flow_action_jump pre_ct_jump;
    struct flow_miss_ctx pre_ct_miss_ctx;
    struct rte_flow_attr post_ct_attr;
    enum table_type tbl_type;
    int ret;

    tbl_type = act_vars->ct_mode == CT_MODE_CT
               ? TABLE_TYPE_CT : TABLE_TYPE_CT_NAT;

    /* post-ct */
    post_ct_mark.id = act_resources->flow_id;
    memcpy(&post_ct_attr, attr, sizeof post_ct_attr);
    if (get_table_id(act_vars->vport, 0, TABLE_TYPE_POST_CT,
                     &act_resources->post_ct_table_id)) {
        return -1;
    }
    post_ct_attr.group = act_resources->post_ct_table_id;
    split_pre_post_ct_actions(actions, &pre_ct_actions, &post_ct_actions);
    add_flow_action(&post_ct_actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    ret = create_rte_flow(netdev, &post_ct_attr, post_ct_items,
                          post_ct_actions.actions, error, fi, 1);
    fi->has_count[1] = true;
    if (ret) {
        goto out;
    }

    /* pre-ct */
    if (get_table_id(act_vars->vport, 0, tbl_type,
                     &act_resources->ct_table_id)) {
        ret = -1;
        goto pre_ct_err;
    }
    pre_ct_miss_ctx.vport = act_vars->vport;
    pre_ct_miss_ctx.recirc_id = act_vars->recirc_id;
    if (act_vars->vport != ODPP_NONE) {
        get_tnl_masked(&pre_ct_miss_ctx.tnl, NULL, act_vars->tnl_key,
                       &act_vars->tnl_mask);
    } else {
        memset(&pre_ct_miss_ctx.tnl, 0, sizeof pre_ct_miss_ctx.tnl);
    }
    if (associate_flow_id(act_resources->flow_id, &pre_ct_miss_ctx)) {
        goto pre_ct_err;
    }
    act_resources->associated_flow_id = true;
    pre_ct_mark.id = act_resources->flow_id;
    add_flow_action(&pre_ct_actions, RTE_FLOW_ACTION_TYPE_MARK, &pre_ct_mark);
    pre_ct_jump.group = act_resources->ct_table_id;
    add_flow_action(&pre_ct_actions, RTE_FLOW_ACTION_TYPE_JUMP, &pre_ct_jump);
    add_flow_action(&pre_ct_actions, RTE_FLOW_ITEM_TYPE_END, NULL);
    ret = create_rte_flow(netdev, attr, items, pre_ct_actions.actions, error,
                          fi, 0);
    if (ret) {
        goto pre_ct_err;
    }
    goto out;

pre_ct_err:
    netdev_offload_dpdk_destroy_flow(netdev, fi->rte_flow[1], NULL);
out:
    free_flow_actions(&pre_ct_actions, false);
    free_flow_actions(&post_ct_actions, false);
    return ret;
}

static int
netdev_offload_dpdk_flow_create(struct netdev *netdev,
                                const struct rte_flow_attr *attr,
                                const struct rte_flow_item *items,
                                const struct rte_flow_action *actions,
                                struct rte_flow_error *error,
                                struct act_resources *act_resources,
                                struct act_vars *act_vars,
                                struct flow_item *fi)
{
    switch (act_vars->ct_mode) {
    case CT_MODE_NONE:
        fi->has_count[0] = true;
        return create_rte_flow(netdev, attr, items, actions, error, fi, 0);
    case CT_MODE_CT:
        /* fallthrough */
    case CT_MODE_CT_NAT:
        return create_pre_post_ct(netdev, attr, items, actions, error,
                                  act_resources, act_vars, fi);
    case CT_MODE_CT_CONN:
        return create_ct_conn(netdev, items, actions, error, act_resources,
                              act_vars, fi);
    default:
        OVS_NOT_REACHED();
    }
}

static int
parse_flow_actions(struct netdev *netdev,
                   struct flow_actions *actions,
                   struct nlattr *nl_actions,
                   size_t nl_actions_len,
                   struct act_resources *act_resources,
                   struct act_vars *act_vars)
{
    struct nlattr *nla;
    size_t left;

    if (nl_actions_len != 0 && !strcmp(netdev_get_type(netdev), "vxlan") &&
        act_vars->recirc_id == 0) {
        add_vxlan_decap_action(actions);
    }
    add_count_action(actions);
    NL_ATTR_FOR_EACH_UNSAFE (nla, left, nl_actions, nl_actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            if (add_output_action(netdev, actions, nla)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_DROP) {
            add_flow_action(actions, RTE_FLOW_ACTION_TYPE_DROP, NULL);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET ||
                   nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED) {
            const struct nlattr *set_actions = nl_attr_get(nla);
            const size_t set_actions_len = nl_attr_get_size(nla);
            bool masked = nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED;

            if (parse_set_actions(actions, set_actions, set_actions_len,
                                  masked, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CLONE) {
            const struct nlattr *clone_actions = nl_attr_get(nla);
            size_t clone_actions_len = nl_attr_get_size(nla);

            if (parse_clone_actions(netdev, actions, clone_actions,
                                    clone_actions_len)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_TUNNEL_POP) {
            if (add_tnl_pop_action(actions, nla, act_resources)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_RECIRC) {
            if (add_recirc_action(actions, nla, act_resources, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CT) {
            const struct nlattr *ct_actions = nl_attr_get(nla);
            size_t ct_actions_len = nl_attr_get_size(nla);

            if (parse_ct_actions(actions, ct_actions, ct_actions_len,
                                 act_resources, act_vars)) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&rl, "Unsupported action type %d", nl_attr_type(nla));
            return -1;
        }
    }

    if (act_vars->pre_ct_tuple_rewrite && act_vars->ct_mode != CT_MODE_NONE) {
        VLOG_DBG_RL(&rl, "Unsupported tuple rewrite before ct action");
        return -1;
    }

    if (nl_actions_len == 0) {
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_DROP, NULL);
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    return 0;
}

static int
netdev_offload_dpdk_create_tnl_flows(struct netdev *netdev,
                                     struct flow_patterns *patterns,
                                     struct flow_actions *actions,
                                     const ovs_u128 *ufid,
                                     struct act_resources *act_resources,
                                     struct act_vars *act_vars,
                                     struct flows_handle *flows)
{
    struct rte_flow_attr flow_attr = { .ingress = 1, .transfer = 1 };
    struct flow_item flow_item = { .devargs = NULL };
    struct netdev_flow_dump **netdev_dumps;
    struct rte_flow_error error;
    int num_ports = 0;
    int ret;
    int i;

    netdev_dumps = netdev_ports_flow_dump_create(netdev->dpif_type,
                                                 &num_ports);
    flow_attr.group = act_resources->self_table_id;
    for (i = 0; i < num_ports; i++) {
        if (!netdev_dpdk_is_uplink_port(netdev_dumps[i]->netdev)) {
            continue;
        }
        ret = netdev_offload_dpdk_flow_create(netdev_dumps[i]->netdev,
                                              &flow_attr, patterns->items,
                                              actions->actions, &error,
                                              act_resources, act_vars,
                                              &flow_item);
        if (ret) {
            continue;
        }
        flow_item.devargs =
            netdev_dpdk_get_port_devargs(netdev_dumps[i]->netdev);
        VLOG_DBG_RL(&rl, "%s: installed flow %p/%p by ufid "UUID_FMT"\n",
                    netdev_get_name(netdev), flow_item.rte_flow[0],
                    flow_item.rte_flow[1],
                    UUID_ARGS((struct uuid *)ufid));
        add_flow_item(flows, &flow_item);
    }
    for (i = 0; i < num_ports; i++) {
        int err = netdev_flow_dump_destroy(netdev_dumps[i]);

        if (err != 0 && err != EOPNOTSUPP) {
            VLOG_ERR("failed dumping netdev: %s", ovs_strerror(err));
        }
    }

    ret = flows->cnt > 0 ? 0 : -1;
    return ret;
}

static int
netdev_offload_dpdk_actions(struct netdev *netdev,
                            struct flow_patterns *patterns,
                            struct nlattr *nl_actions,
                            size_t actions_len,
                            const ovs_u128 *ufid,
                            struct act_resources *act_resources,
                            struct act_vars *act_vars,
                            struct flows_handle *flows)
{
    struct rte_flow_attr flow_attr = { .ingress = 1, .transfer = 1 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct flow_item flow_item = { .devargs = NULL };
    struct rte_flow_error error;
    int ret;

    ret = parse_flow_actions(netdev, &actions, nl_actions, actions_len,
                             act_resources, act_vars);
    if (ret) {
        goto out;
    }
    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        ret = netdev_offload_dpdk_create_tnl_flows(netdev, patterns, &actions,
                                                   ufid, act_resources,
                                                   act_vars, flows);
    } else {
        flow_attr.group = act_resources->self_table_id;
        ret = netdev_offload_dpdk_flow_create(netdev, &flow_attr,
                                              patterns->items,
                                              actions.actions, &error,
                                              act_resources, act_vars,
                                              &flow_item);
        if (ret) {
            goto out;
        }
        VLOG_DBG_RL(&rl, "%s: installed flow %p/%p by ufid "UUID_FMT"\n",
                    netdev_get_name(netdev), flow_item.rte_flow[0],
                    flow_item.rte_flow[1],
                    UUID_ARGS((struct uuid *)ufid));
        add_flow_item(flows, &flow_item);
    }
out:
    free_flow_actions(&actions, true);
    return ret;
}

static int
netdev_offload_dpdk_add_flow(struct netdev *netdev,
                             struct match *match,
                             struct nlattr *nl_actions,
                             size_t actions_len,
                             const ovs_u128 *ufid,
                             struct offload_info *info)
{
    struct act_resources act_resources = { .flow_id = info->flow_mark };
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flows_handle flows = { .items = NULL, .cnt = 0 };
    struct act_vars act_vars = { .vport = ODPP_NONE };
    struct flow_item flow_item = { .devargs = NULL };
    bool actions_offloaded = true;
    int ret;

    ret = parse_flow_match(netdev, &patterns, match, &act_resources,
                           &act_vars);
    if (ret) {
        goto out;
    }

    ret = netdev_offload_dpdk_actions(netdev, &patterns, nl_actions,
                                      actions_len, ufid, &act_resources,
                                      &act_vars, &flows);
    if (ret) {
        /* If we failed to offload the rule actions fallback to MARK+RSS
         * actions.
         */
        actions_offloaded = false;
        flow_item.rte_flow[0] = act_resources.self_table_id == 0 ?
            netdev_offload_dpdk_mark_rss(&patterns, netdev, info->flow_mark) :
            NULL;
        ret = flow_item.rte_flow[0] ? 0 : -1;
        if (ret) {
            goto out;
        }
        VLOG_DBG_RL(&rl, "%s: installed flow %p by ufid "UUID_FMT"\n",
                    netdev_get_name(netdev), flow_item.rte_flow[0],
                    UUID_ARGS((struct uuid *)ufid));
        add_flow_item(&flows, &flow_item);
    }

    if (ret) {
        goto out;
    }
    ufid_to_rte_flow_associate(ufid, &flows, actions_offloaded,
                               &act_resources);

out:
    if (ret) {
        put_action_resources(&act_resources);
    }
    free_flow_patterns(&patterns);
    return ret;
}

static int
netdev_offload_dpdk_remove_flows(struct netdev *netdev,
                                 const ovs_u128 *ufid,
                                 struct flows_handle *flows)
{
    struct ufid_to_rte_flow_data *data;
    struct netdev *flow_netdev;
    int ret;
    int i;
    int j;

    for (i = 0; i < flows->cnt; i++) {
        struct flow_item *fi = &flows->items[i];

        if (fi->devargs) {
            flow_netdev = netdev_dpdk_get_netdev_by_devargs(fi->devargs);
            if (!flow_netdev) {
                VLOG_DBG_RL(&rl, "%s: ufid "UUID_FMT": "
                            "could not find a netdev for devargs='%s'\n",
                            netdev_get_name(netdev),
                            UUID_ARGS((struct uuid *)ufid), fi->devargs);
                continue;
            }
        } else {
            flow_netdev = netdev;
            netdev_ref(flow_netdev);
        }
        for (j = 0; j < NUM_RTE_FLOWS_PER_PORT; j++) {
            struct rte_flow *rte_flow = fi->rte_flow[j];

            if (!rte_flow) {
                continue;
            }
            ret = netdev_offload_dpdk_destroy_flow(flow_netdev, rte_flow, ufid);
            if (ret) {
                netdev_close(flow_netdev);
                goto out;
            }
        }
        netdev_close(flow_netdev);
    }
    data = ufid_to_rte_flow_data_find(ufid);
    if (data) {
        put_action_resources(&data->act_resources);
        ufid_to_rte_flow_disassociate(data);
        ret = 0;
    } else {
        VLOG_WARN("ufid "UUID_FMT" is not associated with rte flow(s)\n",
                  UUID_ARGS((struct uuid *) ufid));
        ret = -1;
    }

out:
    free_flow_handle(flows);
    return ret;
}

static int
netdev_offload_dpdk_flow_put(struct netdev *netdev, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             const ovs_u128 *ufid, struct offload_info *info,
                             struct dpif_flow_stats *stats)
{
    struct ufid_to_rte_flow_data *rte_flow_data;
    int ret;

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    rte_flow_data = ufid_to_rte_flow_data_find(ufid);
    if (rte_flow_data) {
        ret = netdev_offload_dpdk_remove_flows(netdev, ufid,
                                               &rte_flow_data->flows);
        if (ret < 0) {
            return ret;
        }
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return netdev_offload_dpdk_add_flow(netdev, match, actions,
                                        actions_len, ufid, info);
}

static int
netdev_offload_dpdk_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats)
{
    struct ufid_to_rte_flow_data *rte_flow_data;

    rte_flow_data = ufid_to_rte_flow_data_find(ufid);
    if (!rte_flow_data) {
        return -1;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return netdev_offload_dpdk_remove_flows(netdev, ufid,
                                            &rte_flow_data->flows);
}

static int
netdev_offload_dpdk_init_flow_api(struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class)
        && !strcmp(netdev_get_dpif_type(netdev), "system")) {
        VLOG_DBG("%s: vport belongs to the system datapath. Skipping.",
                 netdev_get_name(netdev));
        return EOPNOTSUPP;
    }

    return netdev_dpdk_flow_api_supported(netdev) ? 0 : EOPNOTSUPP;
}

static int
netdev_offload_dpdk_flow_get(struct netdev *netdev,
                             struct match *match OVS_UNUSED,
                             struct nlattr **actions OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats,
                             struct dpif_flow_attrs *attrs,
                             struct ofpbuf *buf OVS_UNUSED)
{
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_query_count query;
    struct rte_flow_error error;
    struct netdev *flow_netdev;
    int ret = 0;
    int i;
    int j;

    rte_flow_data = ufid_to_rte_flow_data_find(ufid);
    if (!rte_flow_data || rte_flow_data->flows.cnt == 0) {
        ret = -1;
        goto out;
    }

    attrs->offloaded = true;
    if (!rte_flow_data->actions_offloaded) {
        attrs->dp_layer = "ovs";
        memset(stats, 0, sizeof *stats);
        goto out;
    }

    attrs->dp_layer = "dpdk";
    for (i = 0; i < rte_flow_data->flows.cnt; i++) {
        struct flow_item *fi = &rte_flow_data->flows.items[i];

        if (rte_flow_data->flows.items[i].devargs) {
            flow_netdev = netdev_dpdk_get_netdev_by_devargs(fi->devargs);
            if (!flow_netdev) {
                ret = -1;
                goto out;
            }
        } else {
            flow_netdev = netdev;
            netdev_ref(flow_netdev);
        }
        for (j = 0; j < NUM_RTE_FLOWS_PER_PORT; j++) {
            struct rte_flow *rte_flow = fi->rte_flow[j];

            if (!rte_flow || !fi->has_count[j]) {
                continue;
            }
            memset(&query, 0, sizeof query);
            query.reset = 1;
            ret = netdev_dpdk_rte_flow_query_count(flow_netdev, rte_flow,
                                                   &query, &error);
            if (ret) {
                VLOG_DBG_RL(&rl, "%s: Failed to query ufid "UUID_FMT" flow:"
                            " %p\n", netdev_get_name(netdev),
                            UUID_ARGS((struct uuid *) ufid), rte_flow);
                netdev_close(flow_netdev);
                goto out;
            }
            rte_flow_data->stats.n_packets += query.hits_set ? query.hits : 0;
            rte_flow_data->stats.n_bytes += query.bytes_set ? query.bytes : 0;
            if (query.hits_set && query.hits) {
                rte_flow_data->stats.used = time_msec();
            }
        }
        netdev_close(flow_netdev);
    }
    memcpy(stats, &rte_flow_data->stats, sizeof *stats);
out:
    attrs->dp_extra_info = NULL;
    return ret;
}

static int
netdev_offload_dpdk_hw_miss_packet_recover(struct netdev *netdev,
                                           uint32_t flow_miss_ctx_id,
                                           struct dp_packet *packet)
{
    struct flow_miss_ctx flow_miss_ctx;
    struct ct_miss_ctx ct_miss_ctx;
    struct netdev *vport_netdev;
    uint32_t ct_ctx_id;

    if (find_flow_miss_ctx(flow_miss_ctx_id, &flow_miss_ctx)) {
        return -1;
    }

    packet->md.recirc_id = flow_miss_ctx.recirc_id;
    if (flow_miss_ctx.vport != ODPP_NONE) {
        if (flow_miss_ctx.recirc_id == 0) {
            vport_netdev = netdev_ports_get(flow_miss_ctx.vport,
                                            netdev->dpif_type);
            if (vport_netdev) {
                pkt_metadata_init(&packet->md, flow_miss_ctx.vport);
                if (vport_netdev->netdev_class->pop_header) {
                    vport_netdev->netdev_class->pop_header(packet);
                    dp_packet_reset_offload(packet);
                    packet->md.in_port.odp_port = flow_miss_ctx.vport;
                } else {
                    VLOG_ERR("vport nedtdev=%s with no pop_header method",
                             netdev_get_name(vport_netdev));
                }
                netdev_close(vport_netdev);
            }
        } else {
            memcpy(&packet->md.tunnel, &flow_miss_ctx.tnl,
                   sizeof packet->md.tunnel);
            packet->md.in_port.odp_port = flow_miss_ctx.vport;
        }
    }
    if (!get_packet_reg_field(packet, REG_FIELD_CT_CTX, &ct_ctx_id)) {
        if (find_ct_miss_ctx(ct_ctx_id, &ct_miss_ctx)) {
            VLOG_ERR("ct ctx id %d is not found", ct_ctx_id);
            return -1;
        }
        packet->md.ct_state = ct_miss_ctx.state;
        packet->md.ct_zone = ct_miss_ctx.zone;
        packet->md.ct_mark = ct_miss_ctx.mark;
        packet->md.ct_label = ct_miss_ctx.label;
    }

    return 0;
}

static int
netdev_offload_dpdk_flow_dump_create(struct netdev *netdev,
                                     struct netdev_flow_dump **dump_out)
{
    struct netdev_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->netdev = netdev_ref(netdev);

    *dump_out = dump;
    return 0;
}

static int
netdev_offload_dpdk_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    netdev_close(dump->netdev);
    free(dump);
    return 0;
}

const struct netdev_flow_api netdev_offload_dpdk = {
    .type = "dpdk_flow_api",
    .flow_put = netdev_offload_dpdk_flow_put,
    .flow_del = netdev_offload_dpdk_flow_del,
    .init_flow_api = netdev_offload_dpdk_init_flow_api,
    .flow_get = netdev_offload_dpdk_flow_get,
    .hw_miss_packet_recover = netdev_offload_dpdk_hw_miss_packet_recover,
    .flow_dump_create = netdev_offload_dpdk_flow_dump_create,
    .flow_dump_destroy = netdev_offload_dpdk_flow_dump_destroy,
};
