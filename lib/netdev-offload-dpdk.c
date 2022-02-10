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
#include <rte_gre.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"
#include "salloc.h"
#include "seq-pool.h"
#include "odp-util.h"
#include "ovs-atomic.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Thread-safety
 * =============
 *
 * Below API is NOT thread safe in following terms:
 *
 *  - The caller must be sure that 'netdev' will not be destructed/deallocated.
 *
 *  - The caller must be sure that 'netdev' configuration will not be changed.
 *    For example, simultaneous call of 'netdev_reconfigure()' for the same
 *    'netdev' is forbidden.
 *
 * For current implementation all above restrictions could be fulfilled by
 * taking the datapath 'port_rwlock' in lib/dpif-netdev.c.  */

struct per_thread {
PADDED_MEMBERS(CACHE_LINE_SIZE,
    char scratch[10000];
    struct salloc *s;
);
};

static struct per_thread per_threads[MAX_OFFLOAD_THREAD_NB];

static void
per_thread_init(void)
{
    struct per_thread *pt = &per_threads[netdev_offload_thread_id()];

    if (pt->s == NULL) {
        pt->s = salloc_init(pt->scratch, sizeof pt->scratch);
    }
    salloc_reset(pt->s);
}

static void *
per_thread_xmalloc(size_t n)
{
    struct per_thread *pt = &per_threads[netdev_offload_thread_id()];
    void *p = salloc(pt->s, n);

    if (p == NULL) {
        p = xmalloc(n);
    }

    return p;
}

static void *
per_thread_xzalloc(size_t n)
{
    struct per_thread *pt = &per_threads[netdev_offload_thread_id()];
    void *p = szalloc(pt->s, n);

    if (p == NULL) {
        p = xzalloc(n);
    }

    return p;
}

static void *
per_thread_xcalloc(size_t n, size_t sz)
{
    struct per_thread *pt = &per_threads[netdev_offload_thread_id()];
    void *p = scalloc(pt->s, n, sz);

    if (p == NULL) {
        p = xcalloc(n, sz);
    }

    return p;
}

static void *
per_thread_xrealloc(void *old_p, size_t old_size, size_t new_size)
{
    struct per_thread *pt = &per_threads[netdev_offload_thread_id()];
    void *new_p = NULL;

    if (salloc_contains(pt->s, old_p)) {
        new_p = srealloc(pt->s, old_p, new_size);
        if (new_p == NULL) {
            new_p = xmalloc(new_size);
            if (new_p) {
                memcpy(new_p, old_p, old_size);
            }
        }
    } else {
        new_p = xrealloc(old_p, new_size);
    }

    return new_p;
}

static void
per_thread_free(void *p)
{
    struct per_thread *pt = &per_threads[netdev_offload_thread_id()];

    if (salloc_contains(pt->s, p)) {
        /* The only freeing done in the scratch allocator is when resetting it.
         * However, realloc has a chance to shrink, so still attempt it. */
        srealloc(pt->s, p, 0);
    } else {
        free(p);
    }
}

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
    uint32_t ct_match_zone_id;
    uint32_t ct_action_zone_id;
    uint32_t ct_match_label_id;
    uint32_t ct_action_label_id;
    uint32_t ct_shared_age_id;
    uint32_t ctid;
    uint32_t counter_id;
    uint32_t sflow_id;
};

#define NUM_RTE_FLOWS_PER_PORT 2
struct flow_item {
    const char *devargs;
    unsigned int creation_tid;
    uint32_t next_table_id;
    uint32_t self_table_id;
    uint32_t self_e2e_table_id;
    uint32_t next_e2e_table_id;
    struct rte_flow *rte_flow[NUM_RTE_FLOWS_PER_PORT];
    bool has_count[NUM_RTE_FLOWS_PER_PORT];
};

struct flows_handle {
    struct ovsrcu_gc_node gc_node;
    struct flow_item *items;
    int cnt;
    int current_max;
};

static void
flows_handle_gc(struct flows_handle *flows)
{
    free(flows->items);
    flows->items = NULL;
    flows->cnt = 0;
}

static void put_table_id(const char *devargs, uint32_t table_id);
static void
free_flow_handle(struct flows_handle *flows, bool postpone_unref)
{
    int i;

    for (i = 0; i < flows->cnt; i++) {
        struct flow_item *fi = &flows->items[i];

        put_table_id(fi->devargs, fi->self_table_id);
        put_table_id(fi->devargs, fi->next_table_id);
        put_table_id(fi->devargs, fi->self_e2e_table_id);
        put_table_id(fi->devargs, fi->next_e2e_table_id);
        if (fi->devargs) {
            free(CONST_CAST(void *, fi->devargs));
        }
    }
    if (postpone_unref) {
        ovsrcu_gc(flows_handle_gc, flows, gc_node);
    } else {
        flows_handle_gc(flows);
    }
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
    flows->items[cnt].creation_tid = netdev_offload_thread_id();
    flows->cnt++;
}

/*
 * A mapping from ufid to dpdk rte_flow.
 */

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct flows_handle flows;
    bool actions_offloaded;
    struct dpif_flow_stats stats;
    struct act_resources act_resources;
    struct ovs_mutex lock;
    struct ovsrcu_gc_node gc_node;
    volatile bool dead;
};

struct netdev_offload_dpdk_data {
    struct cmap ufid_to_rte_flow;
    atomic_uint64_t *rte_flow_counters;
    struct ovs_mutex map_lock;
};

static int
offload_data_init(struct netdev *netdev)
{
    struct netdev_offload_dpdk_data *data;

    data = xzalloc(sizeof *data);
    ovs_mutex_init(&data->map_lock);
    cmap_init(&data->ufid_to_rte_flow);
    /* Configure cmap to never shrink. */
    cmap_set_min_load(&data->ufid_to_rte_flow, 0.0);
    data->rte_flow_counters = xcalloc(netdev_offload_thread_nb(),
                                      sizeof *data->rte_flow_counters);

    ovsrcu_set(&netdev->hw_info.offload_data, (void *) data);

    return 0;
}

static void
offload_data_destroy__(struct netdev_offload_dpdk_data *offload_data)
{
    ovs_mutex_destroy(&offload_data->map_lock);
    free(offload_data->rte_flow_counters);
    free(offload_data);
}

static void
offload_data_destroy(struct netdev *netdev)
{
    struct netdev_offload_dpdk_data *data;
    struct ufid_to_rte_flow_data *node;

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    if (data == NULL) {
        return;
    }

    CMAP_FOR_EACH (node, node, &data->ufid_to_rte_flow) {
        ovsrcu_postpone(free, node);
    }

    cmap_destroy(&data->ufid_to_rte_flow);
    ovsrcu_postpone(offload_data_destroy__, data);
}

static void
offload_data_lock(struct netdev *netdev)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct netdev_offload_dpdk_data *offload_data;

    offload_data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);

    ovs_mutex_lock(&offload_data->map_lock);
}

static void
offload_data_unlock(struct netdev *netdev)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct netdev_offload_dpdk_data *offload_data;

    offload_data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);

    ovs_mutex_unlock(&offload_data->map_lock);
}

static struct cmap *
offload_data_map(struct netdev *netdev)
{
    struct netdev_offload_dpdk_data *data;

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);

    return data ? &data->ufid_to_rte_flow : NULL;
}

/* Find rte_flow_data with @ufid. */
static struct ufid_to_rte_flow_data *
ufid_to_rte_flow_data_find(struct netdev *netdev,
                           const ovs_u128 *ufid,
                           bool warn)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;
    struct cmap *map = offload_data_map(netdev);

    if (!map) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    if (warn) {
        VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow",
                  UUID_ARGS((struct uuid *) ufid));
    }

    return NULL;
}

/* Find rte_flow with @ufid, lock-protected. */
static struct ufid_to_rte_flow_data *
ufid_to_rte_flow_data_find_protected(struct netdev *netdev,
                                     const ovs_u128 *ufid)
{
    struct cmap *map = offload_data_map(netdev);
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    if (!map) {
        return NULL;
    }

    CMAP_FOR_EACH_WITH_HASH_PROTECTED (data, node, hash, map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static inline struct ufid_to_rte_flow_data *
ufid_to_rte_flow_associate(const ovs_u128 *ufid, struct netdev *netdev,
                           struct flows_handle *flows, bool actions_offloaded,
                           struct act_resources *act_resources,
                           bool abort_on_dup)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct cmap *map = offload_data_map(netdev);
    struct ufid_to_rte_flow_data *data_prev;
    struct ufid_to_rte_flow_data *data;

    if (!map) {
        return NULL;
    }

    offload_data_lock(netdev);

    /*
     * We should not simply overwrite an existing rte flow.
     * We should have deleted it first before re-adding it.
     * Thus, if following assert triggers, something is wrong:
     * the rte_flow is not destroyed.
     * However, in a multh-thread environment, miss rules might be added by
     * another thread while not in protected mode, so this is possible. For
     * this, allow it.
     */
    data_prev = ufid_to_rte_flow_data_find_protected(netdev, ufid);
    if (data_prev && !data_prev->dead) {
        ovs_assert(!(abort_on_dup && data_prev->flows.cnt));
        offload_data_unlock(netdev);
        return NULL;
    }

    data = xzalloc(sizeof *data);
    data->ufid = *ufid;
    data->actions_offloaded = actions_offloaded;
    memcpy(&data->flows, flows, sizeof data->flows);
    memcpy(&data->act_resources, act_resources, sizeof data->act_resources);
    ovs_mutex_init(&data->lock);

    cmap_insert(map, CONST_CAST(struct cmap_node *, &data->node), hash);

    offload_data_unlock(netdev);

    return data;
}

static void
ufid_to_rte_flow_data_gc(struct ufid_to_rte_flow_data *data)
{
    ovs_mutex_destroy(&data->lock);
    free(data);
}

static inline void
ufid_to_rte_flow_disassociate(struct netdev *netdev,
                              struct ufid_to_rte_flow_data *data)
    OVS_REQUIRES(data->lock)
{
    struct cmap *map = offload_data_map(netdev);
    size_t hash;

    if (!map) {
        return;
    }

    offload_data_lock(netdev);

    /* Usual CMAP usage requires to make sure, under the critical section the
     * object has not been yet removed by another thread. However, in our case
     * here, the key is ufid which is handled only by this thread. Thus no need
     * to search again here.
     */
    hash = hash_bytes(&data->ufid, sizeof data->ufid, 0);
    cmap_remove(map, CONST_CAST(struct cmap_node *, &data->node), hash);

    offload_data_unlock(netdev);
}

/* A generic data structure used for mapping data to id and id to data. The
 * elements are reference coutned. Changes may come from multiple threads,
 * writes are locked.
 * "name" and "dump_context_data" are used for log messages.
 * "maps_lock" is the hashmaps lock for MT-safety.
 * "d2i_map" is the data-to-id map.
 * "i2d_map" is the id-to-data map.
 * "associated_i2d_map" is a id-to-data map used to associate already
 *      allocated ids.
 * "has_associated_map" is true if this metadata has an associated map.
 * "id_alloc" is used to allocate an id for a new data.
 * "id_free" is used to free an id for the last data release.
 * "data_size" is the size of the data in the elements.
 */
struct context_metadata {
    const char *name;
    struct ds *(*dump_context_data)(struct ds *s, void *data);
    struct ovs_mutex maps_lock;
    struct cmap d2i_map;
    struct cmap i2d_map;
    struct cmap associated_i2d_map;
    bool has_associated_map;
    uint32_t (*id_alloc)(void *arg);
    void (*id_free)(const void *arg, uint32_t id);
    size_t data_size;
    bool delayed_release;
};

struct context_release_item;

struct context_data {
    struct cmap_node d2i_node;
    uint32_t d2i_hash;
    struct cmap_node i2d_node;
    uint32_t i2d_hash;
    struct cmap_node associated_i2d_node;
    uint32_t associated_i2d_hash;
    void *data;
    uint32_t id;
    struct ovs_refcount refcount;
};

static int
get_context_data_id_by_data(struct context_metadata *md,
                            struct context_data *data_req,
                            void *arg,
                            uint32_t *id)
{
    struct context_data *data_cur;
    size_t dhash, ihash;
    uint32_t alloc_id;
    struct ds s;

    ds_init(&s);

    dhash = hash_bytes(data_req->data, md->data_size, 0);
    CMAP_FOR_EACH_WITH_HASH (data_cur, d2i_node, dhash, &md->d2i_map) {
        if (!memcmp(data_req->data, data_cur->data, md->data_size)) {
            if (!ovs_refcount_try_ref_rcu(&data_cur->refcount)) {
                /* If a reference could not be taken, it means that
                 * while the data has been found within the map, it has
                 * since been removed and related ID freed. At this point,
                 * allocate a new data node altogether. */
                break;
            }
            VLOG_DBG_RL(&rl,
                        "%s: %s: '%s', refcnt=%u, id=%d", __func__, md->name,
                        ds_cstr(md->dump_context_data(&s, data_cur->data)),
                        ovs_refcount_read(&data_cur->refcount),
                        data_cur->id);
            ds_destroy(&s);
            *id = data_cur->id;
            return 0;
        }
    }

    alloc_id = md->id_alloc(arg);
    if (alloc_id == 0) {
        goto err_id_alloc;
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
    ovs_refcount_init(&data_cur->refcount);
    data_cur->id = alloc_id;
    ovs_mutex_lock(&md->maps_lock);
    data_cur->d2i_hash = dhash;
    cmap_insert(&md->d2i_map, &data_cur->d2i_node, dhash);
    ihash = hash_add(0, data_cur->id);
    data_cur->i2d_hash = ihash;
    cmap_insert(&md->i2d_map, &data_cur->i2d_node, ihash);
    VLOG_DBG_RL(&rl, "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                ds_cstr(md->dump_context_data(&s, data_cur->data)),
                ovs_refcount_read(&data_cur->refcount),
                data_cur->id);
    *id = data_cur->id;

    ovs_mutex_unlock(&md->maps_lock);
    ds_destroy(&s);
    return 0;

err_data_alloc:
    free(data_cur);
err:
    VLOG_ERR_RL(&rl, "%s: %s: error. '%s'", __func__, md->name,
                ds_cstr(md->dump_context_data(&s, data_req->data)));
err_id_alloc:
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
        CMAP_FOR_EACH_WITH_HASH (data_cur, associated_i2d_node, ihash,
                                 &md->associated_i2d_map) {
            if (data_cur->id == id) {
                memcpy(data, data_cur->data, md->data_size);
                ds_destroy(&s);
                return 0;
            }
        }
    }
    CMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_map) {
        if (data_cur->id == id) {
            memcpy(data, data_cur->data, md->data_size);
            ds_destroy(&s);
            return 0;
        }
    }

    ds_destroy(&s);
    return -1;
}

static struct ovs_list *context_release_lists;

struct context_release_item {
    struct ovs_list node;
    struct ovsrcu_gc_node gc_node;
    long long int timestamp;
    struct context_metadata *md;
    const void *arg;
    uint32_t id;
    struct context_data *data;
    bool associated;
};

static void
context_item_gc(struct context_release_item *item)
{
    free(item->data);
    free(item);
}

static void
context_release(struct context_release_item *item)
{
    struct context_metadata *md = item->md;
    struct context_data *data = item->data;
    struct context_data *data_cur;
    size_t ihash;

    VLOG_DBG_RL(&rl, "%s: md=%s, id=%d. associated=%d", __func__, md->name,
                item->id, item->associated);

    ovs_mutex_lock(&md->maps_lock);

    if (!item->associated
        && ovs_refcount_unref(&item->data->refcount) > 1) {
        /* Data has been referenced again since delayed release request. */
        goto maps_unlock;
    }

    ihash = hash_add(0, item->id);

    if (item->associated) {
        CMAP_FOR_EACH_WITH_HASH_PROTECTED (data_cur, associated_i2d_node,
                                           ihash,
                                           &item->md->associated_i2d_map) {
            if (data_cur->id == item->id) {
                break;
            }
        }
    } else {
        CMAP_FOR_EACH_WITH_HASH_PROTECTED (data_cur, i2d_node, ihash,
                                           &item->md->i2d_map) {
            if (data_cur->id == item->id) {
                break;
            }
        }
    }

    if (data_cur && data_cur->id == item->id) {
        if (!item->associated) {
            cmap_remove(&md->i2d_map, &data->i2d_node, data->i2d_hash);
            cmap_remove(&md->d2i_map, &data->d2i_node, data->d2i_hash);
            item->md->id_free(item->arg, item->id);
        } else {
            cmap_remove(&md->associated_i2d_map,
                        &data->associated_i2d_node,
                        data->associated_i2d_hash);
        }
        ovsrcu_gc(context_item_gc, item, gc_node);
        ovs_mutex_unlock(&md->maps_lock);
        return;
    }

maps_unlock:
    ovs_mutex_unlock(&md->maps_lock);
    free(item);
}

static void
context_delayed_release_init(void)
{
    static struct ovsthread_once init_once =
        OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&init_once)) {
        size_t i;

        context_release_lists = xcalloc(netdev_offload_thread_nb(),
                                        sizeof *context_release_lists);
        for (i = 0; i < netdev_offload_thread_nb(); i++) {
            ovs_list_init(&context_release_lists[i]);
        }
        ovsthread_once_done(&init_once);
    }
}

static void
context_delayed_release(struct context_metadata *md, const void *arg,
                        uint32_t id, struct context_data *data,
                        bool associated)
{
    struct context_release_item *item;
    struct ovs_list *context_release_list;
    unsigned int tid;

    context_delayed_release_init();

    item = xzalloc(sizeof *item);
    item->md = md;
    item->arg = arg;
    item->id = id;
    item->data = data;
    item->associated = associated;
    if (!md->delayed_release) {
        context_release(item);
        return;
    }

    tid = netdev_offload_thread_id();
    context_release_list = &context_release_lists[tid];

    item->timestamp = time_msec();
    ovs_list_push_back(context_release_list, &item->node);
    VLOG_DBG_RL(&rl, "%s: md=%s, id=%d, associated=%d, timestamp=%llu",
                __func__, item->md->name, item->id, associated,
                item->timestamp);
}

#define DELAYED_RELEASE_TIMEOUT_MS 250
/* In ofproto/ofproto-dpif-rid.c, function recirc_run. Timeout for expired
 * flows is 250 msec. Set this timeout the same.
 */

static void
do_context_delayed_release(void)
{
    struct ovs_list *context_release_list;
    struct context_release_item *item;
    struct ovs_list *list;
    long long int now;
    unsigned int tid;

    context_delayed_release_init();

    tid = netdev_offload_thread_id();
    context_release_list = &context_release_lists[tid];

    now = time_msec();
    while (!ovs_list_is_empty(context_release_list)) {
        list = ovs_list_front(context_release_list);
        item = CONTAINER_OF(list, struct context_release_item, node);
        if (now < item->timestamp + DELAYED_RELEASE_TIMEOUT_MS) {
            break;
        }
        VLOG_DBG_RL(&rl, "%s: md=%s, id=%d, associated=%d, timestamp=%llu, "
                    "now=%llu", __func__, item->md->name, item->id,
                    item->associated, item->timestamp, now);
        ovs_list_remove(list);
        context_release(item);
    }
}

static void
put_context_data_by_id(struct context_metadata *md, const void *arg,
                       uint32_t id)
{
    struct context_data *data_cur;
    size_t ihash;
    struct ds s;

    if (id == 0) {
        return;
    }
    ihash = hash_add(0, id);
    CMAP_FOR_EACH_WITH_HASH (data_cur, i2d_node, ihash, &md->i2d_map) {
        if (data_cur->id == id) {
            ds_init(&s);
            VLOG_DBG_RL(&rl,
                        "%s: %s: '%s', refcnt=%u, id=%d", __func__, md->name,
                        ds_cstr(md->dump_context_data(&s, data_cur->data)),
                        ovs_refcount_read(&data_cur->refcount),
                        data_cur->id);
            ds_destroy(&s);
            context_delayed_release(md, arg, id, data_cur, false);
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
    ovs_refcount_init(&data_cur->refcount);
    data_cur->id = data_req->id;
    ihash = hash_add(0, data_cur->id);
    ovs_mutex_lock(&md->maps_lock);
    data_cur->associated_i2d_hash = ihash;
    cmap_insert(&md->associated_i2d_map, &data_cur->associated_i2d_node,
                ihash);
    ovs_mutex_unlock(&md->maps_lock);
    VLOG_DBG_RL(&rl, "%s: %s: '%s', refcnt=%d, id=%d", __func__, md->name,
                ds_cstr(md->dump_context_data(&s, data_cur->data)),
                ovs_refcount_read(&data_cur->refcount),
                data_cur->id);
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
    CMAP_FOR_EACH_WITH_HASH (data_cur, associated_i2d_node, ihash,
                             &md->associated_i2d_map) {
        if (data_cur->id == id) {
            ds_init(&s);
            VLOG_DBG_RL(&rl, "%s: %s: '%s', id=%d", __func__, md->name,
                        ds_cstr(md->dump_context_data(&s, data_cur->data)),
                        data_cur->id);
            ds_destroy(&s);
            context_delayed_release(md, NULL, id, data_cur, true);
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
    REG_FIELD_CT_LABEL_ID,
    REG_FIELD_TUN_INFO,
    REG_FIELD_CT_CTX,
    REG_FIELD_SFLOW_CTX,
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
    [REG_FIELD_CT_LABEL_ID] = {
        .type = REG_TYPE_TAG,
        .index = 2,
        .offset = 0,
        .mask = 0xFFFFFFFF,
    },
    [REG_FIELD_CT_CTX] = {
        .type = REG_TYPE_META,
        .index = 0,
        .offset = 0,
        .mask = 0x0000FFFF,
    },
    /* Since sFlow and CT will not work concurrently is it safe
     * to have the reg_fields use the same bits for SFLOW_CTX and CT_CTX.
     */
    [REG_FIELD_SFLOW_CTX] = {
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

BUILD_ASSERT_DECL(sizeof(bool) == sizeof(uint8_t));
struct table_id_data {
    uint16_t phys_port;
    bool is_e2e_cache;
    uint8_t pad[1];
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
        table_type_str = table_id_data->is_e2e_cache ? "e2e-flow" : "flow";
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

    ds_put_format(s, "(%s): phys_port=%"PRIu32", vport=%"PRIu32
                  ", recirc_id=%"PRIu32, table_type_str,
                  table_id_data->phys_port, table_id_data->vport,
                  table_id_data->recirc_id);
    return s;
}

static struct ds *
dump_label_id(struct ds *s, void *data)
{
    ovs_u128 not_mapped_ct_label = *(ovs_u128 *) data;

    ds_put_format(s, "label = %x%x%x%x", not_mapped_ct_label.u32[3],
                                         not_mapped_ct_label.u32[2],
                                         not_mapped_ct_label.u32[1],
                                         not_mapped_ct_label.u32[0]);
    return s;
}

#define MIN_LABEL_ID     1
#define MAX_LABEL_ID     (reg_fields[REG_FIELD_CT_LABEL_ID].mask - 2)
#define ZERO_LABEL_ID     (reg_fields[REG_FIELD_CT_LABEL_ID].mask - 1)

static struct seq_pool *label_id_pool = NULL;

static uint32_t
label_id_alloc(void *arg OVS_UNUSED)
{
    static struct ovsthread_once label_id_init = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t label_id;

    if (ovsthread_once_start(&label_id_init)) {
        label_id_pool = seq_pool_create(netdev_offload_thread_nb(),
                                        MIN_LABEL_ID, MAX_LABEL_ID);
        ovsthread_once_done(&label_id_init);
    }
    if (seq_pool_new_id(label_id_pool, tid, &label_id)) {
        return label_id;
    }
    return 0;
}

static void
label_id_free(const void *arg OVS_UNUSED, uint32_t label_id)
{
    unsigned int tid = netdev_offload_thread_id();

    seq_pool_free_id(label_id_pool, tid, label_id);
}

static struct context_metadata label_id_md = {
    .name = "label_id",
    .dump_context_data = dump_label_id,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = label_id_alloc,
    .id_free = label_id_free,
    .data_size = sizeof(ovs_u128),
};

static int
get_label_id(ovs_u128 *ct_label, uint32_t *ct_label_id)
{
    struct context_data label_id_context = {
        .data = ct_label,
    };

    if (is_all_zeros(ct_label, sizeof *ct_label)) {
        *ct_label_id = ZERO_LABEL_ID;
        return 0;
    }
    return get_context_data_id_by_data(&label_id_md, &label_id_context,
                                       NULL, ct_label_id);
}

static void
put_label_id(uint32_t label_id)
{
    if (label_id == ZERO_LABEL_ID) {
        return;
    }
    put_context_data_by_id(&label_id_md, NULL, label_id);
}

static struct ds *
dump_zone_id(struct ds *s, void *data)
{
    uint16_t not_mapped_ct_zone = *(uint16_t *) data;

    ds_put_format(s, "zone = %d", not_mapped_ct_zone);
    return s;
}

#define MIN_ZONE_ID     1
#define MAX_ZONE_ID     reg_fields[REG_FIELD_CT_ZONE].mask

static struct seq_pool *zone_id_pool = NULL;

static uint32_t
zone_id_alloc(void *arg OVS_UNUSED)
{
    static struct ovsthread_once zone_id_init = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t zone_id;

    if (ovsthread_once_start(&zone_id_init)) {
        zone_id_pool = seq_pool_create(netdev_offload_thread_nb(),
                                       MIN_ZONE_ID, MAX_ZONE_ID);
        ovsthread_once_done(&zone_id_init);
    }
    if (seq_pool_new_id(zone_id_pool, tid, &zone_id)) {
        return zone_id;
    }
    return 0;
}

static void
zone_id_free(const void *arg OVS_UNUSED, uint32_t zone_id)
{
    unsigned int tid = netdev_offload_thread_id();

    seq_pool_free_id(zone_id_pool, tid, zone_id);
}

static struct context_metadata zone_id_md = {
    .name = "zone_id",
    .dump_context_data = dump_zone_id,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = zone_id_alloc,
    .id_free = zone_id_free,
    .data_size = sizeof(uint16_t),
};

static int
get_zone_id(uint16_t ct_zone, uint32_t *ct_zone_id)
{
    struct context_data zone_id_context = {
        .data = &ct_zone,
    };

    return get_context_data_id_by_data(&zone_id_md, &zone_id_context,
                                       NULL, ct_zone_id);
}

static void
put_zone_id(uint32_t zone_id)
{
    put_context_data_by_id(&zone_id_md, NULL, zone_id);
}

#define MIN_TABLE_ID     1
#define MAX_TABLE_ID     (UINT32_MAX - 2)
#define MISS_TABLE_ID    (UINT32_MAX - 1)

static struct seq_pool *table_id_pool = NULL;
static uint32_t
table_id_alloc(void *arg OVS_UNUSED)
{
    static struct ovsthread_once table_id_init = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t id;

    if (ovsthread_once_start(&table_id_init)) {
        table_id_pool = seq_pool_create(netdev_offload_thread_nb(),
                                        MIN_TABLE_ID, MAX_TABLE_ID);
        ovsthread_once_done(&table_id_init);
    }

    if (seq_pool_new_id(table_id_pool, tid, &id)) {
        return id;
    }

    return 0;
}

static int
table_id_ufid(const char *devargs, bool e2e, uint32_t table_id, ovs_u128 *ufid)
{
    struct uuid *uuid = (struct uuid *)ufid;
    size_t devargs_len;
    size_t buf_len;
    uint8_t *buf;

    uuid_zero(uuid);
    if (!devargs) {
        return -1;
    }
    devargs_len = strlen(devargs);
    buf_len = sizeof table_id + devargs_len;
    buf = xmalloc(buf_len);
    memcpy(buf, (void *)&table_id, sizeof table_id);
    memcpy(&buf[sizeof table_id], devargs, devargs_len);
    odp_flow_key_hash(buf, buf_len, ufid);
    uuid_set_bits_v4(uuid, e2e ? UUID_ATTR_1 : UUID_ATTR_2);
    free(buf);
    return 0;
}

static int
netdev_offload_dpdk_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats);
static void
table_id_free(const void *arg, uint32_t id)
{
    unsigned int tid = netdev_offload_thread_id();
    struct netdev *netdev;
    ovs_u128 table_ufid;

    seq_pool_free_id(table_id_pool, tid, id);

    if (arg && !table_id_ufid(arg, false, id, &table_ufid)) {
        netdev = netdev_dpdk_get_netdev_by_devargs(arg);
        if (netdev) {
            netdev_offload_dpdk_flow_del(netdev, &table_ufid, NULL);
            table_id_ufid(arg, true, id, &table_ufid);
            netdev_offload_dpdk_flow_del(netdev, &table_ufid, NULL);
            netdev_close(netdev);
        }
    }
}

static struct context_metadata table_id_md = {
    .name = "table_id",
    .dump_context_data = dump_table_id,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = table_id_alloc,
    .id_free = table_id_free,
    .data_size = sizeof(struct table_id_data),
};

static int
get_table_id(uint16_t phys_port, odp_port_t vport, uint32_t recirc_id,
             enum table_type table_type, bool is_e2e_cache_flow,
             uint32_t *table_id)
{
    struct table_id_data table_id_data = {
        .phys_port = phys_port,
        .vport = vport,
        .recirc_id = recirc_id,
        .table_type = table_type,
        .is_e2e_cache = netdev_is_e2e_cache_enabled() && is_e2e_cache_flow,
    };
    struct context_data table_id_context = {
        .data = &table_id_data,
    };

    if (vport == ODPP_NONE && recirc_id == 0 &&
        table_type == TABLE_TYPE_FLOW && !(netdev_is_e2e_cache_enabled() &&
                                           !is_e2e_cache_flow)) {
        *table_id = 0;
        return 0;
    }

    return get_context_data_id_by_data(&table_id_md, &table_id_context, NULL,
                                       table_id);
}

static void
put_table_id(const char *devargs, uint32_t table_id)
{
    put_context_data_by_id(&table_id_md, devargs, table_id);
}

struct sflow_ctx {
    struct dpif_sflow_attr sflow_attr;
    struct user_action_cookie cookie;
    struct flow_tnl sflow_tnl;
};

static struct ds *
dump_sflow_id(struct ds *s, void *data)
{
    struct sflow_ctx *sflow_ctx = data;
    struct user_action_cookie *cookie;

    cookie = &sflow_ctx->cookie;
    ds_put_format(s, "sFlow cookie %p, ofproto_uuid "UUID_FMT,
                  cookie, UUID_ARGS(&cookie->ofproto_uuid));
    return s;
}

#define MIN_SFLOW_ID     1
#define MAX_SFLOW_ID     (reg_fields[REG_FIELD_SFLOW_CTX].mask - 1)

static struct seq_pool *sflow_id_pool = NULL;

static uint32_t
sflow_id_alloc(void *arg OVS_UNUSED)
{
    static struct ovsthread_once sflow_id_init = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t sflow_id;

    if (ovsthread_once_start(&sflow_id_init)) {
        sflow_id_pool = seq_pool_create(netdev_offload_thread_nb(),
                                        MIN_SFLOW_ID, MAX_SFLOW_ID);
        ovsthread_once_done(&sflow_id_init);
    }
    if (seq_pool_new_id(sflow_id_pool, tid, &sflow_id)) {
        return sflow_id;
    }
    return 0;
}

static void
sflow_id_free(const void *arg OVS_UNUSED, uint32_t sflow_id)
{
    unsigned int tid = netdev_offload_thread_id();

    seq_pool_free_id(sflow_id_pool, tid, sflow_id);
}

static struct context_metadata sflow_id_md = {
    .name = "sflow_id",
    .dump_context_data = dump_sflow_id,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = sflow_id_alloc,
    .id_free = sflow_id_free,
    .data_size = sizeof(struct sflow_ctx),
};

static int
get_sflow_id(struct sflow_ctx *sflow_ctx, uint32_t *sflow_id)
{
    struct context_data sflow_id_context = {
        .data = sflow_ctx,
    };

    return get_context_data_id_by_data(&sflow_id_md, &sflow_id_context,
                                       NULL, sflow_id);
}

static void
put_sflow_id(uint32_t sflow_id)
{
    put_context_data_by_id(&sflow_id_md, NULL, sflow_id);
}

static int
find_sflow_ctx(int sflow_id, struct sflow_ctx *ctx)
{
    return get_context_data_by_id(&sflow_id_md, sflow_id, ctx);
}

#define MIN_CT_CTX_ID 1
#define MAX_CT_CTX_ID (reg_fields[REG_FIELD_CT_CTX].mask - 1)

static struct seq_pool *ct_ctx_pool = NULL;

static uint32_t
ct_ctx_id_alloc(void *arg OVS_UNUSED)
{
    static struct ovsthread_once ct_ctx_init = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t id;

    if (ovsthread_once_start(&ct_ctx_init)) {
        ct_ctx_pool = seq_pool_create(netdev_offload_thread_nb(),
                                      MIN_CT_CTX_ID, MAX_CT_CTX_ID);
        ovsthread_once_done(&ct_ctx_init);
    }

    if (seq_pool_new_id(ct_ctx_pool, tid, &id)) {
        return id;
    }

    return 0;
}

static void
ct_ctx_id_free(const void *arg OVS_UNUSED, uint32_t id)
{
    unsigned int tid = netdev_offload_thread_id();

    seq_pool_free_id(ct_ctx_pool, tid, id);
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
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = ct_ctx_id_alloc,
    .id_free = ct_ctx_id_free,
    .data_size = sizeof(struct ct_miss_ctx),
    .delayed_release = true,
};

static int
get_ct_ctx_id(struct ct_miss_ctx *ct_miss_ctx_data, uint32_t *ct_ctx_id)
{
    struct context_data ct_ctx = {
        .data = ct_miss_ctx_data,
    };

    return get_context_data_id_by_data(&ct_miss_ctx_md, &ct_ctx, NULL,
                                       ct_ctx_id);
}

static void
put_ct_ctx_id(uint32_t ct_ctx_id)
{
    put_context_data_by_id(&ct_miss_ctx_md, NULL, ct_ctx_id);
}

static int
find_ct_miss_ctx(int ct_ctx_id, struct ct_miss_ctx *ctx)
{
    return get_context_data_by_id(&ct_miss_ctx_md, ct_ctx_id, ctx);
}

#define MIN_TUNNEL_ID 1
#define MAX_TUNNEL_ID (reg_fields[REG_FIELD_TUN_INFO].mask - 1)

static struct seq_pool *tnl_id_pool = NULL;

static uint32_t
tnl_id_alloc(void *arg OVS_UNUSED)
{
    static struct ovsthread_once tnl_id_init = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t id;

    if (ovsthread_once_start(&tnl_id_init)) {
        tnl_id_pool = seq_pool_create(netdev_offload_thread_nb(),
                                      MIN_TUNNEL_ID, MAX_TUNNEL_ID);
        ovsthread_once_done(&tnl_id_init);
    }

    if (seq_pool_new_id(tnl_id_pool, tid, &id)) {
        return id;
    }

    return 0;
}

static void
tnl_id_free(const void *arg OVS_UNUSED, uint32_t id)
{
    unsigned int tid = netdev_offload_thread_id();

    seq_pool_free_id(tnl_id_pool, tid, id);
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
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = tnl_id_alloc,
    .id_free = tnl_id_free,
    .data_size = 2 * sizeof(struct flow_tnl),
};

static void
get_tnl_masked(struct flow_tnl *dst_key, struct flow_tnl *dst_mask,
               struct flow_tnl *src_key, struct flow_tnl *src_mask)
{
    char *psrc_key;
    char *pdst_key, *pdst_mask;
    int i;

    if (dst_mask) {
        memcpy(dst_mask, src_mask, sizeof *dst_mask);
        memset(&dst_mask->metadata, 0, sizeof dst_mask->metadata);

        pdst_key = (char *)dst_key;
        psrc_key = (char *)src_key;
        pdst_mask = (char *)dst_mask;
        for (i = 0; i < sizeof *dst_key; i++) {
            *pdst_key++ = *psrc_key++ & *pdst_mask++;
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
    return get_context_data_id_by_data(&tnl_md, &tnl_ctx, NULL, tnl_id);
}

static void
put_tnl_id(uint32_t tnl_id)
{
    put_context_data_by_id(&tnl_md, NULL, tnl_id);
}

struct flow_miss_ctx {
    odp_port_t vport;
    uint32_t recirc_id;
    struct flow_tnl tnl;
    uint8_t skip_actions;
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

static uint32_t
flow_miss_id_alloc(void *arg OVS_UNUSED)
{
    return netdev_offload_flow_mark_alloc();
}

static void
flow_miss_id_free(const void *arg OVS_UNUSED, uint32_t id)
{
    netdev_offload_flow_mark_free(id);
}

static struct context_metadata flow_miss_ctx_md = {
    .name = "flow_miss_ctx",
    .dump_context_data = dump_flow_ctx_id,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .associated_i2d_map = CMAP_INITIALIZER,
    .has_associated_map = true,
    .id_alloc = flow_miss_id_alloc,
    .id_free = flow_miss_id_free,
    .data_size = sizeof(struct flow_miss_ctx),
    .delayed_release = true,
};

static int
get_flow_miss_ctx_id(struct flow_miss_ctx *flow_ctx_data,
                     uint32_t *miss_ctx_id)
{
    struct context_data flow_ctx = {
        .data = flow_ctx_data,
    };

    return get_context_data_id_by_data(&flow_miss_ctx_md, &flow_ctx, NULL,
                                       miss_ctx_id);
}

static void
put_flow_miss_ctx_id(uint32_t flow_ctx_id)
{
    put_context_data_by_id(&flow_miss_ctx_md, NULL, flow_ctx_id);
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

struct shared_age_ctx_data {
    uint16_t domain_id;
    struct rte_flow_action_handle *action_hdl;
};

static struct ds *
dump_shared_age_ctx(struct ds *s, void *data)
{
    struct shared_age_ctx_data *shared_age_ctx_data =
        (struct shared_age_ctx_data *) data;

    ds_put_format(s, "domain_id=%"PRIu16", action_hdl=%p",
                  shared_age_ctx_data->domain_id,
                  shared_age_ctx_data->action_hdl);
    return s;
}

static struct context_metadata shared_age_ctx_md = {
    .name = "shared_age_ctx",
    .dump_context_data = dump_shared_age_ctx,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .associated_i2d_map = CMAP_INITIALIZER,
    .has_associated_map = true,
    .data_size = sizeof(struct shared_age_ctx_data),
};

static struct ds *
dump_shared_age_id(struct ds *s, void *data)
{
    uintptr_t shared_age_key = *(uintptr_t *) data;

    ds_put_format(s, "shared_age_key=0x%"PRIxPTR, shared_age_key);
    return s;
}

#define MIN_SHARED_AGE_ID     1
#define MAX_SHARED_AGE_ID     (UINT32_MAX - 2)

static struct seq_pool *shared_age_id_pool = NULL;

static uint32_t
shared_age_id_alloc(void *arg)
{
    static struct ovsthread_once shared_age_id_init = OVSTHREAD_ONCE_INITIALIZER;
    struct shared_age_ctx_data shared_age_ctx_data;
    unsigned int tid = netdev_offload_thread_id();
    struct rte_flow_action_age age_conf = {
        .timeout = 0xFFFFFF,
    };
    struct context_data shared_age_ctx;
    struct rte_flow_action action = {
        .type = RTE_FLOW_ACTION_TYPE_AGE,
        .conf = &age_conf,
    };
    struct rte_flow_error error;
    uint32_t shared_age_id;
    struct netdev *netdev;

    netdev = (struct netdev *) arg;
    /* A NULL ID maybe be received from ct_counter_query. This should not
     * create an ID.
     * For vports, we offload on all PFs, so we might try to offload this on
     * the "wrong" PF, which is not of the relevant VF REP, then we would have
     * used a shared action between different switch domain, which is not
     * allowed.
     * To handle it, we will create the ID only for VF REPs, where we know
     * the domain ID, and for uplinks we will find the one created by the VF
     * REP.
     */
    if (netdev == NULL || netdev_dpdk_is_uplink_port(netdev)) {
        return 0;
    }

    if (ovsthread_once_start(&shared_age_id_init)) {
        shared_age_id_pool = seq_pool_create(netdev_offload_thread_nb(),
                                             MIN_SHARED_AGE_ID,
                                             MAX_SHARED_AGE_ID);
        ovsthread_once_done(&shared_age_id_init);
    }
    if (!seq_pool_new_id(shared_age_id_pool, tid, &shared_age_id)) {
        return 0;
    }

    shared_age_ctx_data.action_hdl =
        netdev_dpdk_indirect_action_create(netdev, &action, &error);
    if (!shared_age_ctx_data.action_hdl) {
        goto deallocate_id;
    }
    shared_age_ctx_data.domain_id = netdev_dpdk_get_domain_id_by_netdev(netdev);
    shared_age_ctx.data = &shared_age_ctx_data;
    shared_age_ctx.id = shared_age_id;
    if (associate_id_data(&shared_age_ctx_md, &shared_age_ctx)) {
        goto associate_err;
    }
    return shared_age_id;

associate_err:
    netdev_dpdk_indirect_action_destroy(netdev,
                                        shared_age_ctx_data.action_hdl,
                                        &error);
deallocate_id:
    seq_pool_free_id(shared_age_id_pool, tid, shared_age_id);
    return 0;
}

static void
shared_age_id_free(const void *arg OVS_UNUSED, uint32_t shared_age_id)
{
    struct shared_age_ctx_data shared_age_ctx_data;
    unsigned int tid = netdev_offload_thread_id();
    struct rte_flow_error error;
    struct netdev *netdev;

    seq_pool_free_id(shared_age_id_pool, tid, shared_age_id);
    if (get_context_data_by_id(&shared_age_ctx_md, shared_age_id,
                               &shared_age_ctx_data)) {
        return;
    }

    netdev = netdev_dpdk_get_netdev_by_domain_id(shared_age_ctx_data.domain_id);
    if (!netdev) {
        return;
    }
    netdev_dpdk_indirect_action_destroy(netdev,
                                        shared_age_ctx_data.action_hdl,
                                        &error);
    netdev_close(netdev);
    disassociate_id_data(&shared_age_ctx_md, shared_age_id);
}

static struct context_metadata shared_age_id_md = {
    .name = "shared_age_id",
    .dump_context_data = dump_shared_age_id,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = shared_age_id_alloc,
    .id_free = shared_age_id_free,
    .data_size = sizeof(uintptr_t),
};

static int
get_shared_age_id(struct netdev *netdev,
                  uintptr_t app_counter_key,
                  uint32_t *shared_age_id,
                  struct rte_flow_action_handle **action_hdl)
{
    struct shared_age_ctx_data shared_age_ctx_data;
    struct context_data shared_age_id_ctx = {
        .data = &app_counter_key,
    };
    uint16_t netdev_domain_id;
    int ret;

    if (get_context_data_id_by_data(&shared_age_id_md, &shared_age_id_ctx,
                                    netdev, shared_age_id)) {
        return -1;
    }

    ret = get_context_data_by_id(&shared_age_ctx_md, *shared_age_id,
                                 &shared_age_ctx_data);
    if (ret) {
        goto out;
    }

    netdev_domain_id = netdev_dpdk_get_domain_id_by_netdev(netdev);
    if (shared_age_ctx_data.domain_id != netdev_domain_id) {
        ret = -1;
        goto out;
    }

    *action_hdl = shared_age_ctx_data.action_hdl;
out:
    if (ret) {
        put_context_data_by_id(&shared_age_id_md, NULL, *shared_age_id);
    }
    return ret;
}

static void
put_shared_age_id(uint32_t shared_age_id)
{
    put_context_data_by_id(&shared_age_id_md, NULL, shared_age_id);
}

static struct ds *
dump_counter_id(struct ds *s, void *data)
{
    struct flows_counter_key *key = (struct flows_counter_key *) data;
    char buffer[OFFLOAD_FLOWS_COUNTER_KEY_STRING_SIZE];

    netdev_flow_counter_key_to_string(key, buffer, sizeof buffer);
    ds_put_format(s, "counter_id_key=%s", buffer);
    return s;
}

#define MIN_COUNTER_ID       1U
#define NUM_COUNTER_IDS      (UINT32_MAX - 2U)

static struct seq_pool *counter_id_pool;

static uint32_t
counter_id_alloc(void *arg OVS_UNUSED)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t counter_id;

    if (ovsthread_once_start(&once)) {
        counter_id_pool = seq_pool_create(netdev_offload_thread_nb(),
                                          MIN_COUNTER_ID, NUM_COUNTER_IDS);
        ovsthread_once_done(&once);
    }

    if (OVS_LIKELY(seq_pool_new_id(counter_id_pool, tid, &counter_id))) {
        return counter_id;
    }
    return 0;
}

static void
counter_id_free(const void *arg OVS_UNUSED, uint32_t counter_id)
{
    unsigned int tid = netdev_offload_thread_id();

    seq_pool_free_id(counter_id_pool, tid, counter_id);
}

static struct context_metadata counter_id_md = {
    .name = "counter_id",
    .dump_context_data = dump_counter_id,
    .maps_lock = OVS_MUTEX_INITIALIZER,
    .d2i_map = CMAP_INITIALIZER,
    .i2d_map = CMAP_INITIALIZER,
    .id_alloc = &counter_id_alloc,
    .id_free = &counter_id_free,
    .data_size = sizeof(struct flows_counter_key),
};

static int
get_ct_counter_id(uintptr_t ctid_key, uint32_t *ct_id)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    struct flows_counter_key counter_id_key = { .ptr_key = ctid_key, };
    struct context_data ct_id_ctx = {
        .data = &counter_id_key,
    };

    if (ovsthread_once_start(&init_once)) {
        /* Disable shrinking on CT counter CMAPs.
         * Otherwise they might re-expand afterward, adding latency
         * jitter. */
        cmap_set_min_load(&counter_id_md.d2i_map, 0.0);
        cmap_set_min_load(&counter_id_md.i2d_map, 0.0);
        ovsthread_once_done(&init_once);
    }

    return get_context_data_id_by_data(&counter_id_md, &ct_id_ctx, NULL,
                                       ct_id);
}

static void
put_ct_counter_id(uint32_t ct_id)
{
    put_context_data_by_id(&counter_id_md, NULL, ct_id);
}

static int
get_flows_counter_id(struct flows_counter_key *counter_key,
                     uint32_t *counter_id)
{
    struct context_data ct_id_ctx = {
        .data = counter_key,
    };

    return get_context_data_id_by_data(&counter_id_md, &ct_id_ctx, NULL,
                                       counter_id);
}

static void
put_flows_counter_id(uint32_t counter_id)
{
    put_context_data_by_id(&counter_id_md, NULL, counter_id);
}

static void
put_action_resources(struct netdev *netdev,
                     struct act_resources *act_resources)
{
    const char *devargs = netdev_dpdk_get_port_devargs(netdev);

    put_table_id(devargs, act_resources->self_table_id);
    put_table_id(devargs, act_resources->next_table_id);
    put_flow_miss_ctx_id(act_resources->flow_miss_ctx_id);
    put_tnl_id(act_resources->tnl_id);
    put_table_id(NULL, act_resources->ct_table_id);
    put_table_id(NULL, act_resources->post_ct_table_id);
    if (act_resources->associated_flow_id) {
        disassociate_flow_id(act_resources->flow_id);
    }
    put_ct_ctx_id(act_resources->ct_miss_ctx_id);
    put_table_id(NULL, act_resources->ct_nat_table_id);
    put_zone_id(act_resources->ct_match_zone_id);
    put_zone_id(act_resources->ct_action_zone_id);
    put_label_id(act_resources->ct_match_label_id);
    put_label_id(act_resources->ct_action_label_id);
    put_shared_age_id(act_resources->ct_shared_age_id);
    put_ct_counter_id(act_resources->ctid);
    put_flows_counter_id(act_resources->counter_id);
    put_sflow_id(act_resources->sflow_id);
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
dump_flow_attr(struct ds *s, const struct rte_flow_attr *attr)
{
    ds_put_format(s, "%s%spriority %"PRIu32" group %"PRIu32" %s",
                  attr->ingress  ? "ingress " : "",
                  attr->egress   ? "egress " : "", attr->priority, attr->group,
                  attr->transfer ? "transfer " : "");
}

/* Adds one pattern item 'field' with the 'mask' to dynamic string 's' using
 * 'testpmd command'-like format. */
#define DUMP_PATTERN_ITEM(mask, last, field, fmt, spec_pri, mask_pri, last_pri) \
    if (last) { \
        ds_put_format(s, field " spec " fmt " " field " mask " fmt " " field \
                      " last " fmt " ", spec_pri, mask_pri, last_pri); \
    } else if (is_all_ones(&mask, sizeof mask)) { \
        ds_put_format(s, field " is " fmt " ", spec_pri); \
    } else if (!is_all_zeros(&mask, sizeof mask)) { \
        ds_put_format(s, field " spec " fmt " " field " mask " fmt " ", \
                      spec_pri, mask_pri); \
    }

static void
dump_flow_pattern(struct ds *s, const struct rte_flow_item *item)
{
    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;
        uint8_t ea[ETH_ADDR_LEN];

        ds_put_cstr(s, "eth ");
        if (eth_spec) {
            uint32_t has_vlan_mask;

            if (!eth_mask) {
                eth_mask = &rte_flow_item_eth_mask;
            }
            DUMP_PATTERN_ITEM(eth_mask->src, NULL, "src", ETH_ADDR_FMT,
                              ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                              ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                              ETH_ADDR_BYTES_ARGS(ea));
            DUMP_PATTERN_ITEM(eth_mask->dst, NULL, "dst", ETH_ADDR_FMT,
                              ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                              ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                              ETH_ADDR_BYTES_ARGS(ea));
            DUMP_PATTERN_ITEM(eth_mask->type, NULL, "type", "0x%04"PRIx16,
                              ntohs(eth_spec->type),
                              ntohs(eth_mask->type), 0);
            has_vlan_mask = eth_mask->has_vlan ? UINT32_MAX : 0;
            DUMP_PATTERN_ITEM(has_vlan_mask, NULL, "has_vlan", "%d",
                              eth_spec->has_vlan, eth_mask->has_vlan, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        ds_put_cstr(s, "vlan ");
        if (vlan_spec) {
            if (!vlan_mask) {
                vlan_mask = &rte_flow_item_vlan_mask;
            }
            DUMP_PATTERN_ITEM(vlan_mask->inner_type, NULL, "inner_type",
                              "0x%"PRIx16, ntohs(vlan_spec->inner_type),
                              ntohs(vlan_mask->inner_type), 0);
            DUMP_PATTERN_ITEM(vlan_mask->tci, NULL, "tci", "0x%"PRIx16,
                              ntohs(vlan_spec->tci), ntohs(vlan_mask->tci), 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;
        const struct rte_flow_item_ipv4 *ipv4_last = item->last;

        ds_put_cstr(s, "ipv4 ");
        if (ipv4_spec) {
            uint16_t fragment_offset_mask;

            if (!ipv4_mask) {
                ipv4_mask = &rte_flow_item_ipv4_mask;
            }
            if (!ipv4_last) {
                ipv4_last = &rte_flow_item_ipv4_mask;
            }
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.src_addr, NULL, "src", IP_FMT,
                              IP_ARGS(ipv4_spec->hdr.src_addr),
                              IP_ARGS(ipv4_mask->hdr.src_addr), IP_ARGS(0));
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.dst_addr, NULL, "dst", IP_FMT,
                              IP_ARGS(ipv4_spec->hdr.dst_addr),
                              IP_ARGS(ipv4_mask->hdr.dst_addr), IP_ARGS(0));
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.next_proto_id, NULL, "proto",
                              "0x%"PRIx8, ipv4_spec->hdr.next_proto_id,
                              ipv4_mask->hdr.next_proto_id, 0);
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.type_of_service, NULL, "tos",
                              "0x%"PRIx8, ipv4_spec->hdr.type_of_service,
                              ipv4_mask->hdr.type_of_service, 0);
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.time_to_live, NULL, "ttl",
                              "0x%"PRIx8, ipv4_spec->hdr.time_to_live,
                              ipv4_mask->hdr.time_to_live, 0);
            fragment_offset_mask = ipv4_mask->hdr.fragment_offset ==
                                   htons(RTE_IPV4_HDR_OFFSET_MASK |
                                         RTE_IPV4_HDR_MF_FLAG)
                                   ? UINT16_MAX
                                   : ipv4_mask->hdr.fragment_offset;
            DUMP_PATTERN_ITEM(fragment_offset_mask, item->last,
                              "fragment_offset", "0x%"PRIx16,
                              ipv4_spec->hdr.fragment_offset,
                              ipv4_mask->hdr.fragment_offset,
                              ipv4_last->hdr.fragment_offset);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(s, "udp ");
        if (udp_spec) {
            if (!udp_mask) {
                udp_mask = &rte_flow_item_udp_mask;
            }
            DUMP_PATTERN_ITEM(udp_mask->hdr.src_port, NULL, "src", "%"PRIu16,
                              ntohs(udp_spec->hdr.src_port),
                              ntohs(udp_mask->hdr.src_port), 0);
            DUMP_PATTERN_ITEM(udp_mask->hdr.dst_port, NULL, "dst", "%"PRIu16,
                              ntohs(udp_spec->hdr.dst_port),
                              ntohs(udp_mask->hdr.dst_port), 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        ds_put_cstr(s, "sctp ");
        if (sctp_spec) {
            if (!sctp_mask) {
                sctp_mask = &rte_flow_item_sctp_mask;
            }
            DUMP_PATTERN_ITEM(sctp_mask->hdr.src_port, NULL, "src", "%"PRIu16,
                              ntohs(sctp_spec->hdr.src_port),
                              ntohs(sctp_mask->hdr.src_port), 0);
            DUMP_PATTERN_ITEM(sctp_mask->hdr.dst_port, NULL, "dst", "%"PRIu16,
                              ntohs(sctp_spec->hdr.dst_port),
                              ntohs(sctp_mask->hdr.dst_port), 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        ds_put_cstr(s, "icmp ");
        if (icmp_spec) {
            if (!icmp_mask) {
                icmp_mask = &rte_flow_item_icmp_mask;
            }
            DUMP_PATTERN_ITEM(icmp_mask->hdr.icmp_type, NULL, "icmp_type",
                              "%"PRIu8, icmp_spec->hdr.icmp_type,
                              icmp_mask->hdr.icmp_type, 0);
            DUMP_PATTERN_ITEM(icmp_mask->hdr.icmp_code, NULL, "icmp_code",
                              "%"PRIu8, icmp_spec->hdr.icmp_code,
                              icmp_mask->hdr.icmp_code, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        ds_put_cstr(s, "tcp ");
        if (tcp_spec) {
            if (!tcp_mask) {
                tcp_mask = &rte_flow_item_tcp_mask;
            }
            DUMP_PATTERN_ITEM(tcp_mask->hdr.src_port, NULL, "src", "%"PRIu16,
                              ntohs(tcp_spec->hdr.src_port),
                              ntohs(tcp_mask->hdr.src_port), 0);
            DUMP_PATTERN_ITEM(tcp_mask->hdr.dst_port, NULL, "dst", "%"PRIu16,
                              ntohs(tcp_spec->hdr.dst_port),
                              ntohs(tcp_mask->hdr.dst_port), 0);
            DUMP_PATTERN_ITEM(tcp_mask->hdr.tcp_flags, NULL, "flags",
                              "0x%"PRIx8, tcp_spec->hdr.tcp_flags,
                              tcp_mask->hdr.tcp_flags, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV6) {
        const struct rte_flow_item_ipv6 *ipv6_spec = item->spec;
        const struct rte_flow_item_ipv6 *ipv6_mask = item->mask;

        char addr_str[INET6_ADDRSTRLEN];
        char mask_str[INET6_ADDRSTRLEN];
        struct in6_addr addr, mask;

        ds_put_cstr(s, "ipv6 ");
        if (ipv6_spec) {
            uint8_t has_frag_ext_mask;

            if (!ipv6_mask) {
                ipv6_mask = &rte_flow_item_ipv6_mask;
            }
            memcpy(&addr, ipv6_spec->hdr.src_addr, sizeof addr);
            memcpy(&mask, ipv6_mask->hdr.src_addr, sizeof mask);
            ipv6_string_mapped(addr_str, &addr);
            ipv6_string_mapped(mask_str, &mask);
            DUMP_PATTERN_ITEM(mask, NULL, "src", "%s", addr_str, mask_str, "");

            memcpy(&addr, ipv6_spec->hdr.dst_addr, sizeof addr);
            memcpy(&mask, ipv6_mask->hdr.dst_addr, sizeof mask);
            ipv6_string_mapped(addr_str, &addr);
            ipv6_string_mapped(mask_str, &mask);
            DUMP_PATTERN_ITEM(mask, NULL, "dst", "%s", addr_str, mask_str, "");

            DUMP_PATTERN_ITEM(ipv6_mask->hdr.proto, NULL, "proto", "%"PRIu8,
                              ipv6_spec->hdr.proto, ipv6_mask->hdr.proto, 0);
            DUMP_PATTERN_ITEM(ipv6_mask->hdr.vtc_flow, NULL, "tc", "0x%"PRIx32,
                              ntohl(ipv6_spec->hdr.vtc_flow),
                              ntohl(ipv6_mask->hdr.vtc_flow), 0);
            DUMP_PATTERN_ITEM(ipv6_mask->hdr.hop_limits, NULL, "hop", "%"PRIu8,
                              ipv6_spec->hdr.hop_limits,
                              ipv6_mask->hdr.hop_limits, 0);
            has_frag_ext_mask = ipv6_mask->has_frag_ext ? UINT8_MAX : 0;
            DUMP_PATTERN_ITEM(has_frag_ext_mask, NULL, "has_frag_ext",
                              "%"PRIu8, ipv6_spec->has_frag_ext,
                              ipv6_mask->has_frag_ext, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT) {
        const struct rte_flow_item_ipv6_frag_ext *ipv6_frag_spec = item->spec;
        const struct rte_flow_item_ipv6_frag_ext *ipv6_frag_mask = item->mask;
        const struct rte_flow_item_ipv6_frag_ext *ipv6_frag_last = item->last;
        const struct rte_flow_item_ipv6_frag_ext ipv6_frag_def = {
            .hdr.next_header = 0, .hdr.frag_data = 0};

        ds_put_cstr(s, "ipv6_frag_ext ");
        if (ipv6_frag_spec) {
            if (!ipv6_frag_mask) {
                ipv6_frag_mask = &ipv6_frag_def;
            }
            if (!ipv6_frag_last) {
                ipv6_frag_last = &ipv6_frag_def;
            }
            DUMP_PATTERN_ITEM(ipv6_frag_mask->hdr.next_header, item->last,
                              "next_hdr", "%"PRIu8,
                              ipv6_frag_spec->hdr.next_header,
                              ipv6_frag_mask->hdr.next_header,
                              ipv6_frag_last->hdr.next_header);
            DUMP_PATTERN_ITEM(ipv6_frag_mask->hdr.frag_data, item->last,
                              "frag_data", "0x%"PRIx16,
                              ntohs(ipv6_frag_spec->hdr.frag_data),
                              ntohs(ipv6_frag_mask->hdr.frag_data),
                              ntohs(ipv6_frag_last->hdr.frag_data));
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_VXLAN) {
        const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
        const struct rte_flow_item_vxlan *vxlan_mask = item->mask;

        ds_put_cstr(s, "vxlan ");
        if (vxlan_spec) {
            if (!vxlan_mask) {
                vxlan_mask = &rte_flow_item_vxlan_mask;
            }
            DUMP_PATTERN_ITEM(vxlan_mask->vni, NULL, "vni", "%"PRIu32,
                              ntohl(*(ovs_be32 *)vxlan_spec->vni) >> 8,
                              ntohl(*(ovs_be32 *)vxlan_mask->vni) >> 8, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_TAG) {
        const struct rte_flow_item_tag *tag_spec = item->spec;
        const struct rte_flow_item_tag *tag_mask = item->mask;

        ds_put_cstr(s, "tag ");
        if (tag_spec) {
            if (!tag_mask) {
                tag_mask = &rte_flow_item_tag_mask;
            }
            DUMP_PATTERN_ITEM(tag_mask->index, NULL, "index", "%"PRIu8,
                              tag_spec->index, tag_mask->index, 0);
            DUMP_PATTERN_ITEM(tag_mask->data, NULL, "data", "0x%"PRIx32,
                              tag_spec->data, tag_mask->data, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_META) {
        const struct rte_flow_item_meta *meta_spec = item->spec;
        const struct rte_flow_item_meta *meta_mask = item->mask;

        ds_put_cstr(s, "meta ");
        if (meta_spec) {
            if (!meta_mask) {
                meta_mask = &rte_flow_item_meta_mask;
            }
            DUMP_PATTERN_ITEM(meta_mask->data, NULL, "data", "0x%"PRIx32,
                              meta_spec->data, meta_mask->data, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_MARK) {
        const struct rte_flow_item_mark *mark_spec = item->spec;
        const struct rte_flow_item_mark *mark_mask = item->mask;

        ds_put_cstr(s, "mark ");
        if (mark_spec) {
            ds_put_format(s, "id spec %d ", mark_spec->id);
        }
        if (mark_mask) {
            ds_put_format(s, "id mask %d ", mark_mask->id);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_GENEVE) {
         const struct rte_flow_item_geneve *gnv_spec = item->spec;
         const struct rte_flow_item_geneve *gnv_mask = item->mask;

         ds_put_cstr(s, "geneve ");
         if (gnv_spec) {
             if (!gnv_mask) {
                 gnv_mask = &rte_flow_item_geneve_mask;
             }
             DUMP_PATTERN_ITEM(gnv_mask->vni, NULL, "vni", "%"PRIu32,
                               ntohl(*(ovs_be32 *)gnv_spec->vni) >> 8,
                               ntohl(*(ovs_be32 *)gnv_mask->vni) >> 8, 0);
         }
         ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_GENEVE_OPT) {
         const struct rte_flow_item_geneve_opt *opt_spec = item->spec;
         const struct rte_flow_item_geneve_opt *opt_mask = item->mask;
         uint8_t len, len_mask;
         int i;

         ds_put_cstr(s, "geneve-opt ");
         if (opt_spec) {
             if (!opt_mask) {
                 opt_mask = &rte_flow_item_geneve_opt_mask;
             }
             DUMP_PATTERN_ITEM(opt_mask->option_class, NULL, "class",
                               "0x%"PRIx16, opt_spec->option_class,
                               opt_mask->option_class, 0);
             DUMP_PATTERN_ITEM(opt_mask->option_type, NULL, "type",
                               "0x%"PRIx8,opt_spec->option_type,
                               opt_mask->option_type, 0);
             len = opt_spec->option_len;
             len_mask = opt_mask->option_len;
             DUMP_PATTERN_ITEM(len_mask, NULL, "length", "0x%"PRIx8,
                               len, len_mask, 0);
             if (is_all_ones(opt_mask->data,
                             sizeof (uint32_t) * opt_spec->option_len)) {
                 ds_put_cstr(s, "data is 0x");
                 for (i = 0; i < opt_spec->option_len; i++) {
                     ds_put_format(s,"%"PRIx32"", htonl(opt_spec->data[i]));
                 }
             } else if (!is_all_zeros(opt_mask->data,
                         sizeof (uint32_t) * opt_spec->option_len)) {
                 ds_put_cstr(s, "data spec 0x");
                 for (i = 0; i < opt_spec->option_len; i++) {
                     ds_put_format(s,"%"PRIx32"", htonl(opt_spec->data[i]));
                 }
                 ds_put_cstr(s, "data mask 0x");
                 for (i = 0; i < opt_spec->option_len; i++) {
                     ds_put_format(s,"%"PRIx32"", htonl(opt_mask->data[i]));
                 }
             }
         }
         ds_put_cstr(s, "/ ");
     } else if (item->type == RTE_FLOW_ITEM_TYPE_GRE) {
        const struct rte_flow_item_gre *gre_spec = item->spec;
        const struct rte_flow_item_gre *gre_mask = item->mask;
        const struct rte_gre_hdr *greh_spec, *greh_mask;
        uint8_t c_bit_spec, c_bit_mask;
        uint8_t k_bit_spec, k_bit_mask;

        ds_put_cstr(s, "gre ");
        if (gre_spec) {
            if (!gre_mask) {
                gre_mask = &rte_flow_item_gre_mask;
            }
            greh_spec = (struct rte_gre_hdr *) gre_spec;
            greh_mask = (struct rte_gre_hdr *) gre_mask;

            c_bit_spec = greh_spec->c;
            c_bit_mask = greh_mask->c ? UINT8_MAX : 0;
            DUMP_PATTERN_ITEM(c_bit_mask, NULL, "c_bit", "%"PRIu8,
                              c_bit_spec, c_bit_mask, 0);

            k_bit_spec = greh_spec->k;
            k_bit_mask = greh_mask->k ? UINT8_MAX : 0;
            DUMP_PATTERN_ITEM(k_bit_mask, NULL, "k_bit", "%"PRIu8,
                              k_bit_spec, k_bit_mask, 0);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_GRE_KEY) {
        const rte_be32_t gre_mask = RTE_BE32(UINT32_MAX);
        const rte_be32_t *key_spec = item->spec;
        const rte_be32_t *key_mask = item->mask;

        ds_put_cstr(s, "gre_key ");
        if (key_spec) {
            if (!key_mask) {
                key_mask = &gre_mask;
            }
            DUMP_PATTERN_ITEM(*key_mask, NULL, "value", "%"PRIu32,
                              ntohl(*key_spec), ntohl(*key_mask), 0);
        }
        ds_put_cstr(s, "/ ");
    } else {
        ds_put_format(s, "unknown rte flow pattern (%d)\n", item->type);
    }
}

static void
dump_vxlan_encap(struct ds *s, const struct rte_flow_item *items)
{
    const struct rte_flow_item_eth *eth = NULL;
    const struct rte_flow_item_vlan *vlan = NULL;
    const struct rte_flow_item_ipv4 *ipv4 = NULL;
    const struct rte_flow_item_ipv6 *ipv6 = NULL;
    const struct rte_flow_item_udp *udp = NULL;
    const struct rte_flow_item_vxlan *vxlan = NULL;

    for (; items && items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
        if (items->type == RTE_FLOW_ITEM_TYPE_ETH) {
            eth = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_VLAN) {
            vlan = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_IPV4) {
            ipv4 = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_IPV6) {
            ipv6 = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_UDP) {
            udp = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_VXLAN) {
            vxlan = items->spec;
        }
    }

    ds_put_format(s, "set vxlan%s ip-version %s ",
                  vlan ? "-with-vlan" : "",
                  ipv4 ? "ipv4" : ipv6 ? "ipv6" : "ERR");
    if (vxlan) {
        ds_put_format(s, "vni %"PRIu32" ",
                      ntohl(*(ovs_be32 *) vxlan->vni) >> 8);
    }
    if (udp) {
        ds_put_format(s, "udp-src %"PRIu16" udp-dst %"PRIu16" ",
                      ntohs(udp->hdr.src_port), ntohs(udp->hdr.dst_port));
    }
    if (ipv4) {
        ds_put_format(s, "ip-src "IP_FMT" ip-dst "IP_FMT" ",
                      IP_ARGS(ipv4->hdr.src_addr),
                      IP_ARGS(ipv4->hdr.dst_addr));
    }
    if (ipv6) {
        struct in6_addr addr;

        ds_put_cstr(s, "ip-src ");
        memcpy(&addr, ipv6->hdr.src_addr, sizeof addr);
        ipv6_format_mapped(&addr, s);
        ds_put_cstr(s, " ip-dst ");
        memcpy(&addr, ipv6->hdr.dst_addr, sizeof addr);
        ipv6_format_mapped(&addr, s);
        ds_put_cstr(s, " ");
    }
    if (vlan) {
        ds_put_format(s, "vlan-tci 0x%"PRIx16" ", ntohs(vlan->tci));
    }
    if (eth) {
        ds_put_format(s, "eth-src "ETH_ADDR_FMT" eth-dst "ETH_ADDR_FMT,
                      ETH_ADDR_BYTES_ARGS(eth->src.addr_bytes),
                      ETH_ADDR_BYTES_ARGS(eth->dst.addr_bytes));
    }
}

static void
format_raw_encap(struct ds *s,
                 struct ds *s_extra,
                 const struct rte_flow_action_raw_encap *raw_encap)
{
    int i;

    ds_put_cstr(s, "raw_encap index 0 / ");
    if (raw_encap) {
        ds_put_format(s_extra, "Raw-encap size=%ld set raw_encap 0 raw "
                      "pattern is ", raw_encap->size);
        for (i = 0; i < raw_encap->size; i++) {
            ds_put_format(s_extra, "%02x", raw_encap->data[i]);
        }
        ds_put_cstr(s_extra, " / end_set;");
    }
}

enum ct_mode {
    CT_MODE_NONE,
    CT_MODE_CT,
    CT_MODE_CT_NAT,
    CT_MODE_CT_CONN,
};

enum tnl_type {
    TNL_TYPE_NONE,
    TNL_TYPE_VXLAN,
    TNL_TYPE_GENEVE,
    TNL_TYPE_GRE,
};

struct act_vars {
    enum ct_mode ct_mode;
    bool pre_ct_tuple_rewrite;
    struct nlattr *pre_ct_actions;
    uint8_t pre_ct_cnt;
    odp_port_t vport;
    uint32_t recirc_id;
    struct flow_tnl *tnl_key;
    struct flow_tnl tnl_mask;
    struct rte_flow_action_jump *jump;
    bool is_e2e_cache_flow;
    uintptr_t ct_counter_key;
    struct flows_counter_key flows_counter_key;
    enum tnl_type tnl_type;
    bool is_outer_ipv4;
    struct ds s_extra;
    uint8_t gnv_opts_cnt;
    bool is_pre_ct;
    bool is_ct_conn;
    rte_be16_t vlan_tpid;
    uint8_t vlan_pcp;
};

static void
dump_flow_action(struct ds *s, struct ds *s_extra,
                 const struct rte_flow_action *actions,
                 struct act_vars *act_vars)
{
    if (actions->type == RTE_FLOW_ACTION_TYPE_MARK) {
        const struct rte_flow_action_mark *mark = actions->conf;

        ds_put_cstr(s, "mark ");
        if (mark) {
            ds_put_format(s, "id %d ", mark->id);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RSS) {
        ds_put_cstr(s, "rss / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_COUNT) {
        const struct rte_flow_action_count *count = actions->conf;

        ds_put_cstr(s, "count ");
        if (count) {
            ds_put_format(s, "shared %d identifier %d ", count->shared,
                          count->id);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
        const struct rte_flow_action_port_id *port_id = actions->conf;

        ds_put_cstr(s, "port_id ");
        if (port_id) {
            ds_put_format(s, "original %d id %d ",
                          port_id->original, port_id->id);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_DROP) {
        ds_put_cstr(s, "drop / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
        const struct rte_flow_action_set_mac *set_mac = actions->conf;

        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_mac_%s ", dirstr);
        if (set_mac) {
            ds_put_format(s, "mac_addr "ETH_ADDR_FMT" ",
                          ETH_ADDR_BYTES_ARGS(set_mac->mac_addr));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST) {
        const struct rte_flow_action_set_ipv4 *set_ipv4 = actions->conf;
        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_ipv4_%s ", dirstr);
        if (set_ipv4) {
            ds_put_format(s, "ipv4_addr "IP_FMT" ",
                          IP_ARGS(set_ipv4->ipv4_addr));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TTL) {
        const struct rte_flow_action_set_ttl *set_ttl = actions->conf;

        ds_put_cstr(s, "set_ttl ");
        if (set_ttl) {
            ds_put_format(s, "ttl_value %d ", set_ttl->ttl_value);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST) {
        const struct rte_flow_action_set_tp *set_tp = actions->conf;
        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_tp_%s ", dirstr);
        if (set_tp) {
            ds_put_format(s, "port %"PRIu16" ", ntohs(set_tp->port));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN) {
        const struct rte_flow_action_of_push_vlan *of_push_vlan =
            actions->conf;

        ds_put_cstr(s, "of_push_vlan ");
        if (of_push_vlan) {
            ds_put_format(s, "ethertype 0x%"PRIx16" ",
                          ntohs(of_push_vlan->ethertype));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP) {
        const struct rte_flow_action_of_set_vlan_pcp *of_set_vlan_pcp =
            actions->conf;

        ds_put_cstr(s, "of_set_vlan_pcp ");
        if (of_set_vlan_pcp) {
            ds_put_format(s, "vlan_pcp %"PRIu8" ", of_set_vlan_pcp->vlan_pcp);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID) {
        const struct rte_flow_action_of_set_vlan_vid *of_set_vlan_vid =
            actions->conf;

        ds_put_cstr(s, "of_set_vlan_vid ");
        if (of_set_vlan_vid) {
            ds_put_format(s, "vlan_vid %"PRIu16" ",
                          ntohs(of_set_vlan_vid->vlan_vid));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_POP_VLAN) {
        ds_put_cstr(s, "of_pop_vlan / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST) {
        const struct rte_flow_action_set_ipv6 *set_ipv6 = actions->conf;

        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_ipv6_%s ", dirstr);
        if (set_ipv6) {
            ds_put_cstr(s, "ipv6_addr ");
            ipv6_format_addr((struct in6_addr *) &set_ipv6->ipv6_addr, s);
            ds_put_cstr(s, " ");
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
        const struct rte_flow_action_raw_encap *raw_encap = actions->conf;

        format_raw_encap(s, s_extra, raw_encap);
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
        const struct rte_flow_action_vxlan_encap *vxlan_encap = actions->conf;
        const struct rte_flow_item *items = vxlan_encap->definition;

        ds_put_cstr(s, "vxlan_encap / ");
        dump_vxlan_encap(s_extra, items);
        ds_put_cstr(s_extra, ";");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_JUMP) {
        const struct rte_flow_action_jump *jump = actions->conf;

        ds_put_cstr(s, "jump ");
        if (jump) {
            ds_put_format(s, "group %"PRIu32" ", jump->group);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP) {
        ds_put_cstr(s, "vxlan_decap / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_NVGRE_DECAP) {
        ds_put_cstr(s, "nvgre_decap / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TAG) {
        const struct rte_flow_action_set_tag *set_tag = actions->conf;

        ds_put_cstr(s, "set_tag ");
        if (set_tag) {
            ds_put_format(s, "index %u data 0x%08x mask 0x%08x ",
                          set_tag->index, set_tag->data, set_tag->mask);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_META) {
        const struct rte_flow_action_set_meta *meta = actions->conf;

        ds_put_cstr(s, "set_meta ");
        if (meta) {
            ds_put_format(s, "data 0x%08x mask 0x%08x ", meta->data,
                          meta->mask);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_INDIRECT) {
        ds_put_format(s, "INDIRECT %p ", actions->conf);
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RAW_DECAP) {
        const struct rte_flow_action_raw_decap *raw_decap = actions->conf;

        ds_put_cstr(s, "raw_decap index 0 / ");
        if (raw_decap) {
            ds_put_format(s_extra, "%s", ds_cstr(&act_vars->s_extra));
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SAMPLE) {
        const struct rte_flow_action_sample *sample = actions->conf;
        bool remote = false;

        if (sample) {
            const struct rte_flow_action *rte_actions;

            rte_actions = sample->actions;
            if (rte_actions->type == RTE_FLOW_ACTION_TYPE_END) {
                ds_put_cstr(s_extra, "set sample_actions 0 / ");
            }
            while (rte_actions &&
                   rte_actions->type != RTE_FLOW_ACTION_TYPE_END) {
                if (rte_actions->type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
                    format_raw_encap(s, s_extra, rte_actions->conf);
                    rte_actions++;
                    ds_put_cstr(s_extra,
                                " set sample_actions 0 raw_encap index 0 ");
                    remote = true;
                } else if (rte_actions->type ==
                           RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
                    const struct rte_flow_action_vxlan_encap *vxlan_encap =
                        rte_actions->conf;
                    const struct rte_flow_item *items =
                        vxlan_encap->definition;

                    rte_actions++;
                    dump_vxlan_encap(s_extra, items);
                    ds_put_cstr(s_extra, " set sample_actions"
                                " 0 vxlan_encap / ");
                    remote = true;
                } else if (!remote) {
                        ds_put_cstr(s_extra, "set sample_actions 0 ");
                }
                dump_flow_action(s_extra, s_extra,
                                 rte_actions++, act_vars);

            }
            ds_put_cstr(s_extra, "end;");
            ds_put_format(s, "sample ratio %d index 0 / ", sample->ratio);
        }
    } else {
        ds_put_format(s, "unknown rte flow action (%d)\n", actions->type);
    }
}

static struct ds *
dump_flow(struct ds *s, struct ds *s_extra,
          const struct rte_flow_attr *attr,
          const struct rte_flow_item *items,
          const struct rte_flow_action *actions,
          struct act_vars *act_vars)
{
    if (attr) {
        dump_flow_attr(s, attr);
    }
    ds_put_cstr(s, "pattern ");
    while (items && items->type != RTE_FLOW_ITEM_TYPE_END) {
        dump_flow_pattern(s, items++);
    }
    ds_put_cstr(s, "end actions ");
    while (actions && actions->type != RTE_FLOW_ACTION_TYPE_END) {
        dump_flow_action(s, s_extra, actions++, act_vars);
    }
    ds_put_cstr(s, "end");
    return s;
}

static int
create_rte_flow(struct netdev *netdev,
                const struct rte_flow_attr *attr,
                const struct rte_flow_item *items,
                const struct rte_flow_action *actions,
                struct rte_flow_error *error,
                struct flow_item *fi,
                int pos,
                struct act_vars *act_vars)
{
    struct ds s_extra = DS_EMPTY_INITIALIZER;
    struct ds s = DS_EMPTY_INITIALIZER;
    char *extra_str;

    fi->rte_flow[pos] = netdev_dpdk_rte_flow_create(netdev, attr, items,
                                                    actions, error);
    if (fi->rte_flow[pos]) {
        struct netdev_offload_dpdk_data *data;
        unsigned int tid = netdev_offload_thread_id();

        data = (struct netdev_offload_dpdk_data *)
            ovsrcu_get(void *, &netdev->hw_info.offload_data);
        if (data) {
            atomic_count_inc64(&data->rte_flow_counters[tid]);
        }
        if (!VLOG_DROP_DBG(&rl)) {
            dump_flow(&s, &s_extra, attr, items, actions, act_vars);
            extra_str = ds_cstr(&s_extra);
            VLOG_DBG_RL(&rl, "%s: rte_flow 0x%"PRIxPTR" %s  flow create %d %s",
                        netdev_get_name(netdev), (intptr_t) fi->rte_flow[pos],
                        extra_str, netdev_dpdk_get_port_id(netdev),
                        ds_cstr(&s));
        }
    } else {
        enum vlog_level level = VLL_WARN;

        if (error->type == RTE_FLOW_ERROR_TYPE_ACTION) {
            level = VLL_DBG;
        }
        VLOG_RL(&rl, level, "%s: rte_flow creation failed: %d (%s).",
                netdev_get_name(netdev), error->type, error->message);
        if (!vlog_should_drop(&this_module, level, &rl)) {
            dump_flow(&s, &s_extra, attr, items, actions, act_vars);
            extra_str = ds_cstr(&s_extra);
            VLOG_RL(&rl, level, "%s: Failed flow: %s  flow create %d %s",
                    netdev_get_name(netdev), extra_str,
                    netdev_dpdk_get_port_id(netdev), ds_cstr(&s));
        }
    }
    ds_destroy(&s);
    ds_destroy(&s_extra);
    return fi->rte_flow[pos] ? 0 : -1;
}

static int
netdev_offload_dpdk_destroy_flow(struct netdev *netdev,
                                 struct rte_flow *rte_flow,
                                 unsigned int creation_tid,
                                 const ovs_u128 *ufid);
static int
add_e2e_miss_flow(struct netdev *netdev,
                  const char *devargs,
                  uint32_t e2e_table_id,
                  uint32_t table_id,
                  struct act_vars *act_vars)
{
    struct rte_flow_item miss_items[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH, },
        { .type = RTE_FLOW_ITEM_TYPE_END, } };
    struct rte_flow_action_jump miss_jump = { .group = table_id, };
    const struct rte_flow_action miss_actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &miss_jump },
        { .type = RTE_FLOW_ACTION_TYPE_END, } };
    struct act_resources act_resources = { .flow_id = INVALID_FLOW_MARK };
    struct flows_handle flows = { .items = NULL, .cnt = 0 };
    struct flow_item flow_item = { .devargs = devargs };
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_attr attr = {
        .transfer = 1,
        .ingress = 1,
        .group = e2e_table_id,
        .priority = 1,
    };
    struct rte_flow_error error;
    ovs_u128 ufid;
    int ret;

    if (table_id_ufid(devargs, true, table_id, &ufid)) {
        return -1;
    }
    rte_flow_data = ufid_to_rte_flow_data_find(netdev, &ufid, false);
    if (rte_flow_data) {
        return 0;
    }

    ret = create_rte_flow(netdev, &attr, miss_items, miss_actions,
                          &error, &flow_item, 0, act_vars);
    if (ret) {
        return -1;
    }

    VLOG_DBG_RL(&rl, "%s: installed flow %p by ufid "UUID_FMT"\n",
                netdev_get_name(netdev), flow_item.rte_flow[0],
                UUID_ARGS((struct uuid *) &ufid));
    add_flow_item(&flows, &flow_item);
    if (!ufid_to_rte_flow_associate(&ufid, netdev, &flows, true,
                                    &act_resources, false)) {
        netdev_offload_dpdk_destroy_flow(netdev, flow_item.rte_flow[0],
                                         netdev_offload_thread_id(), &ufid);
        free_flow_handle(&flows, false);
    }
    return 0;
}

static int
add_miss_flow(struct netdev *netdev,
              const char *devargs,
              uint32_t table_id,
              uint32_t mark_id,
              struct act_vars *act_vars);

static struct rte_flow_action *
find_action(const struct rte_flow_action *actions,
            uint32_t type)
{
    while (actions && actions->type != RTE_FLOW_ACTION_TYPE_END) {
        if (actions->type == type) {
            return CONST_CAST(struct rte_flow_action *, actions);
         }
         actions++;
    }

    return NULL;
}

static int
create_offload_flow(struct netdev *netdev,
                    const uint32_t group_id,
                    const struct rte_flow_item *items,
                    const struct rte_flow_action *actions,
                    struct rte_flow_error *error,
                    struct act_resources *act_resources,
                    struct act_vars *act_vars,
                    struct flow_item *fi,
                    int pos)
{
    struct rte_flow_action *indirect_action;
    struct rte_flow_attr attr = {
        .transfer = 1,
        .ingress = 1,
        .group = group_id,
    };
    uint32_t self_table_id = 0;
    uint32_t next_table_id = 0;
    uint16_t phys_port;
    int ret = -1;

    if (act_vars->jump && act_resources->sflow_id) {
        /* Reject flows with sample and jump actions */
        VLOG_DBG_RL(&rl, "cannot offload sFlow with jump");
        return -1;
    }
    phys_port = netdev_dpdk_get_port_id(netdev);
    fi->devargs = netdev_dpdk_get_port_devargs(netdev);
    if (act_vars->ct_mode == CT_MODE_NONE ||
        (group_id == 0 && (act_vars->ct_mode == CT_MODE_CT ||
                           act_vars->ct_mode == CT_MODE_CT_NAT))) {
        if (get_table_id(phys_port, act_vars->vport, act_vars->recirc_id,
                         TABLE_TYPE_FLOW, act_vars->is_e2e_cache_flow,
                         &self_table_id)) {
            return -1;
        }
        attr.group = self_table_id;

        if (netdev_is_e2e_cache_enabled() && !act_vars->is_e2e_cache_flow &&
            act_vars->recirc_id == 0) {
            if (get_table_id(phys_port, act_vars->vport, 0, TABLE_TYPE_FLOW,
                true, &fi->self_e2e_table_id)) {
                goto err;
            }
            if (add_e2e_miss_flow(netdev, fi->devargs, fi->self_e2e_table_id,
                                  self_table_id, act_vars)) {
                goto err;
            }
        }
    }
    if (!act_vars->is_pre_ct && act_resources->flow_miss_ctx_id) {
        struct flow_miss_ctx flow_miss_ctx;

        if (find_flow_miss_ctx(act_resources->flow_miss_ctx_id,
                               &flow_miss_ctx)) {
            goto err;
        }
        if (get_table_id(phys_port, flow_miss_ctx.vport,
                         flow_miss_ctx.recirc_id, TABLE_TYPE_FLOW,
                         act_vars->is_e2e_cache_flow, &next_table_id)) {
            goto err;
        }
        if (netdev_is_e2e_cache_enabled() && !act_vars->is_e2e_cache_flow) {
            if (flow_miss_ctx.recirc_id == 0) {
                if (get_table_id(phys_port, flow_miss_ctx.vport, 0,
                                 TABLE_TYPE_FLOW, true,
                                 &fi->next_e2e_table_id)) {
                    goto err;
                }
                if (add_e2e_miss_flow(netdev, fi->devargs,
                                      fi->next_e2e_table_id,
                                      next_table_id, act_vars)) {
                    goto err;
                }
            }
        }
        if (add_miss_flow(netdev, fi->devargs, next_table_id,
                          act_resources->flow_miss_ctx_id, act_vars)) {
            goto err;
        }
        act_vars->jump->group = fi->next_e2e_table_id ? fi->next_e2e_table_id
                                                      : next_table_id;
    }
    indirect_action = find_action(actions, RTE_FLOW_ACTION_TYPE_INDIRECT);
    if (indirect_action) {
        struct rte_flow_action_handle *action_hdl = NULL;
        uint32_t ct_shared_age_id;

        if (get_shared_age_id(netdev, act_vars->ct_counter_key,
                              &ct_shared_age_id, &action_hdl)) {
            goto err;
        }
        if (!act_resources->ct_shared_age_id) {
            act_resources->ct_shared_age_id = ct_shared_age_id;
        } else {
            put_shared_age_id(ct_shared_age_id);
        }
        indirect_action->conf = action_hdl;
    }
    ret = create_rte_flow(netdev, &attr, items, actions,
                          error, fi, pos, act_vars);
    if (indirect_action) {
        indirect_action->conf = NULL;
    }
    if (ret) {
        goto err;
    }
    if (self_table_id) {
        fi->self_table_id = self_table_id;
        act_resources->self_table_id = 0;
    }
    if (next_table_id) {
        fi->next_table_id = next_table_id;
        act_resources->next_table_id = 0;
    }
    return 0;

err:
    if (self_table_id) {
        put_table_id(fi->devargs, self_table_id);
    }
    if (next_table_id) {
        put_table_id(fi->devargs, next_table_id);
    }
    if (fi->self_e2e_table_id) {
        put_table_id(fi->devargs, fi->self_e2e_table_id);
    }
    if (fi->next_e2e_table_id) {
        put_table_id(fi->devargs, fi->next_e2e_table_id);
    }
    return -1;
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask, const void *last)
{
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = per_thread_xcalloc(patterns->current_max,
                                             sizeof *patterns->items);
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = per_thread_xrealloc(patterns->items,
                                              patterns->current_max / 2 *
                                              sizeof *patterns->items,
                                              patterns->current_max *
                                              sizeof *patterns->items);
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = last;
    patterns->cnt++;
}

static struct rte_flow_action *
add_flow_action(struct flow_actions *actions, enum rte_flow_action_type type,
                const void *conf)
{
    int cnt = actions->cnt;

    if (cnt == 0) {
        actions->current_max = 8;
        actions->actions = per_thread_xcalloc(actions->current_max,
                                              sizeof *actions->actions);
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = per_thread_xrealloc(actions->actions,
                                               actions->current_max / 2 *
                                               sizeof *actions->actions,
                                               actions->current_max *
                                               sizeof *actions->actions);
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
    return &actions->actions[cnt];
}

static void
free_flow_patterns(struct flow_patterns *patterns)
{
    int i;

    for (i = 0; i < patterns->cnt; i++) {
        if (patterns->items[i].spec) {
            per_thread_free(CONST_CAST(void *, patterns->items[i].spec));
        }
        if (patterns->items[i].mask) {
            per_thread_free(CONST_CAST(void *, patterns->items[i].mask));
        }
        if (patterns->items[i].last) {
            per_thread_free(CONST_CAST(void *, patterns->items[i].last));
        }
    }
    per_thread_free(patterns->items);
    patterns->items = NULL;
    patterns->cnt = 0;
}

static void
free_flow_actions(struct flow_actions *actions, bool free_confs)
{
    int i;

    for (i = 0; free_confs && i < actions->cnt; i++) {
        if (actions->actions[i].conf) {
            per_thread_free(CONST_CAST(void *, actions->actions[i].conf));
        }
    }
    per_thread_free(actions->actions);
    actions->actions = NULL;
    actions->cnt = 0;
}

static int
netdev_offload_dpdk_destroy_flow(struct netdev *netdev,
                                 struct rte_flow *rte_flow,
                                 unsigned int creation_tid,
                                 const ovs_u128 *ufid)
{
    struct uuid ufid0 = UUID_ZERO;
    struct rte_flow_error error;
    int ret;

    ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);
    if (!ret) {
        struct netdev_offload_dpdk_data *data;

        data = (struct netdev_offload_dpdk_data *)
            ovsrcu_get(void *, &netdev->hw_info.offload_data);
        if (data) {
            atomic_count_dec64(&data->rte_flow_counters[creation_tid]);
        }

        VLOG_DBG("%s: removed rte flow %p associated with ufid "UUID_FMT,
                 netdev_get_name(netdev), rte_flow,
                 UUID_ARGS(ufid ? (struct uuid *)ufid : &ufid0));
    } else {
        VLOG_ERR("%s: Failed to destroy flow: %s (%u)",
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

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

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

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask, NULL);
    } else if (!is_all_zeros(&match->wc.masks.tunnel.ipv6_src,
                             sizeof(struct in6_addr)) ||
               !is_all_zeros(&match->wc.masks.tunnel.ipv6_dst,
                             sizeof(struct in6_addr))) {
        /* IP v6 */
        struct rte_flow_item_ipv6 *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

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

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6, spec, mask, NULL);
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

    spec = per_thread_xzalloc(sizeof *spec);
    mask = per_thread_xzalloc(sizeof *mask);

    spec->hdr.src_port = match->flow.tunnel.tp_src;
    spec->hdr.dst_port = match->flow.tunnel.tp_dst;

    mask->hdr.src_port = match->wc.masks.tunnel.tp_src;
    mask->hdr.dst_port = match->wc.masks.tunnel.tp_dst;

    consumed_masks->tunnel.tp_src = 0;
    consumed_masks->tunnel.tp_dst = 0;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask, NULL);
}

static int
parse_vxlan_match(struct flow_patterns *patterns,
                  struct match *match)
{
    struct rte_flow_item_vxlan *vx_spec, *vx_mask;
    struct flow *consumed_masks;
    int ret;

    ret = parse_tnl_ip_match(patterns, match, IPPROTO_UDP);
    if (ret) {
        return -1;
    }
    parse_tnl_udp_match(patterns, match);

    consumed_masks = &match->wc.masks;
    /* VXLAN */
    vx_spec = per_thread_xzalloc(sizeof *vx_spec);
    vx_mask = per_thread_xzalloc(sizeof *vx_mask);

    put_unaligned_be32((ovs_be32 *)vx_spec->vni,
                       htonl(ntohll(match->flow.tunnel.tun_id) << 8));
    put_unaligned_be32((ovs_be32 *)vx_mask->vni,
                       htonl(ntohll(match->wc.masks.tunnel.tun_id) << 8));

    consumed_masks->tunnel.tun_id = 0;
    consumed_masks->tunnel.flags = 0;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VXLAN, vx_spec, vx_mask,
                     NULL);
    return 0;
}

static int
parse_gre_match(struct flow_patterns *patterns,
                struct match *match)
{
    struct rte_flow_item_gre *gre_spec, *gre_mask;
    struct rte_gre_hdr *greh_spec, *greh_mask;
    rte_be32_t *key_spec, *key_mask;
    struct flow *consumed_masks;
    int ret;


    ret = parse_tnl_ip_match(patterns, match, IPPROTO_GRE);
    if (ret) {
        return -1;
    }

    gre_spec = per_thread_xzalloc(sizeof *gre_spec);
    gre_mask = per_thread_xzalloc(sizeof *gre_mask);
    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_GRE, gre_spec,
                        gre_mask, NULL);

    consumed_masks = &match->wc.masks;

    greh_spec = (struct rte_gre_hdr *) gre_spec;
    greh_mask = (struct rte_gre_hdr *) gre_mask;

    if (match->wc.masks.tunnel.flags & FLOW_TNL_F_CSUM) {
        greh_spec->c = !!(match->flow.tunnel.flags & FLOW_TNL_F_CSUM);
        greh_mask->c = 1;
        consumed_masks->tunnel.flags &= ~FLOW_TNL_F_CSUM;
    }

    if (match->wc.masks.tunnel.flags & FLOW_TNL_F_KEY) {
        greh_spec->k = !!(match->flow.tunnel.flags & FLOW_TNL_F_KEY);
        greh_mask->k = 1;

        key_spec = per_thread_xzalloc(sizeof *key_spec);
        key_mask = per_thread_xzalloc(sizeof *key_mask);

        *key_spec = htonl(ntohll(match->flow.tunnel.tun_id));
        *key_mask = htonl(ntohll(match->wc.masks.tunnel.tun_id));

        consumed_masks->tunnel.tun_id = 0;
        consumed_masks->tunnel.flags &= ~FLOW_TNL_F_KEY;
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_GRE_KEY, key_spec,
                         key_mask, NULL);
    }

    consumed_masks->tunnel.flags &= ~FLOW_TNL_F_DONT_FRAGMENT;

    return 0;
}

static void
parse_geneve_opt_match(struct flow *consumed_masks,
                       struct flow_patterns *patterns,
                       struct match *match,
                       struct act_vars *act_vars)
{
    int len, opt_idx;
    uint8_t idx;
    struct geneve_opt curr_opt_spec, curr_opt_mask;
    struct gnv_opts {
        struct rte_flow_item_geneve_opt opts[TUN_METADATA_NUM_OPTS];
        uint32_t options_data[TUN_METADATA_NUM_OPTS];
    } *gnv_opts;
    BUILD_ASSERT_DECL(offsetof(struct gnv_opts, opts) == 0);
    struct gnv_opts_mask {
        struct rte_flow_item_geneve_opt opts_mask[TUN_METADATA_NUM_OPTS];
        uint32_t options_data_mask[TUN_METADATA_NUM_OPTS];
    } *gnv_opts_mask;
    BUILD_ASSERT_DECL(offsetof(struct gnv_opts_mask, opts_mask) == 0);

    len = match->flow.tunnel.metadata.present.len;
    idx = 0;
    opt_idx = 0;
    curr_opt_spec = match->flow.tunnel.metadata.opts.gnv[opt_idx];
    curr_opt_mask = match->wc.masks.tunnel.metadata.opts.gnv[opt_idx];

    if (!is_all_zeros(match->wc.masks.tunnel.metadata.opts.gnv,
                      sizeof *match->wc.masks.tunnel.metadata.opts.gnv) &&
        match->flow.tunnel.metadata.present.len) {
        while (len) {
            gnv_opts = per_thread_xzalloc(sizeof *gnv_opts);
            gnv_opts_mask = per_thread_xzalloc(sizeof *gnv_opts_mask);
            memcpy(&gnv_opts->opts[idx].option_class,
                   &curr_opt_spec.opt_class, sizeof curr_opt_spec.opt_class);
            memcpy(&gnv_opts_mask->opts_mask[idx].option_class,
                   &curr_opt_mask.opt_class,
                   sizeof curr_opt_mask.opt_class);

            gnv_opts->opts[idx].option_type = curr_opt_spec.type;
            gnv_opts_mask->opts_mask[idx].option_type = curr_opt_mask.type;

            gnv_opts->opts[idx].option_len = curr_opt_spec.length;
            gnv_opts_mask->opts_mask[idx].option_len = curr_opt_mask.length;

            /* According to the Geneve protocol
            * https://tools.ietf.org/html/draft-gross-geneve-00#section-3.1
            * Length (5 bits):  Length of the option, expressed in four byte
            * multiples excluding the option header
            * (tunnel.metadata.opts.gnv.length).
            * Opt Len (6 bits):  The length of the options fields, expressed
            * in four byte multiples, not including the eight byte
            * fixed tunnel header (tunnel.metadata.present.len).
            */
            opt_idx++;
            memcpy(&gnv_opts->options_data[opt_idx - 1],
                   &match->flow.tunnel.metadata.opts.gnv[opt_idx],
                   sizeof gnv_opts->options_data[opt_idx - 1] *
                   curr_opt_spec.length * 4);
            memcpy(&gnv_opts_mask->options_data_mask[opt_idx - 1],
                   &match->wc.masks.tunnel.metadata.opts.gnv[opt_idx],
                   sizeof gnv_opts_mask->options_data_mask[opt_idx - 1] *
                   curr_opt_spec.length * 4);

            gnv_opts->opts[opt_idx - 1].data = gnv_opts->options_data;
            gnv_opts_mask->opts_mask[opt_idx - 1].data =
            gnv_opts_mask->options_data_mask;

            add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_GENEVE_OPT,
                             &gnv_opts->opts[idx],
                             &gnv_opts_mask->opts_mask[idx], NULL);

            len -= sizeof(struct geneve_opt) + curr_opt_spec.length * 4;
            opt_idx += sizeof(struct geneve_opt) / 4 +
                curr_opt_spec.length - 1;
            idx++;
        }
        memset(&consumed_masks->tunnel.metadata.opts.gnv, 0,
               sizeof consumed_masks->tunnel.metadata.opts.gnv);
    }
    act_vars->gnv_opts_cnt = idx;
}

static int
parse_geneve_match(struct flow_patterns *patterns,
                   struct match *match,
                   struct act_vars *act_vars)
{
    struct rte_flow_item_geneve *gnv_spec, *gnv_mask;
    struct flow *consumed_masks;
    int ret;

    ret = parse_tnl_ip_match(patterns, match, IPPROTO_UDP);
    if (ret) {
        return -1;
    }

    parse_tnl_udp_match(patterns, match);

    consumed_masks = &match->wc.masks;
    /* GENEVE */
    gnv_spec = per_thread_xzalloc(sizeof *gnv_spec);
    gnv_mask = per_thread_xzalloc(sizeof *gnv_mask);

    put_unaligned_be32((ovs_be32 *)gnv_spec->vni,
                       htonl(ntohll(match->flow.tunnel.tun_id) << 8));
    put_unaligned_be32((ovs_be32 *)gnv_mask->vni,
                       htonl(ntohll(match->wc.masks.tunnel.tun_id) << 8));

    consumed_masks->tunnel.tun_id = 0;
    consumed_masks->tunnel.flags = 0;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_GENEVE, gnv_spec, gnv_mask,
                     NULL);
    parse_geneve_opt_match(consumed_masks, patterns, match, act_vars);

    /* tunnel.metadata.present.len value indicates the number of
     * options, it's mask does not indicate any match on the packet,
     * thus masked.
     */
    memset(&consumed_masks->tunnel.metadata.present, 0,
           sizeof consumed_masks->tunnel.metadata.present);

    return 0;
}

static int
parse_tnl_match(struct flow_patterns *patterns,
                struct match *match,
                struct netdev *netdev,
                struct act_vars *act_vars)
{
    if (is_all_zeros(&match->wc.masks.tunnel, sizeof match->wc.masks.tunnel)) {
        return 0;
    }

    if (!strcmp(netdev_get_type(netdev),"vxlan")) {
        act_vars->tnl_type = TNL_TYPE_VXLAN;
        return parse_vxlan_match(patterns, match);
    }
    if (!strcmp(netdev_get_type(netdev), "geneve")) {
        act_vars->tnl_type = TNL_TYPE_GENEVE;
        return parse_geneve_match(patterns, match, act_vars);
    }
    if (!strcmp(netdev_get_type(netdev), "gre") ||
        !strcmp(netdev_get_type(netdev), "ip6gre")) {
            act_vars->tnl_type = TNL_TYPE_GRE;
            return parse_gre_match(patterns, match);
    }

    return -1;
}

static int
get_packet_reg_field(struct dp_packet *packet, uint8_t reg_field_id,
                     uint32_t *val)
{
    struct reg_field *reg_field;
    uint32_t mark = 0;
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
        dp_packet_has_flow_mark(packet, &mark);
        VLOG_ERR_RL(&rl, "port %d, recirc=%d: packet reg field id %d is 0, mark=%d",
                    packet->md.in_port.odp_port, packet->md.recirc_id, reg_field_id, mark);
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
        tag_spec = per_thread_xzalloc(sizeof *tag_spec);
        tag_spec->index = reg_field->index;
        tag_spec->data = reg_spec;

        tag_mask = per_thread_xzalloc(sizeof *tag_mask);
        tag_mask->index = 0xFF;
        tag_mask->data = reg_mask;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TAG, tag_spec, tag_mask,
                         NULL);
        break;
    case REG_TYPE_META:
        meta_spec = per_thread_xzalloc(sizeof *meta_spec);
        meta_spec->data = reg_spec;

        meta_mask = per_thread_xzalloc(sizeof *meta_mask);
        meta_mask->data = reg_mask;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_META, meta_spec,
                         meta_mask, NULL);
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
        set_tag = per_thread_xzalloc(sizeof *set_tag);
        set_tag->index = reg_field->index;
        set_tag->data = reg_spec;
        set_tag->mask = reg_mask;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_TAG, set_tag);
        break;
    case REG_TYPE_META:
        set_meta = per_thread_xzalloc(sizeof *set_meta);
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
    struct rte_flow_item_eth *eth_spec = NULL, *eth_mask = NULL;
    struct flow *consumed_masks;
    uint8_t proto = 0;

    consumed_masks = &match->wc.masks;

    if (!flow_tnl_dst_is_set(&match->flow.tunnel)) {
        memset(&consumed_masks->tunnel, 0, sizeof consumed_masks->tunnel);
    }
    if (!is_nd(&match->flow, NULL)) {
        memset(&match->wc.masks.nd_target, 0,
               sizeof match->wc.masks.nd_target);
        if (!is_arp(&match->flow)) {
            memset(&match->wc.masks.arp_sha, 0,
                   sizeof match->wc.masks.arp_sha);
            memset(&match->wc.masks.arp_tha, 0,
                   sizeof match->wc.masks.arp_tha);
        }
        if (!is_igmp(&match->flow, NULL)) {
            match->wc.masks.igmp_group_ip4 = 0;
        }
    }

    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        act_vars->vport = match->flow.in_port.odp_port;
        act_vars->tnl_key = &match->flow.tunnel;
        act_vars->tnl_mask = match->wc.masks.tunnel;
        act_vars->is_outer_ipv4 = match->wc.masks.tunnel.ip_src ||
                                  match->wc.masks.tunnel.ip_dst;
        /* In case of a tunnel, pre-ct flow decapsulates the tunnel and sets
         * the tunnel info (matches) in a register. Following tunnel flows
         * (recirc_id>0) don't match the tunnel outer headers, as they are
         * already decapsulated, but on the tunnel info register.
         *
         * CT2CT is applied after a pre-ct flow, so tunnel match should be done
         * on the tunnel info register, as recirc_id>0 flows.
         */
        if ((match->flow.recirc_id ||
             (act_vars->is_e2e_cache_flow &&
              act_resources->flow_id != INVALID_FLOW_MARK)) &&
            parse_tnl_match_recirc(patterns, match, act_resources)) {
            return -1;
        }
        if (parse_tnl_match(patterns, match, netdev, act_vars)) {
            return -1;
        }
    } else {
        act_vars->tnl_type = TNL_TYPE_NONE;
    }

    act_vars->recirc_id = match->flow.recirc_id;
    memset(&consumed_masks->in_port, 0, sizeof consumed_masks->in_port);
    consumed_masks->recirc_id = 0;
    consumed_masks->packet_type = 0;

    /* Eth */
    if (act_vars->is_ct_conn) {
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL, NULL);
    } else if (match->wc.masks.dl_type ||
        !eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        struct rte_flow_item_eth *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

        memcpy(&spec->dst, &match->flow.dl_dst, sizeof spec->dst);
        memcpy(&spec->src, &match->flow.dl_src, sizeof spec->src);
        spec->type = match->flow.dl_type;

        memcpy(&mask->dst, &match->wc.masks.dl_dst, sizeof mask->dst);
        memcpy(&mask->src, &match->wc.masks.dl_src, sizeof mask->src);
        mask->type = match->wc.masks.dl_type;

        memset(&consumed_masks->dl_dst, 0, sizeof consumed_masks->dl_dst);
        memset(&consumed_masks->dl_src, 0, sizeof consumed_masks->dl_src);
        consumed_masks->dl_type = 0;

        spec->has_vlan = 0;
        mask->has_vlan = 1;
        eth_spec = spec;
        eth_mask = mask;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, spec, mask, NULL);
    }

    /* VLAN */
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        struct rte_flow_item_vlan *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

        spec->tci = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask->tci = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        if (eth_spec && eth_mask) {
            eth_spec->has_vlan = 1;
            eth_mask->has_vlan = 1;
            spec->inner_type = eth_spec->type;
            mask->inner_type = eth_mask->type;
            eth_spec->type = match->flow.vlans[0].tpid;
            eth_mask->type = match->wc.masks.vlans[0].tpid;
        }

        act_vars->vlan_tpid = match->flow.vlans[0].tpid;
        act_vars->vlan_pcp = vlan_tci_to_pcp(match->flow.vlans[0].tci);
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VLAN, spec, mask, NULL);
    }
    /* For untagged matching match->wc.masks.vlans[0].tci is 0xFFFF and
     * match->flow.vlans[0].tci is 0. Consuming is needed outside of the if
     * scope to handle that.
     */
    memset(&consumed_masks->vlans[0], 0, sizeof consumed_masks->vlans[0]);

    /* IP v4 */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        struct rte_flow_item_ipv4 *spec, *mask, *last = NULL;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

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

        if (match->wc.masks.nw_frag & FLOW_NW_FRAG_ANY) {
            if (!(match->flow.nw_frag & FLOW_NW_FRAG_ANY)) {
                /* frag=no */
                spec->hdr.fragment_offset = 0;
                mask->hdr.fragment_offset = htons(RTE_IPV4_HDR_OFFSET_MASK |
                                                  RTE_IPV4_HDR_MF_FLAG);
            } else if (match->wc.masks.nw_frag & FLOW_NW_FRAG_LATER) {
                if (!(match->flow.nw_frag & FLOW_NW_FRAG_LATER)) {
                    /* frag=first */
                    spec->hdr.fragment_offset = htons(RTE_IPV4_HDR_MF_FLAG);
                    mask->hdr.fragment_offset = htons(RTE_IPV4_HDR_OFFSET_MASK |
                                                      RTE_IPV4_HDR_MF_FLAG);
                } else {
                    /* frag=later */
                    last = per_thread_xzalloc(sizeof *last);
                    spec->hdr.fragment_offset = htons(1 << RTE_IPV4_HDR_FO_SHIFT);
                    mask->hdr.fragment_offset = htons(RTE_IPV4_HDR_OFFSET_MASK);
                    last->hdr.fragment_offset = htons(RTE_IPV4_HDR_OFFSET_MASK);
                }
            } else {
                VLOG_WARN_RL(&rl, "Unknown IPv4 frag (0x%x/0x%x)",
                             match->flow.nw_frag, match->wc.masks.nw_frag);
                return -1;
            }
            consumed_masks->nw_frag = 0;
        }

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask, last);

        /* Save proto for L4 protocol setup. */
        proto = spec->hdr.next_proto_id &
                mask->hdr.next_proto_id;
    }

    /* IP v6 */
    if (match->flow.dl_type == htons(ETH_TYPE_IPV6)) {
        struct rte_flow_item_ipv6 *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

        spec->hdr.proto = match->flow.nw_proto;
        spec->hdr.hop_limits = match->flow.nw_ttl;
        spec->hdr.vtc_flow =
            htonl((uint32_t) match->flow.nw_tos << RTE_IPV6_HDR_TC_SHIFT);
        memcpy(spec->hdr.src_addr, &match->flow.ipv6_src,
               sizeof spec->hdr.src_addr);
        memcpy(spec->hdr.dst_addr, &match->flow.ipv6_dst,
               sizeof spec->hdr.dst_addr);
        if ((match->wc.masks.nw_frag & FLOW_NW_FRAG_ANY) &&
            (match->flow.nw_frag & FLOW_NW_FRAG_ANY)) {
                spec->has_frag_ext = 1;
        }

        mask->hdr.proto = match->wc.masks.nw_proto;
        mask->hdr.hop_limits = match->wc.masks.nw_ttl;
        mask->hdr.vtc_flow =
            htonl((uint32_t) match->wc.masks.nw_tos << RTE_IPV6_HDR_TC_SHIFT);
        memcpy(mask->hdr.src_addr, &match->wc.masks.ipv6_src,
               sizeof mask->hdr.src_addr);
        memcpy(mask->hdr.dst_addr, &match->wc.masks.ipv6_dst,
               sizeof mask->hdr.dst_addr);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6, spec, mask, NULL);

        /* Save proto for L4 protocol setup. */
        proto = spec->hdr.proto & mask->hdr.proto;

        if (spec->has_frag_ext) {
            struct rte_flow_item_ipv6_frag_ext *frag_spec, *frag_mask,
                *frag_last = NULL;

            frag_spec = per_thread_xzalloc(sizeof *frag_spec);
            frag_mask = per_thread_xzalloc(sizeof *frag_mask);

            if (match->wc.masks.nw_frag & FLOW_NW_FRAG_LATER) {
                if (!(match->flow.nw_frag & FLOW_NW_FRAG_LATER)) {
                    /* frag=first */
                    frag_spec->hdr.frag_data = htons(RTE_IPV6_EHDR_MF_MASK);
                    frag_mask->hdr.frag_data = htons(RTE_IPV6_EHDR_MF_MASK |
                                                     RTE_IPV6_EHDR_FO_MASK);
                    /* move the proto match to the extension item */
                    frag_spec->hdr.next_header = match->flow.nw_proto;
                    frag_mask->hdr.next_header = match->wc.masks.nw_proto;
                    spec->hdr.proto = 0;
                    mask->hdr.proto = 0;
                } else {
                    /* frag=later */
                    frag_last = per_thread_xzalloc(sizeof *frag_last);
                    frag_spec->hdr.frag_data = htons(1 << RTE_IPV6_EHDR_FO_SHIFT);
                    frag_mask->hdr.frag_data = htons(RTE_IPV6_EHDR_FO_MASK);
                    frag_last->hdr.frag_data = htons(RTE_IPV6_EHDR_FO_MASK);
                    /* can't be a proto for later frags. */
                    spec->hdr.proto = 0;
                    mask->hdr.proto = 0;
                }
            } else {
                VLOG_WARN_RL(&rl, "Unknown IPv6 frag (0x%x/0x%x)",
                             match->flow.nw_frag, match->wc.masks.nw_frag);
                return -1;
            }

            add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
                             frag_spec, frag_mask, frag_last);
        }
        if (match->wc.masks.nw_frag) {
            /* frag=no is indicated by spec->has_frag_ext=0 */
            mask->has_frag_ext = 1;
            consumed_masks->nw_frag = 0;
        }
        consumed_masks->nw_proto = 0;
        consumed_masks->nw_ttl = 0;
        consumed_masks->nw_tos = 0;
        memset(&consumed_masks->ipv6_src, 0, sizeof consumed_masks->ipv6_src);
        memset(&consumed_masks->ipv6_dst, 0, sizeof consumed_masks->ipv6_dst);
    }

    if (!act_vars->is_ct_conn &&
        proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        return -1;
    }

    if (proto == IPPROTO_TCP) {
        struct rte_flow_item_tcp *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

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

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP, spec, mask, NULL);
    } else if (proto == IPPROTO_UDP) {
        struct rte_flow_item_udp *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask, NULL);
    } else if (proto == IPPROTO_SCTP) {
        struct rte_flow_item_sctp *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_SCTP, spec, mask, NULL);
    } else if (proto == IPPROTO_ICMP) {
        struct rte_flow_item_icmp *spec, *mask;

        spec = per_thread_xzalloc(sizeof *spec);
        mask = per_thread_xzalloc(sizeof *mask);

        spec->hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec->hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask->hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask->hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ICMP, spec, mask, NULL);
    }

    /* ct-state */
    if (match->wc.masks.ct_state &&
        !(match->wc.masks.ct_state & match->flow.ct_state & CS_NEW)) {
        if ((!match->flow.recirc_id &&
             !(match->wc.masks.ct_state & match->flow.ct_state)) ||
            !add_pattern_match_reg_field(patterns, REG_FIELD_CT_STATE,
                                         match->flow.ct_state,
                                         match->wc.masks.ct_state)) {
            consumed_masks->ct_state = 0;
        }
    }
    /* ct-zone */
    if (match->wc.masks.ct_zone &&
        (!get_zone_id(match->flow.ct_zone,
                      &act_resources->ct_match_zone_id) &&
         !add_pattern_match_reg_field(patterns,
                                      REG_FIELD_CT_ZONE,
                                      act_resources->ct_match_zone_id,
                                      reg_fields[REG_FIELD_CT_ZONE].mask))) {
        consumed_masks->ct_zone = 0;
    }
    /* ct-mark */
    if (match->wc.masks.ct_mark) {
        if ((!match->flow.recirc_id &&
             !(match->flow.ct_mark & match->wc.masks.ct_mark)) ||
            !add_pattern_match_reg_field(patterns, REG_FIELD_CT_MARK,
                                         match->flow.ct_mark,
                                         match->wc.masks.ct_mark)) {
            consumed_masks->ct_mark = 0;
        }
    }
    /* ct-label */
    if (!act_vars->is_ct_conn &&
        !is_all_zeros(&match->wc.masks.ct_label,
                      sizeof match->wc.masks.ct_label)) {
        uint32_t label_match_value, mask;
        ovs_u128 tmp_u128;

        tmp_u128.u64.lo = match->flow.ct_label.u64.lo &
                          match->wc.masks.ct_label.u64.lo;
        tmp_u128.u64.hi = match->flow.ct_label.u64.hi &
                          match->wc.masks.ct_label.u64.hi;
        if (get_label_id(&tmp_u128, &act_resources->ct_match_label_id)) {
            return -1;
        }
        label_match_value = act_resources->ct_match_label_id == ZERO_LABEL_ID
            ? 0 : act_resources->ct_match_label_id;
        mask = reg_fields[REG_FIELD_CT_LABEL_ID].mask;
        if (!add_pattern_match_reg_field(patterns, REG_FIELD_CT_LABEL_ID,
                                         label_match_value, mask)) {
            memset(&consumed_masks->ct_label,
                   0, sizeof consumed_masks->ct_label);
        }
    }
    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL, NULL);

    /* A CT conn offload is assured to be fully matched.
     * Verify full match only for other offloads. */
    if (!act_vars->is_ct_conn &&
        !is_all_zeros(consumed_masks, sizeof *consumed_masks)) {
        return -1;
    }
    return 0;
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

    mark = per_thread_xzalloc(sizeof *mark);

    mark->id = flow_mark;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);

    rss_data = per_thread_xmalloc(sizeof *rss_data +
                                  netdev_n_rxq(netdev) *
                                  sizeof rss_data->queue[0]);
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
                             uint32_t flow_mark,
                             struct act_vars *act_vars)
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

    if (act_vars->is_e2e_cache_flow) {
        return NULL;
    }

    add_flow_mark_rss_actions(&actions, flow_mark, netdev);

    create_rte_flow(netdev, &flow_attr, patterns->items, actions.actions,
                    &error, &flow_item, 0, act_vars);

    free_flow_actions(&actions, true);
    return flow_item.rte_flow[0];
}

static void
add_empty_sample_action(int ratio,
                        struct flow_actions *actions)
{
    struct sample_data {
        struct rte_flow_action_sample sample;
        struct rte_flow_action end_action;
    } *sample_data;
    BUILD_ASSERT_DECL(offsetof(struct sample_data, sample) == 0);

    sample_data = per_thread_xzalloc(sizeof *sample_data);
    sample_data->end_action.type = RTE_FLOW_ACTION_TYPE_END;
    sample_data->sample.actions = &sample_data->end_action;
    sample_data->sample.ratio = ratio;

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SAMPLE,
                    sample_data);
}

static int
map_sflow_attr(struct flow_actions *actions,
               const struct nlattr *nl_actions,
               struct dpif_sflow_attr *sflow_attr,
               struct act_resources *act_resources,
               struct act_vars *act_vars)
{
    struct sflow_ctx sflow_ctx;
    const struct nlattr *nla;
    unsigned int left;

    NL_NESTED_FOR_EACH_UNSAFE (nla, left, nl_actions) {
        if (nl_attr_type(nla) == OVS_USERSPACE_ATTR_USERDATA) {
            const struct user_action_cookie *cookie;

            cookie = nl_attr_get(nla);
            if (cookie->type == USER_ACTION_COOKIE_SFLOW) {
                sflow_attr->userdata_len = nl_attr_get_size(nla);
                sflow_ctx.sflow_attr = *sflow_attr;
                sflow_ctx.cookie = *cookie;
                if (act_vars->tnl_type != TNL_TYPE_NONE) {
                    memcpy(&sflow_ctx.sflow_tnl, act_vars->tnl_key,
                           sizeof sflow_ctx.sflow_tnl);
                } else {
                    memset(&sflow_ctx.sflow_tnl, 0,
                           sizeof sflow_ctx.sflow_tnl);
                }
                if (!get_sflow_id(&sflow_ctx, &act_resources->sflow_id) &&
                    !add_action_set_reg_field(actions, REG_FIELD_SFLOW_CTX,
                                              act_resources->sflow_id,
                                              UINT32_MAX)) {
                    return 0;
                }
            }
        }
    }

    VLOG_DBG_RL(&rl, "no sFlow cookie");
    return -1;
}

static int
parse_userspace_action(struct flow_actions *actions,
                       const struct nlattr *nl_actions,
                       struct dpif_sflow_attr *sflow_attr,
                       struct act_resources *act_resources,
                       struct act_vars *act_vars)
{
    const struct nlattr *nla;
    unsigned int left;

    NL_NESTED_FOR_EACH_UNSAFE (nla, left, nl_actions) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_USERSPACE) {
            return map_sflow_attr(actions, nla, sflow_attr,
                                  act_resources, act_vars);
        }
    }

    VLOG_DBG_RL(&rl, "no OVS_ACTION_ATTR_USERSPACE attribute");
    return -1;
}

static int
parse_sample_action(struct flow_actions *actions,
                    const struct nlattr *nl_actions,
                    struct dpif_sflow_attr *sflow_attr,
                    struct act_resources *act_resources,
                    struct act_vars *act_vars)
{
    const struct nlattr *nla;
    unsigned int left;
    int ratio = 0;

    sflow_attr->sflow = nl_actions;
    sflow_attr->sflow_len = nl_actions->nla_len;

    NL_NESTED_FOR_EACH_UNSAFE (nla, left, nl_actions) {
        if (nl_attr_type(nla) == OVS_SAMPLE_ATTR_ACTIONS) {
            if (parse_userspace_action(actions, nla,
                                       sflow_attr, act_resources, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_SAMPLE_ATTR_PROBABILITY) {
            ratio = UINT32_MAX / nl_attr_get_u32(nla);
        } else {
            return -1;
        }
    }

    add_empty_sample_action(ratio, actions);
    return 0;
}

static int
add_count_action(struct flow_actions *actions,
                 struct act_vars *act_vars,
                 struct act_resources *act_resources)
{
    struct rte_flow_action_count *count = per_thread_xzalloc(sizeof *count);

    /* e2e flows don't use mark. ct2ct do. we can share only e2e, not ct2ct. */
    if (act_vars->is_e2e_cache_flow &&
        act_resources->flow_id == INVALID_FLOW_MARK &&
        !netdev_is_flow_counter_key_zero(&act_vars->flows_counter_key)) {
        if (get_flows_counter_id(&act_vars->flows_counter_key, &count->id)) {
            per_thread_free(count);
            return -1;
        }
        count->shared = 1;
        act_resources->counter_id = count->id;
    }
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, count);

    /* e2e flows don't use mark. ct2ct do. we can share only e2e, not ct2ct. */
    if (act_vars->is_e2e_cache_flow && act_vars->ct_counter_key &&
        act_resources->flow_id == INVALID_FLOW_MARK) {
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_INDIRECT, NULL);
    }
    return 0;
}

static void
add_port_id_action(struct flow_actions *actions,
                   int outdev_id)
{
    struct rte_flow_action_port_id *port_id;

    port_id = per_thread_xzalloc(sizeof *port_id);
    port_id->id = outdev_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_PORT_ID, port_id);
}

static int
get_netdev_by_port(struct netdev *netdev,
                   const struct nlattr *nla,
                   int *outdev_id,
                   struct netdev **outdev)
{
    odp_port_t port;

    port = nl_attr_get_odp_port(nla);
    *outdev = netdev_ports_get(port, netdev->dpif_type);
    if (!*outdev) {
        VLOG_DBG_RL(&rl, "Cannot find netdev for odp port %"PRIu32, port);
        return -1;
    }
    if (!netdev_flow_api_equals(netdev, *outdev)) {
        goto err;
    }
    *outdev_id = netdev_dpdk_get_port_id(*outdev);
    if (*outdev_id < 0) {
        goto err;
    }
    return 0;
err:
    VLOG_DBG_RL(&rl, "%s: Output to port \'%s\' cannot be offloaded.",
                netdev_get_name(netdev), netdev_get_name(*outdev));
    netdev_close(*outdev);
    return -1;
}

static int
add_output_action(struct netdev *netdev,
                  struct flow_actions *actions,
                  const struct nlattr *nla)
{
    struct netdev *outdev;
    int outdev_id;
    int ret = 0;

    if (get_netdev_by_port(netdev, nla, &outdev_id, &outdev)) {
        return -1;
    }
    add_port_id_action(actions, outdev_id);

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

    spec = per_thread_xzalloc(size);
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
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv6) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv6) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ttl) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_hlimit));
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
            //add_set_flow_action(ipv4_ttl, RTE_FLOW_ACTION_TYPE_SET_TTL);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported IPv4 set action");
                return -1;
            }
            act_vars->pre_ct_tuple_rewrite = act_vars->ct_mode == CT_MODE_NONE;
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV6) {
            const struct ovs_key_ipv6 *key = nl_attr_get(sa);
            const struct ovs_key_ipv6 *mask = masked ? key + 1 : NULL;

            add_set_flow_action(ipv6_src, RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC);
            add_set_flow_action(ipv6_dst, RTE_FLOW_ACTION_TYPE_SET_IPV6_DST);
            //add_set_flow_action(ipv6_hlimit, RTE_FLOW_ACTION_TYPE_SET_TTL);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported IPv6 set action");
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
        } else {
            VLOG_DBG_RL(&rl,
                        "Unsupported set action type %d", nl_attr_type(sa));
            return -1;
        }
    }

    return 0;
}

/* Maximum number of items in vxlan/geneve encap/decap.
 * ETH / (VLANs) / IPv4(6) / UDP / VXLAN(GENEVE) / GENEVE-OPTS / END
 */
#define VXLAN_VLANS 1
#define TUNNEL_ITEMS_NUM (5 + VXLAN_VLANS + TUN_METADATA_NUM_OPTS)

struct vxlan_data {
    struct rte_flow_action_vxlan_encap conf;
    struct rte_flow_item items[TUNNEL_ITEMS_NUM];
    struct vlan_header vlans[VXLAN_VLANS];
    uint32_t vlan_index;
};
BUILD_ASSERT_DECL(offsetof(struct vxlan_data, conf) == 0);

static struct vxlan_data *
add_vxlan_encap_action(struct flow_actions *actions,
                       const void *header,
                       struct vxlan_data *vxlan_data_)
{
    struct vxlan_data *vxlan_data = NULL;
    struct rte_flow_item *vxlan_items;
    const struct eth_header *eth;
    const struct udp_header *udp;
    const void *vxlan;
    const void *l3;
    const void *l4;
    int field;

    if (!vxlan_data_) {
        vxlan_data = per_thread_xzalloc(sizeof *vxlan_data);
        vxlan_data->conf.definition = vxlan_data->items;
    } else {
        vxlan_data = vxlan_data_;
    }
    vxlan_items = vxlan_data->items;
    field = 0;

    eth = header;
    /* Ethernet */
    vxlan_items[field].type = RTE_FLOW_ITEM_TYPE_ETH;
    vxlan_items[field].spec = eth;
    vxlan_items[field].mask = &rte_flow_item_eth_mask;
    field++;

    l3 = eth + 1;
    /* IP */
    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* IPv4 */
        const struct ip_header *ip = l3;

        vxlan_items[field].type = RTE_FLOW_ITEM_TYPE_IPV4;
        vxlan_items[field].spec = ip;
        vxlan_items[field].mask = &rte_flow_item_ipv4_mask;

        if (ip->ip_proto != IPPROTO_UDP) {
            goto err;
        }
        l4 = (ip + 1);
    } else if (eth->eth_type == htons(ETH_TYPE_IPV6)) {
        const struct ovs_16aligned_ip6_hdr *ip6 = l3;

        vxlan_items[field].type = RTE_FLOW_ITEM_TYPE_IPV6;
        vxlan_items[field].spec = ip6;
        vxlan_items[field].mask = &rte_flow_item_ipv6_mask;

        if (ip6->ip6_nxt != IPPROTO_UDP) {
            goto err;
        }
        l4 = (ip6 + 1);
    } else {
        goto err;
    }
    field++;

    udp = l4;
    vxlan_items[field].type = RTE_FLOW_ITEM_TYPE_UDP;
    vxlan_items[field].spec = udp;
    vxlan_items[field].mask = &rte_flow_item_udp_mask;
    field++;

    vxlan = (udp + 1);
    vxlan_items[field].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    vxlan_items[field].spec = vxlan;
    vxlan_items[field].mask = &rte_flow_item_vxlan_mask;
    field++;

    vxlan_items[field].type = RTE_FLOW_ITEM_TYPE_END;

    if (!vxlan_data_) {
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP, vxlan_data);
    }

    return vxlan_data;
err:
    if (!vxlan_data_) {
        per_thread_free(vxlan_data);
    }
    return NULL;
}

static int
parse_vlan_push_action(struct flow_actions *actions,
                       const struct ovs_action_push_vlan *vlan_push,
                       struct act_vars *act_vars)
{
    struct rte_flow_action_of_push_vlan *rte_push_vlan;
    struct rte_flow_action_of_set_vlan_pcp *rte_vlan_pcp;
    struct rte_flow_action_of_set_vlan_vid *rte_vlan_vid;
    struct rte_flow_action *last_action = NULL;

    if (actions->cnt > 0) {
        last_action = &actions->actions[actions->cnt - 1];
    }
    if (last_action && last_action->type == RTE_FLOW_ACTION_TYPE_OF_POP_VLAN &&
        act_vars->vlan_tpid == vlan_push->vlan_tpid &&
        act_vars->vlan_pcp == vlan_tci_to_pcp(vlan_push->vlan_tci)) {
        actions->cnt--;
    } else {
        rte_push_vlan = per_thread_xzalloc(sizeof *rte_push_vlan);
        rte_push_vlan->ethertype = vlan_push->vlan_tpid;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN, rte_push_vlan);

        rte_vlan_pcp = per_thread_xzalloc(sizeof *rte_vlan_pcp);
        rte_vlan_pcp->vlan_pcp = vlan_tci_to_pcp(vlan_push->vlan_tci);
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP,
                        rte_vlan_pcp);
    }

    rte_vlan_vid = per_thread_xzalloc(sizeof *rte_vlan_vid);
    rte_vlan_vid->vlan_vid = htons(vlan_tci_to_vid(vlan_push->vlan_tci));
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID,
                    rte_vlan_vid);
    return 0;
}

struct raw_encap_data {
    struct rte_flow_action_raw_encap conf;
    uint8_t headroom[8];
    uint8_t data[TNL_PUSH_HEADER_SIZE - 8];
};
BUILD_ASSERT_DECL(offsetof(struct raw_encap_data, conf) == 0);

static int
push_vlan_vxlan(struct vxlan_data *vxlan_data,
                const struct ovs_action_push_vlan *vlan)
{
    struct rte_flow_item_eth *vx_eth_spec;
    struct vlan_header *vx_vlan;
    uint32_t i;

    /* If there is no empty slot available, error. */
    if (vxlan_data->vlan_index < VXLAN_VLANS &&
        vxlan_data->items[TUNNEL_ITEMS_NUM - 1].type != RTE_FLOW_ITEM_TYPE_END &&
        vxlan_data->items[TUNNEL_ITEMS_NUM - 2].type != RTE_FLOW_ITEM_TYPE_END) {
        return -1;
    }

    /* Make room for the VLAN entry */
    for (i = TUNNEL_ITEMS_NUM - 2; i > 1; i--) {
        vxlan_data->items[i] = vxlan_data->items[i - 1];
    }

    vx_vlan = &vxlan_data->vlans[vxlan_data->vlan_index++];
    vxlan_data->items[1].type = RTE_FLOW_ITEM_TYPE_VLAN;
    vxlan_data->items[1].spec = vx_vlan;
    vxlan_data->items[1].mask = &rte_flow_item_vlan_mask;
    vx_eth_spec = CONST_CAST(struct rte_flow_item_eth *,
                             vxlan_data->items[0].spec);
    vx_vlan->vlan_next_type = vx_eth_spec->type;
    vx_eth_spec->type = vlan->vlan_tpid;
    vx_vlan->vlan_tci = vlan->vlan_tci & htons(~VLAN_CFI);

    return 0;
}

static int
parse_clone_actions(struct netdev *netdev,
                    struct flow_actions *actions,
                    const struct nlattr *clone_actions,
                    const size_t clone_actions_len,
                    int *outdev_id,
                    struct raw_encap_data *raw_encap_data,
                    struct vxlan_data *vxlan_data_)
{
    struct vxlan_data *vxlan_data = NULL;
    const struct nlattr *ca;
    struct netdev *outdev;
    unsigned int cleft;

    NL_ATTR_FOR_EACH_UNSAFE (ca, cleft, clone_actions, clone_actions_len) {
        int clone_type = nl_attr_type(ca);

        if (clone_type == OVS_ACTION_ATTR_TUNNEL_PUSH) {
            const struct ovs_action_push_tnl *tnl_push = nl_attr_get(ca);
            struct raw_encap_data *actions_raw_encap_data = NULL;

            if (tnl_push->tnl_type == OVS_VPORT_TYPE_VXLAN) {
                vxlan_data = add_vxlan_encap_action(actions, tnl_push->header,
                                                    vxlan_data_);
                if (vxlan_data) {
                    continue;
                }
            }
            if (!raw_encap_data) {
                actions_raw_encap_data =
                    per_thread_xzalloc(sizeof *raw_encap_data);
                raw_encap_data = actions_raw_encap_data;
            }

            memcpy(raw_encap_data->data, tnl_push->header,
                   tnl_push->header_len);
            raw_encap_data->conf.data = raw_encap_data->data;
            raw_encap_data->conf.preserve = NULL;
            raw_encap_data->conf.size = tnl_push->header_len;
            if (actions_raw_encap_data) {
                add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
                                actions_raw_encap_data);
            }
        } else if (clone_type == OVS_ACTION_ATTR_OUTPUT) {
            if (actions) {
                if (add_output_action(netdev, actions, ca)) {
                    return -1;
                }
            } else {
                if (get_netdev_by_port(netdev, ca, outdev_id, &outdev)) {
                    return -1;
                }
                netdev_close(outdev);
            }
        } else if (clone_type == OVS_ACTION_ATTR_PUSH_VLAN) {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(ca);
            struct vlan_eth_header *veh;

            if (vxlan_data && !push_vlan_vxlan(vxlan_data, vlan)) {
                continue;
            }

            /* Insert new 802.1Q header. */
            raw_encap_data->conf.data -= VLAN_HEADER_LEN;
            if (raw_encap_data->conf.data < raw_encap_data->headroom) {
                return -1;
            }
            raw_encap_data->conf.size += VLAN_HEADER_LEN;
            veh = (struct vlan_eth_header *) raw_encap_data->conf.data;
            memmove(veh, (char *)veh + VLAN_HEADER_LEN, 2 * ETH_ADDR_LEN);
            veh->veth_type = vlan->vlan_tpid;
            veh->veth_tci = vlan->vlan_tci & htons(~VLAN_CFI);
        } else {
            VLOG_DBG_RL(&rl,
                        "Unsupported nested action inside clone(), "
                        "action type: %d", clone_type);
            return -1;
        }
    }
    return 0;
}

/* Maximum number of actions in port mirror.
 * RAW_ENCAP(VXLAN_ENCAP) / PORT_ID / END
 */
#define MIRROR_ACTIONS_NUM 3

static int
add_mirror_action(struct netdev *netdev,
                  struct flow_actions *actions,
                  const struct nlattr *nla,
                  const size_t clone_actions_len)
{
    struct netdev *outdev;
    struct sample_conf {
        struct rte_flow_action_sample sample;
        struct rte_flow_action_port_id port_id;
        struct raw_encap_data raw_encap_data;
        struct vxlan_data vxlan_data;
        struct rte_flow_action sample_actions[MIRROR_ACTIONS_NUM];
    } *sample_conf;
    BUILD_ASSERT_DECL(offsetof(struct sample_conf, sample) == 0);
    struct rte_flow_action *sample_itr;
    bool is_vxlan, is_raw;
    int port_id;

    sample_conf = per_thread_xzalloc(sizeof *sample_conf);
    sample_itr = sample_conf->sample_actions;
    is_vxlan = false;
    is_raw = false;
    if (!clone_actions_len) {
        if (get_netdev_by_port(netdev, nla, &port_id, &outdev)) {
            goto err;
        }
        netdev_close(outdev);
    } else {
        if (parse_clone_actions(netdev, NULL, nla,
                                clone_actions_len, &port_id,
                                &sample_conf->raw_encap_data,
                                &sample_conf->vxlan_data)) {
            goto err;
        }
        /* Identify whether to use vxlan_encap or raw_encap */
        is_vxlan = sample_conf->vxlan_data.items[0].type !=
            RTE_FLOW_ITEM_TYPE_END;
        is_raw = sample_conf->raw_encap_data.conf.size > 0;
        sample_conf->vxlan_data.conf.definition = sample_conf->vxlan_data.items;
    }

    /* Initialize sample struct */
    sample_conf->sample.ratio = 1;
    sample_conf->sample.actions = sample_conf->sample_actions;
    sample_conf->port_id.id = port_id;
    if (is_vxlan) {
        sample_itr->conf = &sample_conf->vxlan_data.conf;
        sample_itr->type = RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP;
        sample_itr++;
    } else if (is_raw) {
        sample_itr->conf = &sample_conf->raw_encap_data.conf;
        sample_itr->type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
        sample_itr++;
    }
    sample_itr->conf = &sample_conf->port_id;
    sample_itr->type = RTE_FLOW_ACTION_TYPE_PORT_ID;
    sample_itr++;
    sample_itr->type = RTE_FLOW_ACTION_TYPE_END;

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SAMPLE,
                    sample_conf);
    return 0;
err:
    per_thread_free(sample_conf);
    return -1;
}

static struct rte_flow_action_jump *
add_jump_action(struct flow_actions *actions, uint32_t group)
{
    struct rte_flow_action_jump *jump = per_thread_xzalloc(sizeof *jump);

    jump->group = group;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump);

    return jump;
}

static int
add_miss_flow(struct netdev *netdev,
              const char *devargs,
              uint32_t table_id,
              uint32_t mark_id,
              struct act_vars *act_vars)
{
    struct rte_flow_item miss_items[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH, },
        { .type = RTE_FLOW_ITEM_TYPE_END, } };
    struct rte_flow_action_jump miss_jump = { .group = MISS_TABLE_ID, };
    struct rte_flow_action_mark miss_mark;
    const struct rte_flow_action miss_actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_MARK, .conf = &miss_mark },
        { .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &miss_jump },
        { .type = RTE_FLOW_ACTION_TYPE_END, } };
    struct act_resources act_resources = { .flow_id = INVALID_FLOW_MARK };
    struct flows_handle flows = { .items = NULL, .cnt = 0 };
    struct flow_item flow_item = { .devargs = devargs };
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_attr attr = {
        .transfer = 1,
        .ingress = 1,
        .group = table_id,
        .priority = 1,
    };
    struct rte_flow_error error;
    ovs_u128 ufid;
    int ret;

    if (table_id_ufid(devargs, false, table_id, &ufid)) {
        return -1;
    }
    rte_flow_data = ufid_to_rte_flow_data_find(netdev, &ufid, false);
    if (rte_flow_data) {
        return 0;
    }

    miss_mark.id = mark_id;
    ret = create_rte_flow(netdev, &attr, miss_items, miss_actions,
                          &error, &flow_item, 0, act_vars);
    if (ret) {
        return -1;
    }

    VLOG_DBG_RL(&rl, "%s: installed flow %p by ufid "UUID_FMT"\n",
                netdev_get_name(netdev), flow_item.rte_flow[0],
                UUID_ARGS((struct uuid *) &ufid));
    add_flow_item(&flows, &flow_item);
    if (!ufid_to_rte_flow_associate(&ufid, netdev, &flows, true,
                                    &act_resources, false)) {
        netdev_offload_dpdk_destroy_flow(netdev, flow_item.rte_flow[0],
                                         netdev_offload_thread_id(), &ufid);
        free_flow_handle(&flows, false);
    }
    return 0;
}

static int
add_tnl_pop_action(struct flow_actions *actions,
                   const struct nlattr *nla,
                   struct act_resources *act_resources,
                   struct act_vars *act_vars)
{
    struct flow_miss_ctx miss_ctx;
    odp_port_t port;

    port = nl_attr_get_odp_port(nla);
    miss_ctx.vport = port;
    miss_ctx.recirc_id = 0;
    memset(&miss_ctx.tnl, 0, sizeof miss_ctx.tnl);
    miss_ctx.skip_actions = act_vars->pre_ct_cnt;
    if (get_flow_miss_ctx_id(&miss_ctx, &act_resources->flow_miss_ctx_id)) {
        return -1;
    }
    act_vars->jump = add_jump_action(actions, 0);
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
    miss_ctx.skip_actions = act_vars->pre_ct_cnt;
    if (act_vars->vport != ODPP_NONE) {
        get_tnl_masked(&miss_ctx.tnl, NULL, act_vars->tnl_key,
                       &act_vars->tnl_mask);
    } else {
        memset(&miss_ctx.tnl, 0, sizeof miss_ctx.tnl);
    }
    if (get_flow_miss_ctx_id(&miss_ctx, &act_resources->flow_miss_ctx_id)) {
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
    act_vars->jump = add_jump_action(actions, 0);
    return 0;
}

static void
dump_raw_decap(struct act_vars *act_vars)
{
    int i;

    ds_init(&act_vars->s_extra);
    ds_put_format(&act_vars->s_extra, "set raw_decap eth / udp / ");
    if (act_vars->is_outer_ipv4) {
        ds_put_format(&act_vars->s_extra, "ipv4 / ");
    } else {
        ds_put_format(&act_vars->s_extra, "ipv6 / ");
    }
    ds_put_format(&act_vars->s_extra, "geneve / ");
    for (i = 0; i < act_vars->gnv_opts_cnt; i++) {
        ds_put_format(&act_vars->s_extra, "geneve-opt / ");
    }
    ds_put_format(&act_vars->s_extra, "end_set");
}

static int
add_vxlan_decap_action(struct flow_actions *actions)
{
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP, NULL);
    return 0;
}

static int
add_geneve_decap_action(struct flow_actions *actions,
                        struct act_vars *act_vars)
{
    struct rte_flow_action_raw_decap *conf;

    conf = per_thread_xmalloc(sizeof (struct rte_flow_action_raw_decap));
    /* MLX5 PMD supports only one option of size 32 bits
     * which is the minimum size of options (if exists)
     * in case a flow exists with an option decapsulate 32 bits
     * from the header for the geneve options.
     */
    conf->size = sizeof (struct eth_header) +
                 sizeof (struct udp_header) +
                 sizeof (struct geneve_opt) +
                 (act_vars->is_outer_ipv4 ?
                  sizeof (struct ip_header) :
                  sizeof (struct ovs_16aligned_ip6_hdr)) +
                 (act_vars->gnv_opts_cnt ?
                   sizeof (uint32_t) : 0);

    conf->data = NULL;

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RAW_DECAP, conf);
    if (VLOG_IS_DBG_ENABLED()) {
        dump_raw_decap(act_vars);
    }
    return 0;
}

static int
add_gre_decap_action(struct flow_actions *actions)
{
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_NVGRE_DECAP, NULL);
    return 0;
}

static int
add_tnl_decap_action(struct flow_actions *actions,
                     struct act_vars *act_vars)
{
    if (act_vars->tnl_type == TNL_TYPE_VXLAN) {
        return add_vxlan_decap_action(actions);
    }
    if (act_vars->tnl_type == TNL_TYPE_GENEVE) {
        return add_geneve_decap_action(actions, act_vars);
    }
    if (act_vars->tnl_type == TNL_TYPE_GRE) {
        return add_gre_decap_action(actions);
    }
    return -1;
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
        if (nl_attr_type(cta) == OVS_CT_ATTR_ZONE) {
            const uint32_t ct_zone_mask = reg_fields[REG_FIELD_CT_ZONE].mask;

            if (act_resources->flow_id != INVALID_FLOW_MARK &&
                (get_zone_id(nl_attr_get_u16(cta),
                             &act_resources->ct_action_zone_id) ||
                 add_action_set_reg_field(actions, REG_FIELD_CT_ZONE,
                                          act_resources->ct_action_zone_id,
                                          ct_zone_mask))) {
                VLOG_DBG_RL(&rl, "Could not create zone id");
                return -1;
            }

            ct_miss_ctx.zone = nl_attr_get_u16(cta);
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_MARK) {
            const uint32_t *key = nl_attr_get(cta);
            const uint32_t *mask = key + 1;

            add_action_set_reg_field(actions, REG_FIELD_CT_MARK, *key, *mask);
            ct_miss_ctx.mark = *key;
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_LABELS) {
            const ovs_32aligned_u128 *key = nl_attr_get(cta);
            const ovs_32aligned_u128 *mask = key + 1;
            ovs_u128 tmp_key, tmp_mask;
            uint32_t set_value, set_mask;

            tmp_key.u32[0] = key->u32[0];
            tmp_key.u32[1] = key->u32[1];
            tmp_key.u32[2] = key->u32[2];
            tmp_key.u32[3] = key->u32[3];

            tmp_mask.u32[0] = mask->u32[0];
            tmp_mask.u32[1] = mask->u32[1];
            tmp_mask.u32[2] = mask->u32[2];
            tmp_mask.u32[3] = mask->u32[3];

            tmp_key.u64.lo &= tmp_mask.u64.lo;
            tmp_key.u64.hi &= tmp_mask.u64.hi;
            if (get_label_id(&tmp_key, &act_resources->ct_action_label_id)) {
                return -1;
            }
            set_value = act_resources->ct_action_label_id == ZERO_LABEL_ID
                ? 0 : act_resources->ct_action_label_id;
            set_mask = reg_fields[REG_FIELD_CT_LABEL_ID].mask;
            if (add_action_set_reg_field(actions, REG_FIELD_CT_LABEL_ID,
                                          set_value, set_mask)) {
                VLOG_DBG_RL(&rl, "Could not create label id");
                return -1;
            }
            ct_miss_ctx.label.u32[0] = key->u32[0];
            ct_miss_ctx.label.u32[1] = key->u32[1];
            ct_miss_ctx.label.u32[2] = key->u32[2];
            ct_miss_ctx.label.u32[3] = key->u32[3];
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_NAT) {
            act_vars->ct_mode = CT_MODE_CT_NAT;
        } else if (nl_attr_type(cta) == OVS_CT_ATTR_HELPER) {
            const char *helper = nl_attr_get(cta);
            uintptr_t ctid_key;

            if (strncmp(helper, "offl", strlen("offl"))) {
                continue;
            }

            if (!ovs_scan(helper, "offl,st(0x%"SCNx8"),id_key(0x%"SCNxPTR")",
                          &ct_miss_ctx.state, &ctid_key)) {
                VLOG_ERR("Invalid offload helper: '%s'", helper);
                return -1;
            }
            /* mt ct flows don't use mark. ct2ct do. we can share only mt, not
             * ct2ct.
             */
            if (act_resources->flow_id == INVALID_FLOW_MARK &&
                get_ct_counter_id(ctid_key, &act_resources->ctid)) {
                VLOG_ERR("Could not create CT id");
                return -1;
            }

            act_vars->ct_mode = CT_MODE_CT_CONN;
            act_vars->pre_ct_tuple_rewrite = false;
            if (!act_resources->next_table_id &&
                get_table_id(0, act_vars->vport, 0, TABLE_TYPE_POST_CT, false,
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
            if (act_resources->flow_id != INVALID_FLOW_MARK) {
                struct rte_flow_action_mark *mark =
                    per_thread_xzalloc(sizeof *mark);

                mark->id = act_resources->flow_id;
                add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);
            }
            act_vars->jump = add_jump_action(actions,
                                             act_resources->next_table_id);
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
                      struct flow_actions *nat_actions,
                      uint32_t ctid)
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
        if (ctid && actions->type == RTE_FLOW_ACTION_TYPE_COUNT) {
            struct rte_flow_action_count *count;

            count = CONST_CAST(struct rte_flow_action_count *, actions->conf);
            count->shared = 1;
            count->id = ctid;
        }
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
    int ret = -1;
    int pos = 0;
    bool is_ct;

    fi->rte_flow[0] = fi->rte_flow[1] = NULL;
    fi->has_count[0] = fi->has_count[1] = false;

    split_ct_conn_actions(actions, &ct_actions, &nat_actions,
                          act_resources->ctid);
    is_ct = ct_actions.cnt == nat_actions.cnt;

    if (netdev_offload_ct_on_ct_nat || !is_ct) {
        if (!act_resources->ct_nat_table_id &&
            get_table_id(0, act_vars->vport, 0, TABLE_TYPE_CT_NAT, false,
                         &act_resources->ct_nat_table_id)) {
            return -1;
        }
        fi->has_count[pos] = true;
        ret = create_offload_flow(netdev, act_resources->ct_nat_table_id,
                                  items, nat_actions.actions, error,
                                  act_resources, act_vars, fi, pos);
        if (ret) {
            goto out;
        }
        pos++;
    }

    if (netdev_offload_ct_on_ct_nat || is_ct) {
        if (!act_resources->self_table_id &&
            get_table_id(0, act_vars->vport, 0, TABLE_TYPE_CT, false,
                         &act_resources->self_table_id)) {
            ret = -1;
            goto ct_err;
        }
        fi->has_count[pos] = true;
        ret = create_offload_flow(netdev, act_resources->self_table_id, items,
                                  ct_actions.actions, error, act_resources,
                                  act_vars, fi, pos);
    }

ct_err:
    if (ret != 0) {
        if (fi->rte_flow[0] != NULL) {
            netdev_offload_dpdk_destroy_flow(netdev, fi->rte_flow[0],
                                             fi->creation_tid, NULL);
        }
    }
out:
    free_flow_actions(&ct_actions, false);
    free_flow_actions(&nat_actions, false);
    return ret;
}

static int
add_ct_nat_miss(struct netdev *netdev,
                const char *devargs,
                uint32_t table_id,
                struct act_vars *act_vars)
{
    struct rte_flow_item miss_items[] = {
        { .type = RTE_FLOW_ITEM_TYPE_ETH, },
        { .type = RTE_FLOW_ITEM_TYPE_END, } };
    struct rte_flow_action_jump miss_jump;
    const struct rte_flow_action miss_actions[] = {
        { .type = RTE_FLOW_ACTION_TYPE_JUMP, .conf = &miss_jump },
        { .type = RTE_FLOW_ACTION_TYPE_END, } };
    struct act_resources act_resources = { .flow_id = INVALID_FLOW_MARK };
    struct flows_handle flows = { .items = NULL, .cnt = 0 };
    struct flow_item flow_item = { .devargs = devargs };
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_attr attr = {
        .transfer = 1,
        .ingress = 1,
        .group = table_id,
        .priority = 1,
    };
    struct rte_flow_error error;
    uint32_t ct_table_id;
    ovs_u128 ufid;
    int ret;

    if (table_id_ufid(devargs, false, table_id, &ufid)) {
        return -1;
    }
    rte_flow_data = ufid_to_rte_flow_data_find(netdev, &ufid, false);
    if (rte_flow_data) {
        return 0;
    }

    if (get_table_id(0, act_vars->vport, 0, TABLE_TYPE_CT, false,
                     &ct_table_id)) {
        return -1;
    }
    miss_jump.group = ct_table_id;

    ret = create_rte_flow(netdev, &attr, miss_items, miss_actions,
                          &error, &flow_item, 0, act_vars);
    if (ret) {
        return -1;
    }

    VLOG_DBG_RL(&rl, "%s: installed flow %p by ufid "UUID_FMT"\n",
                netdev_get_name(netdev), flow_item.rte_flow[0],
                UUID_ARGS((struct uuid *) &ufid));
    add_flow_item(&flows, &flow_item);
    if (!ufid_to_rte_flow_associate(&ufid, netdev, &flows, true,
                                    &act_resources, false)) {
        netdev_offload_dpdk_destroy_flow(netdev, flow_item.rte_flow[0],
                                         netdev_offload_thread_id(), &ufid);
        free_flow_handle(&flows, false);
    }
    return 0;
}

static void
split_pre_post_ct_actions(const struct rte_flow_action *actions,
                          struct flow_actions *pre_ct_actions,
                          struct flow_actions *post_ct_actions)
{
    while (actions && actions->type != RTE_FLOW_ACTION_TYPE_END) {
        if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_DECAP ||
            actions->type == RTE_FLOW_ACTION_TYPE_NVGRE_DECAP ||
            actions->type == RTE_FLOW_ACTION_TYPE_SET_TAG ||
            actions->type == RTE_FLOW_ACTION_TYPE_SET_META ||
            actions->type == RTE_FLOW_ACTION_TYPE_RAW_DECAP ||
            actions->type == RTE_FLOW_ACTION_TYPE_SAMPLE) {
            add_flow_action(pre_ct_actions, actions->type, actions->conf);
        } else {
            add_flow_action(post_ct_actions, actions->type, actions->conf);
        }
        actions++;
    }
}

static int
create_pre_post_ct(struct netdev *netdev,
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
    enum table_type tbl_type;
    int ret;

    tbl_type = act_vars->ct_mode == CT_MODE_CT
               ? TABLE_TYPE_CT : TABLE_TYPE_CT_NAT;

    /* post-ct */
    post_ct_mark.id = act_resources->flow_id;
    if (!act_resources->post_ct_table_id &&
        get_table_id(0, act_vars->vport, 0, TABLE_TYPE_POST_CT, false,
                     &act_resources->post_ct_table_id)) {
        return -1;
    }
    split_pre_post_ct_actions(actions, &pre_ct_actions, &post_ct_actions);
    add_flow_action(&post_ct_actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    ret = create_offload_flow(netdev, act_resources->post_ct_table_id,
                              post_ct_items, post_ct_actions.actions, error,
                              act_resources, act_vars, fi, 1);
    fi->has_count[1] = true;
    if (ret) {
        goto out;
    }

    /* pre-ct */
    if (!act_resources->ct_table_id &&
        get_table_id(0, act_vars->vport, 0, tbl_type, false,
                     &act_resources->ct_table_id)) {
        ret = -1;
        goto pre_ct_err;
    }
    /* Add a miss-rule from CT-NAT to CT table for natted connections
     * without NAT actions (e.g. 'ct(nat)'). Without NAT actions, they
     * will be offloaded in the CT table by default, unless
     * 'ct-action-on-nat-conns' is enabled.
     */
    if (tbl_type == TABLE_TYPE_CT_NAT &&
        add_ct_nat_miss(netdev, netdev_dpdk_get_port_devargs(netdev),
                        act_resources->ct_table_id, act_vars)) {
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
    pre_ct_miss_ctx.skip_actions = act_vars->pre_ct_cnt;
    if (!act_resources->associated_flow_id) {
        if (associate_flow_id(act_resources->flow_id, &pre_ct_miss_ctx)) {
            goto pre_ct_err;
        }
        act_resources->associated_flow_id = true;
    }
    pre_ct_mark.id = act_resources->flow_id;
    add_flow_action(&pre_ct_actions, RTE_FLOW_ACTION_TYPE_MARK, &pre_ct_mark);
    pre_ct_jump.group = act_resources->ct_table_id;
    add_flow_action(&pre_ct_actions, RTE_FLOW_ACTION_TYPE_JUMP, &pre_ct_jump);
    add_flow_action(&pre_ct_actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    act_vars->is_pre_ct = true;
    ret = create_offload_flow(netdev, 0, items, pre_ct_actions.actions, error,
                              act_resources, act_vars, fi, 0);
    act_vars->is_pre_ct = false;
    if (ret) {
        goto pre_ct_err;
    }
    goto out;

pre_ct_err:
    netdev_offload_dpdk_destroy_flow(netdev, fi->rte_flow[1],
                                     fi->creation_tid, NULL);
out:
    free_flow_actions(&pre_ct_actions, false);
    free_flow_actions(&post_ct_actions, false);
    return ret;
}

static int
netdev_offload_dpdk_flow_create(struct netdev *netdev,
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
        return create_offload_flow(netdev, 0, items, actions, error,
                                   act_resources, act_vars, fi, 0);
    case CT_MODE_CT:
        /* fallthrough */
    case CT_MODE_CT_NAT:
        return create_pre_post_ct(netdev, items, actions, error,
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

    if (nl_actions_len != 0 &&
        act_vars->tnl_type != TNL_TYPE_NONE &&
        act_vars->recirc_id == 0 &&
        add_tnl_decap_action(actions, act_vars)) {
        return -1;
    }
    if (add_count_action(actions, act_vars, act_resources)) {
        return -1;
    }
    NL_ATTR_FOR_EACH_UNSAFE (nla, left, nl_actions, nl_actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            if (left <= NLA_ALIGN(nla->nla_len)) {
                if (add_output_action(netdev, actions, nla)) {
                   return -1;
                }
            } else {
                if (add_mirror_action(netdev, actions, nla, 0)) {
                    return -1;
                }
                act_vars->pre_ct_cnt++;
                act_vars->pre_ct_actions = nla;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_DROP) {
            free_flow_actions(actions, true);
            if (add_count_action(actions, act_vars, act_resources)) {
                return -1;
            }
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
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_PUSH_VLAN) {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(nla);

            if (parse_vlan_push_action(actions, vlan, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_POP_VLAN) {
            add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_POP_VLAN, NULL);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CLONE) {
            const struct nlattr *clone_actions = nl_attr_get(nla);
            size_t clone_actions_len = nl_attr_get_size(nla);

            if (left <= NLA_ALIGN(nla->nla_len)) {
                if (parse_clone_actions(netdev, actions, clone_actions,
                                        clone_actions_len, NULL,
                                        NULL, NULL)) {
                    return -1;
                }
            } else {
                if (add_mirror_action(netdev, actions, clone_actions,
                                      clone_actions_len)) {
                    return -1;
                }
                act_vars->pre_ct_cnt++;
                act_vars->pre_ct_actions = nla;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_TUNNEL_POP) {
            if (add_tnl_pop_action(actions, nla, act_resources, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_RECIRC) {
            if (add_recirc_action(actions, nla, act_resources, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CT) {
            const struct nlattr *ct_actions = nl_attr_get(nla);
            size_t ct_actions_len = nl_attr_get_size(nla);

            /* Check that the mirror is the first action of the flow */
            if (act_vars->pre_ct_actions &&
                act_vars->pre_ct_actions != nl_actions) {
                VLOG_DBG_RL(&rl, "Mirror should be the first action");
                return -1;
            }
            if (parse_ct_actions(actions, ct_actions, ct_actions_len,
                                 act_resources, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SAMPLE) {
            struct dpif_sflow_attr sflow_attr;

            memset(&sflow_attr, 0, sizeof sflow_attr);
            if (parse_sample_action(actions, nla,
                                    &sflow_attr, act_resources, act_vars)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_USERSPACE) {
            struct dpif_sflow_attr sflow_attr;

            memset(&sflow_attr, 0, sizeof sflow_attr);
            /* Cases where the sFlow sampling rate is 1 the ovs action
             * is translated into OVS_ACTION_ATTR_USERSPACE and not
             * OVS_ACTION_ATTR_SAMPLE, this requires only mapping the
             * sFlow cookie.
             */
            sflow_attr.sflow = nla;
            sflow_attr.sflow_len = nla->nla_len;
            if (map_sflow_attr(actions, nla, &sflow_attr,
                               act_resources, act_vars)) {
                return -1;
            }
            add_empty_sample_action(1, actions);
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
        VLOG_DBG_RL(&rl, "No actions provided");
        return -1;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    return 0;
}

struct tnl_flow_create_aux {
    struct netdev *vport;
    const struct rte_flow_item *items;
    const struct rte_flow_action *actions;
    const ovs_u128 *ufid;
    struct act_resources *act_resources;
    struct act_vars *act_vars;
    struct flows_handle *flows;
};

static bool
flow_create_for_each_uplink(struct netdev *netdev,
                            odp_port_t odp_port OVS_UNUSED,
                            void *arg)
{
    struct flow_item flow_item = { .devargs = NULL };
    struct tnl_flow_create_aux *aux = arg;
    struct rte_flow_error error;
    int ret;

    if (!netdev_dpdk_is_uplink_port(netdev)) {
        /* False == continue; */
        return false;
    }

    ret = netdev_offload_dpdk_flow_create(netdev, aux->items, aux->actions,
                                          &error, aux->act_resources,
                                          aux->act_vars, &flow_item);
    if (ret != 0) {
        return false;
    }

    flow_item.devargs = netdev_dpdk_get_port_devargs(netdev);
    VLOG_DBG_RL(&rl, "%s: installed flow %p/%p by ufid "UUID_FMT,
                netdev_get_name(aux->vport), flow_item.rte_flow[0],
                flow_item.rte_flow[1],
                UUID_ARGS((struct uuid *)aux->ufid));
    add_flow_item(aux->flows, &flow_item);

    return false;
}

static int
netdev_offload_dpdk_create_tnl_flows(struct netdev *netdev,
                                     const struct rte_flow_item *items,
                                     const struct rte_flow_action *actions,
                                     const ovs_u128 *ufid,
                                     struct act_resources *act_resources,
                                     struct act_vars *act_vars,
                                     struct flows_handle *flows)
{
    struct tnl_flow_create_aux tnl = {
        .vport = netdev, .items = items, .actions = actions,
        .ufid = ufid, .act_resources = act_resources, .act_vars = act_vars,
        .flows = flows,
    };

    netdev_ports_traverse(netdev->dpif_type,
                          flow_create_for_each_uplink, &tnl);

    return flows->cnt > 0 ? 0 : -1;
}

static int
create_highnetdev_flow(struct netdev *netdev,
                       const struct rte_flow_item *items,
                       const struct rte_flow_action *actions,
                       const ovs_u128 *ufid,
                       struct act_resources *act_resources,
                       struct act_vars *act_vars,
                       struct flows_handle *flows)
{
    struct flow_item flow_item = { .devargs = NULL };
    struct rte_flow_error error;
    int ret;

    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        ret = netdev_offload_dpdk_create_tnl_flows(netdev, items, actions,
                                                   ufid, act_resources,
                                                   act_vars, flows);
    } else {
        ret = netdev_offload_dpdk_flow_create(netdev, items, actions,
                                              &error, act_resources, act_vars,
                                              &flow_item);
        if (ret) {
            goto out;
        }
        VLOG_DBG_RL(&rl, "%s: installed flow %p/%p by ufid "UUID_FMT,
                    netdev_get_name(netdev), flow_item.rte_flow[0],
                    flow_item.rte_flow[1],
                    UUID_ARGS((struct uuid *)ufid));
        add_flow_item(flows, &flow_item);
    }
out:
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
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    int ret;

    ret = parse_flow_actions(netdev, &actions, nl_actions, actions_len,
                             act_resources, act_vars);
    if (ret) {
        goto out;
    }
    ret = create_highnetdev_flow(netdev, patterns->items, actions.actions,
                                 ufid, act_resources, act_vars, flows);
out:
    free_flow_actions(&actions, true);
    return ret;
}

static struct ufid_to_rte_flow_data *
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
    struct ufid_to_rte_flow_data *flows_data = NULL;
    bool actions_offloaded = true;
    int ret;

    act_vars.is_e2e_cache_flow = info->is_e2e_cache_flow;
    act_vars.is_ct_conn = info->is_ct_conn;
    act_vars.ct_counter_key = info->ct_counter_key;
    memcpy(&act_vars.flows_counter_key, &info->flows_counter_key,
           sizeof info->flows_counter_key);
    ret = parse_flow_match(netdev, &patterns, match, &act_resources,
                           &act_vars);
    if (ret) {
        VLOG_DBG_RL(&rl, "%s: matches of ufid "UUID_FMT" are not supported",
                    netdev_get_name(netdev), UUID_ARGS((struct uuid *) ufid));
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
        if (act_vars.vport == ODPP_NONE && act_vars.recirc_id == 0) {
            flow_item.rte_flow[0] =
                netdev_offload_dpdk_mark_rss(&patterns, netdev,
                                             info->flow_mark, &act_vars);
        } else {
            flow_item.rte_flow[0] = NULL;
        }
        ret = flow_item.rte_flow[0] ? 0 : -1;
        if (ret) {
            goto out;
        }
        VLOG_DBG_RL(&rl, "%s: installed flow %p by ufid "UUID_FMT,
                    netdev_get_name(netdev), flow_item.rte_flow[0],
                    UUID_ARGS((struct uuid *)ufid));
        add_flow_item(&flows, &flow_item);
    }

    if (ret) {
        goto out;
    }

    flows_data = ufid_to_rte_flow_associate(ufid, netdev, &flows,
                                            actions_offloaded, &act_resources,
                                            true);

out:
    if (ret) {
        put_action_resources(netdev, &act_resources);
    }
    free_flow_patterns(&patterns);
    return flows_data;
}

static int
netdev_offload_dpdk_remove_flows(struct netdev *netdev,
                                 struct ufid_to_rte_flow_data *rte_flow_data)
    OVS_EXCLUDED(data->lock)
{
    struct netdev *flow_netdev;
    struct flows_handle *flows;
    const ovs_u128 *ufid;
    int ret;
    int i;
    int j;

    flows = &rte_flow_data->flows;
    ufid = &rte_flow_data->ufid;

    if (rte_flow_data->dead) {
        return 0;
    }

    ovs_mutex_lock(&rte_flow_data->lock);

    if (rte_flow_data->dead) {
        ovs_mutex_unlock(&rte_flow_data->lock);
        /* Mutex unlock will do memory fence, ensuring the boolean update
         * is seen from other threads as well. */
        return 0;
    }

    rte_flow_data->dead = true;
    ufid_to_rte_flow_disassociate(netdev, rte_flow_data);

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
            ret = netdev_offload_dpdk_destroy_flow(flow_netdev, rte_flow,
                                                   fi->creation_tid, ufid);
            if (ret) {
                netdev_close(flow_netdev);
                goto out;
            }
        }
        netdev_close(flow_netdev);
    }

    ret = 0;
out:
    free_flow_handle(flows, true);
    ovs_mutex_unlock(&rte_flow_data->lock);
    if (!ret) {
        put_action_resources(netdev, &rte_flow_data->act_resources);
        ovsrcu_gc(ufid_to_rte_flow_data_gc, rte_flow_data, gc_node);
    }
    return ret;
}

static int
netdev_offload_dpdk_flow_put(struct netdev *netdev, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             const ovs_u128 *ufid, struct offload_info *info,
                             struct dpif_flow_stats *stats)
{
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct dpif_flow_stats old_stats;
    bool modification = false;
    int ret;

    do_context_delayed_release();

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     * Keep the stats for the newly created rule.
     */
    rte_flow_data = ufid_to_rte_flow_data_find(netdev, ufid, false);
    if (rte_flow_data) {
        old_stats = rte_flow_data->stats;
        modification = true;
        ret = netdev_offload_dpdk_remove_flows(netdev, rte_flow_data);
        if (ret < 0) {
            return ret;
        }
    }

    per_thread_init();

    rte_flow_data = netdev_offload_dpdk_add_flow(netdev, match, actions,
                                                 actions_len, ufid, info);
    if (!rte_flow_data) {
        return -1;
    }
    if (modification) {
        rte_flow_data->stats = old_stats;
    }
    if (stats) {
        *stats = rte_flow_data->stats;
    }
    return 0;
}

static int
netdev_offload_dpdk_flow_del(struct netdev *netdev OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats)
{
    struct ufid_to_rte_flow_data *rte_flow_data;

    do_context_delayed_release();

    rte_flow_data = ufid_to_rte_flow_data_find(netdev, ufid, true);
    if (!rte_flow_data) {
        VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow",
                  UUID_ARGS((struct uuid *) ufid));
        return -1;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return netdev_offload_dpdk_remove_flows(netdev, rte_flow_data);
}

static bool
offload_dpdk_flow_api_supported(struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class)
        && !strcmp(netdev_get_dpif_type(netdev), "system")) {
        VLOG_DBG("%s: vport belongs to the system datapath. Skipping.",
                 netdev_get_name(netdev));
        return false;
    }

    return netdev_dpdk_flow_api_supported(netdev) ? true : false;
}

static int
netdev_offload_dpdk_init_flow_api(struct netdev *netdev)
{
    int ret = EOPNOTSUPP;

    if (offload_dpdk_flow_api_supported(netdev)) {
        ret = offload_data_init(netdev);
    }

    return ret;
}

static void
netdev_offload_dpdk_deinit_flow_api(struct netdev *netdev)
{
    if (offload_dpdk_flow_api_supported(netdev)) {
        offload_data_destroy(netdev);
        ovsrcu_set(&netdev->hw_info.offload_data, NULL);
    }
}

static int
netdev_offload_dpdk_flow_get(struct netdev *netdev,
                             struct match *match OVS_UNUSED,
                             struct nlattr **actions OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats,
                             struct dpif_flow_attrs *attrs,
                             struct ofpbuf *buf OVS_UNUSED,
                             long long now)
{
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_query_count query;
    struct rte_flow_error error;
    struct netdev *flow_netdev;
    int ret = 0;
    int i;
    int j;

    attrs->dp_extra_info = NULL;

    rte_flow_data = ufid_to_rte_flow_data_find(netdev, ufid, false);
    if (!rte_flow_data || rte_flow_data->flows.cnt == 0 ||
        rte_flow_data->dead || ovs_mutex_trylock(&rte_flow_data->lock)) {
        return -1;
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
                VLOG_DBG_RL(&rl, "%s: Failed to query ufid "UUID_FMT" flow: %p",
                            netdev_get_name(netdev),
                            UUID_ARGS((struct uuid *) ufid), rte_flow);
                netdev_close(flow_netdev);
                goto out;
            }
            rte_flow_data->stats.n_packets += query.hits_set ? query.hits : 0;
            rte_flow_data->stats.n_bytes += query.bytes_set ? query.bytes : 0;
            if (query.hits_set && query.hits) {
                rte_flow_data->stats.used = now;
            }
        }
        netdev_close(flow_netdev);
    }
    memcpy(stats, &rte_flow_data->stats, sizeof *stats);
out:
    ovs_mutex_unlock(&rte_flow_data->lock);
    return ret;
}

static int
netdev_offload_dpdk_flow_flush(struct netdev *netdev)
{
    unsigned int tid = netdev_offload_thread_id();
    struct cmap *map = offload_data_map(netdev);
    struct ufid_to_rte_flow_data *data;

    if (!map) {
        return -1;
    }

    CMAP_FOR_EACH (data, node, map) {
        struct flows_handle *flows = &data->flows;

        /* Destroy flow rules that were inserted by
         * the current thread. */
        if (flows->items[0].creation_tid == tid) {
            netdev_offload_dpdk_remove_flows(netdev, data);
        }
    }

    return 0;
}

static int
netdev_offload_dpdk_hw_miss_packet_recover(struct netdev *netdev,
                                           uint32_t flow_miss_ctx_id,
                                           struct dp_packet *packet,
                                           uint8_t *skip_actions,
                                           struct dpif_sflow_attr *sflow_attr)
{
    struct flow_miss_ctx flow_miss_ctx;
    struct ct_miss_ctx ct_miss_ctx;
    struct sflow_ctx sflow_ctx;
    struct netdev *vport_netdev;
    uint32_t ct_ctx_id;
    uint32_t sflow_id;

    if (find_flow_miss_ctx(flow_miss_ctx_id, &flow_miss_ctx)) {
        /* Since sFlow does not work with CT, offloaded sampled packets
         * cannot have mark. If a packet without a mark reaches SW it
         * is either a sampled packet if a cookie is found or a datapath one.
         */
        if (get_packet_reg_field(packet, REG_FIELD_SFLOW_CTX, &sflow_id)) {
            return 0;
        }
        if (find_sflow_ctx(sflow_id, &sflow_ctx)) {
            VLOG_ERR("sFlow id %d is not found", sflow_id);
            return 0;
        }
        memcpy(sflow_attr->userdata, &sflow_ctx.cookie,
               sflow_ctx.sflow_attr.userdata_len);
        if (!is_all_zeros(&sflow_ctx.sflow_tnl, sizeof sflow_ctx.sflow_tnl)) {
            memcpy(sflow_attr->tunnel, &sflow_ctx.sflow_tnl,
                   sizeof *sflow_attr->tunnel);
        } else {
            sflow_attr->tunnel = NULL;
        }
        sflow_attr->sflow = sflow_ctx.sflow_attr.sflow;
        sflow_attr->sflow_len = sflow_ctx.sflow_attr.sflow_len;
        sflow_attr->userdata_len = sflow_ctx.sflow_attr.userdata_len;
        return EIO;
    }

    *skip_actions = flow_miss_ctx.skip_actions;
    packet->md.recirc_id = flow_miss_ctx.recirc_id;
    if (flow_miss_ctx.vport != ODPP_NONE) {
        if (is_all_zeros(&flow_miss_ctx.tnl, sizeof flow_miss_ctx.tnl)) {
            vport_netdev = netdev_ports_get(flow_miss_ctx.vport,
                                            netdev->dpif_type);
            if (vport_netdev) {
                pkt_metadata_init(&packet->md, flow_miss_ctx.vport);
                if (vport_netdev->netdev_class->pop_header) {
                    if (!vport_netdev->netdev_class->pop_header(packet)) {
                        netdev_close(vport_netdev);
                        return -1;
                    }
                    netdev_close(vport_netdev);
                    packet->md.in_port.odp_port = flow_miss_ctx.vport;
                } else {
                    VLOG_ERR("vport nedtdev=%s with no pop_header method",
                             netdev_get_name(vport_netdev));
                    netdev_close(vport_netdev);
                    return EOPNOTSUPP;
                }
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
            return 0;
        }
        packet->md.ct_state = ct_miss_ctx.state;
        packet->md.ct_zone = ct_miss_ctx.zone;
        packet->md.ct_mark = ct_miss_ctx.mark;
        packet->md.ct_label = ct_miss_ctx.label;
    }
    dp_packet_reset_offload(packet);

    return 0;
}

static int
netdev_offload_dpdk_hw_offload_stats_get(struct netdev *netdev,
                                         uint64_t *counters)
{
    struct netdev_offload_dpdk_data *data;
    unsigned int tid;

    data = (struct netdev_offload_dpdk_data *)
        ovsrcu_get(void *, &netdev->hw_info.offload_data);
    if (!data) {
        return -1;
    }

    for (tid = 0; tid < netdev_offload_thread_nb(); tid++) {
        counters[tid] = atomic_count_get64(&data->rte_flow_counters[tid]);
    }
    return 0;
}

static int
netdev_offload_dpdk_ct_counter_query(struct netdev *netdev OVS_UNUSED,
                                     uintptr_t counter_key,
                                     long long now,
                                     long long prev_now,
                                     struct dpif_flow_stats *stats)
{
    struct shared_age_ctx_data shared_age_ctx_data;
    struct context_data shared_age_id_ctx = {
        .data = &counter_key,
    };
    struct rte_flow_query_age query_age;
    struct netdev *shared_age_netdev;
    struct rte_flow_error error;
    uint32_t shared_age_id;
    int ret;

    memset(stats, 0, sizeof *stats);
    if (get_context_data_id_by_data(&shared_age_id_md, &shared_age_id_ctx,
                                    NULL, &shared_age_id)) {
        /* Getting a context from shared_age_id_md might fail normally. No
         * need to log an error.
         */
        return -1;
    }
    ret = get_context_data_by_id(&shared_age_ctx_md, shared_age_id,
                                 &shared_age_ctx_data);
    if (ret) {
        VLOG_ERR_RL(&rl, "Could not find data for shared_age_id=%d",
                    shared_age_id);
        goto err;
    }
    shared_age_netdev =
       netdev_dpdk_get_netdev_by_domain_id(shared_age_ctx_data.domain_id);
    if (!shared_age_netdev) {
        VLOG_ERR_RL(&rl, "Could not get netdev for domain_id=%"PRIu16,
                    shared_age_ctx_data.domain_id);
        ret = -1;
        goto err;
    }
    ret = netdev_dpdk_indirect_action_query(shared_age_netdev,
                                            shared_age_ctx_data.action_hdl,
                                            &query_age, &error);
    if (!ret && query_age.sec_since_last_hit_valid &&
        (query_age.sec_since_last_hit * 1000) <= (now - prev_now)) {
        stats->used = now;
    }
    netdev_close(shared_age_netdev);
err:
    put_context_data_by_id(&shared_age_id_md, NULL, shared_age_id);
    return ret;
}

const struct netdev_flow_api netdev_offload_dpdk = {
    .type = "dpdk_flow_api",
    .flow_put = netdev_offload_dpdk_flow_put,
    .flow_del = netdev_offload_dpdk_flow_del,
    .init_flow_api = netdev_offload_dpdk_init_flow_api,
    .deinit_flow_api = netdev_offload_dpdk_deinit_flow_api,
    .flow_get = netdev_offload_dpdk_flow_get,
    .flow_flush = netdev_offload_dpdk_flow_flush,
    .hw_miss_packet_recover = netdev_offload_dpdk_hw_miss_packet_recover,
    .hw_offload_stats_get = netdev_offload_dpdk_hw_offload_stats_get,
    .ct_counter_query = netdev_offload_dpdk_ct_counter_query,
};
