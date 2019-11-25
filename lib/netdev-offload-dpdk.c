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

#include <rte_flow.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "netdev-vport.h"
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"
#include "netdev-offload-dpdk-private.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk);

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

struct flow_item {
    struct netdev *netdev;
    struct rte_flow *rte_flow;
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
    struct flow_action_resources act_resources;
};

static void
flow_handle_free(struct flows_handle *flows)
{
    /* When calling this function 'flows' must be valid */
    free(flows->items);
    flows->items = NULL;
    flows->cnt = 0;
}

static void
flow_handle_add(struct flows_handle *flows,
                struct netdev *netdev,
                struct rte_flow *rte_flow)
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

    flows->items[cnt].netdev = netdev;
    flows->items[cnt].rte_flow = rte_flow;
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
                           struct flows_handle *flows,
                           struct flow_action_resources *act_resources)
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

static void
put_action_resources(struct flow_action_resources *act_resources)
{
    put_table_id(act_resources->self_table_id);
    put_table_id(act_resources->table_id);
    put_flow_miss_ctx_id(act_resources->flow_miss_ctx_id);
}

static struct rte_flow *
netdev_offload_dpdk_mark_rss(struct flow_patterns *patterns,
                             struct netdev *netdev, uint32_t flow_mark)
{
    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow_error error;
    struct rte_flow *flow;

    netdev_dpdk_flow_actions_add_mark_rss(&actions, netdev, flow_mark);
    flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr,
                                       patterns->items,
                                       actions.actions, &error);
    if (!flow) {
        VLOG_ERR("%s: rte flow create error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
    }
    netdev_dpdk_flow_actions_free(&actions);
    return flow;
}

static int
netdev_offload_dpdk_create_tnl_flows(struct flow_patterns *patterns,
                                     struct flow_actions *actions,
                                     struct offload_info *info,
                                     struct flow_action_resources *action_resources,
                                     struct flows_handle *flows)
{
    struct rte_flow_attr flow_attr = { .ingress = 1, .transfer = 1 };
    struct netdev_flow_dump **netdev_dumps;
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    int num_ports = 0;
    int ret;
    int i;

    netdev_dumps = netdev_ports_flow_dump_create(info->dpif_type_str, &num_ports);
    flow_attr.group = action_resources->self_table_id;
    for (i = 0; i < num_ports; i++) {
        if (!netdev_dpdk_is_uplink_port(netdev_dumps[i]->netdev)) {
            continue;
        }
        flow = netdev_dpdk_rte_flow_create(netdev_dumps[i]->netdev,
                                           &flow_attr,
                                           patterns->items,
                                           actions->actions, &error);
        if (!flow) {
            VLOG_DBG("%s: rte flow create error: %u : message : %s\n",
                     netdev_get_name(netdev_dumps[i]->netdev), error.type,
                     error.message);
            continue;
        }
        flow_handle_add(flows, netdev_dumps[i]->netdev, flow);
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
                            struct offload_info *info,
                            struct flow_action_resources *act_resources,
                            struct flows_handle *flows)
{
    const struct rte_flow_attr flow_attr = { .ingress = 1, .transfer = 1 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    int ret;

    if (!strcmp(netdev_get_type(netdev), "vxlan")) {
        netdev_dpdk_flow_add_vxlan_decap_actions(&actions);
    }
    ret = netdev_dpdk_flow_actions_add(&actions, nl_actions, actions_len, info,
                                       act_resources);
    if (ret) {
        goto out;
    }
    if (!strcmp(netdev_get_type(netdev), "vxlan")) {
        ret = netdev_offload_dpdk_create_tnl_flows(patterns, &actions, info,
                                                   act_resources, flows);
    } else {
        flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr, patterns->items,
                                           actions.actions, &error);
        if (!flow) {
            VLOG_ERR("%s: rte flow create error: %u : message : %s\n",
                     netdev_get_name(netdev), error.type, error.message);
            ret = -1;
        }
        flow_handle_add(flows, netdev, flow);
    }
    if (!ret && info->actions_offloaded) {
        *info->actions_offloaded = true;
    }
out:
    netdev_dpdk_flow_actions_free(&actions);
    return ret;
}

static int
netdev_offload_dpdk_add_flow(struct netdev *netdev,
                             const struct match *match,
                             struct nlattr *nl_actions,
                             size_t actions_len,
                             const ovs_u128 *ufid,
                             struct offload_info *info)
{
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flows_handle flows = { .items = NULL, .cnt = 0 };
    struct flow_action_resources act_resources = {0};
    struct match consumed_match;
    struct rte_flow *flow = NULL;
    int ret;

    memcpy(&consumed_match, match, sizeof consumed_match);

    ret = netdev_dpdk_flow_patterns_add(netdev, &patterns, &consumed_match);
    if (ret) {
        VLOG_WARN("Adding rte match patterns for flow ufid"UUID_FMT" failed",
                  UUID_ARGS((struct uuid *)ufid));
        goto out;
    }
    if (netdev_vport_is_vport_class(netdev->netdev_class)) {
        ret = get_table_id(match->flow.in_port.odp_port,
                           &act_resources.self_table_id);
        if (ret) {
            goto out;
        }
    }

    ret = netdev_offload_dpdk_actions(netdev, &patterns, nl_actions,
                                      actions_len, info, &act_resources,
                                      &flows);
    if (ret) {
        /* if we failed to offload the rule actions fallback to mark rss
         * actions.
         */
        flow = act_resources.self_table_id == 0 ?
            netdev_offload_dpdk_mark_rss(&patterns, netdev, info->flow_mark) :
            NULL;
        if (!flow) {
            ret = -1;
            goto out;
        }
        flow_handle_add(&flows, netdev, flow);
    }
    ufid_to_rte_flow_associate(ufid, &flows, &act_resources);
    VLOG_DBG("%s: installed flow %p by ufid "UUID_FMT"\n",
             netdev_get_name(netdev), flow, UUID_ARGS((struct uuid *)ufid));

out:
    netdev_dpdk_flow_patterns_free(&patterns);
    if (ret) {
        put_action_resources(&act_resources);
    }
    return ret;
}

static int
netdev_offload_dpdk_destroy_flow(struct netdev *netdev OVS_UNUSED,
                                 const ovs_u128 *ufid,
                                 struct flows_handle *flows)
{
    struct ufid_to_rte_flow_data *data;
    struct rte_flow_error error;
    int ret;
    int i;

    for (i = 0; i < flows->cnt; i++) {
        ret = netdev_dpdk_rte_flow_destroy(flows->items[i].netdev,
                                           flows->items[i].rte_flow,
                                           &error);
        if (!ret) {
            VLOG_DBG("%s: removed rte flow %p associated with ufid " UUID_FMT "\n",
                     netdev_get_name(flows->items[i].netdev),
                     flows->items[i].rte_flow,
                     UUID_ARGS((struct uuid *)ufid));
        } else {
            VLOG_ERR("%s: rte flow destroy error: %u : message : %s\n",
                     netdev_get_name(flows->items[i].netdev), error.type,
                     error.message);
            return ret;
        }
    }

    data = ufid_to_rte_flow_data_find(ufid);
    if (!data) {
        VLOG_WARN("ufid "UUID_FMT" is not associated with rte flow(s)\n",
                  UUID_ARGS((struct uuid *) ufid));
        return -1;
    }
    put_action_resources(&data->act_resources);
    ufid_to_rte_flow_disassociate(data);
    flow_handle_free(flows);

    return 0;
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
        ret = netdev_offload_dpdk_destroy_flow(netdev, ufid,
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
    return netdev_offload_dpdk_destroy_flow(netdev, ufid,
                                            &rte_flow_data->flows);
}

static int
netdev_offload_dpdk_flow_flush(struct netdev *netdev)
{
    struct rte_flow_error error;
    int ret;

    ret = netdev_dpdk_rte_flow_flush(netdev, &error);
    if (ret) {
        VLOG_ERR("%s: rte flow flush error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
    }

    return ret;
}

static int
netdev_offload_dpdk_init_flow_api(struct netdev *netdev)
{
    return netdev_dpdk_flow_api_supported(netdev) ? 0 : EOPNOTSUPP;
}

static bool
netdev_offload_dpdk_flow_dump_next(struct netdev_flow_dump *dump OVS_UNUSED,
                                   struct match *match OVS_UNUSED,
                                   struct nlattr **actions OVS_UNUSED,
                                   struct dpif_flow_stats *stats,
                                   struct dpif_flow_attrs *attrs OVS_UNUSED,
                                   ovs_u128 *ufid,
                                   struct ofpbuf *rbuffer OVS_UNUSED,
                                   struct ofpbuf *wbuffer OVS_UNUSED)
{
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_query_count query;
    struct rte_flow_error error;
    int ret;
    int i;

    rte_flow_data = ufid_to_rte_flow_data_find(ufid);
    if (!rte_flow_data || rte_flow_data->flows.cnt == 0) {
        return -1;
    }

    memset(stats, 0, sizeof *stats);

    for (i = 0; i < rte_flow_data->flows.cnt; i++) {
        memset(&query, 0, sizeof query);
        /* reset counters after query */
        query.reset = 1;
        ret = netdev_dpdk_rte_flow_query(rte_flow_data->flows.items[i].netdev,
                                         rte_flow_data->flows.items[i].rte_flow,
                                         &query, &error);
        if (ret) {
            VLOG_DBG("ufid "UUID_FMT
                     " flow %p query for '%s' failed\n",
                     UUID_ARGS((struct uuid *)ufid),
                     rte_flow_data->flows.items[i].rte_flow,
                     netdev_get_name(rte_flow_data->flows.items[i].netdev));
            return false;
        }
        stats->n_packets += (query.hits_set) ? query.hits : 0;
        stats->n_bytes += (query.bytes_set) ? query.bytes : 0;
    }

    return true;
}

static int
netdev_offload_dpdk_hw_miss_packet_recover(uint32_t flow_miss_ctx_id,
                                           struct dp_packet *packet,
                                           const char *dpif_type_str)
{
    struct flow_miss_ctx *flow_miss_ctx;
    struct netdev *netdev;

    flow_miss_ctx = find_flow_miss_ctx(flow_miss_ctx_id);
    if (!flow_miss_ctx) {
        return -1;
    }
    parse_tcp_flags(packet);
    pkt_metadata_init(&packet->md, flow_miss_ctx->vport);

    netdev = netdev_ports_get(flow_miss_ctx->vport, dpif_type_str);
    if (netdev) {
        if (netdev->netdev_class->pop_header) {
            netdev->netdev_class->pop_header(packet);
            dp_packet_reset_offload(packet);
            packet->md.in_port.odp_port = flow_miss_ctx->vport;
        }
        netdev_close(netdev);
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
    .flow_flush = netdev_offload_dpdk_flow_flush,
    .flow_put = netdev_offload_dpdk_flow_put,
    .flow_del = netdev_offload_dpdk_flow_del,
    .init_flow_api = netdev_offload_dpdk_init_flow_api,
    .flow_dump_next = netdev_offload_dpdk_flow_dump_next,
    .hw_miss_packet_recover = netdev_offload_dpdk_hw_miss_packet_recover,
    .flow_dump_create = netdev_offload_dpdk_flow_dump_create,
    .flow_dump_destroy = netdev_offload_dpdk_flow_dump_destroy,
};
