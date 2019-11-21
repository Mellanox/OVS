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

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct rte_flow *rte_flow;
    struct flow_action_resources act_resources;
};

/* Find rte_flow with @ufid. */
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
                           struct rte_flow *rte_flow,
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
        ovs_assert(data_prev->rte_flow == NULL);
    }

    data->ufid = *ufid;
    data->rte_flow = rte_flow;
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

static struct rte_flow *
netdev_offload_dpdk_actions(struct netdev *netdev,
                            struct flow_patterns *patterns,
                            struct nlattr *nl_actions,
                            size_t actions_len,
                            struct offload_info *info,
                            struct flow_action_resources *act_resources)
{
    const struct rte_flow_attr flow_attr = { .ingress = 1, .transfer = 1 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    int ret;

    ret = netdev_dpdk_flow_actions_add(&actions, nl_actions, actions_len, info,
                                       act_resources);
    if (ret) {
        goto out;
    }
    flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr, patterns->items,
                                       actions.actions, &error);
    if (!flow) {
        VLOG_ERR("%s: rte flow create error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
    }
    if (flow && info->actions_offloaded) {
        *info->actions_offloaded = true;
    }
out:
    netdev_dpdk_flow_actions_free(&actions);
    return flow;
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
    struct flow_action_resources act_resources = {0};
    struct rte_flow *flow;
    int ret = 0;

    ret = netdev_dpdk_flow_patterns_add(&patterns, match);
    if (ret) {
        VLOG_WARN("Adding rte match patterns for flow ufid"UUID_FMT" failed",
                  UUID_ARGS((struct uuid *)ufid));
        goto out;
    }

    flow = netdev_offload_dpdk_actions(netdev, &patterns, nl_actions,
                                       actions_len, info, &act_resources);
    if (!flow) {
        /* if we failed to offload the rule actions fallback to mark rss
         * actions.
         */
        flow = netdev_offload_dpdk_mark_rss(&patterns, netdev, info->flow_mark);
    }
    if (!flow) {
        ret = -1;
        goto out;
    }
    ufid_to_rte_flow_associate(ufid, flow, &act_resources);
    VLOG_DBG("%s: installed flow %p by ufid "UUID_FMT"\n",
             netdev_get_name(netdev), flow, UUID_ARGS((struct uuid *)ufid));

out:
    netdev_dpdk_flow_patterns_free(&patterns);
    if (ret) {
        put_action_resources(&act_resources);
    }
    return ret;
}

/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_offload_dpdk_validate_flow(const struct match *match)
{
    struct match match_zero_wc;
    const struct flow *masks = &match->wc.masks;

    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (!is_all_zeros(&match_zero_wc.flow.tunnel,
                      sizeof match_zero_wc.flow.tunnel)) {
        goto err;
    }

    if (masks->metadata || masks->skb_priority ||
        masks->pkt_mark || masks->dp_hash) {
        goto err;
    }

    /* recirc id must be zero. */
    if (match_zero_wc.flow.recirc_id) {
        goto err;
    }

    if (masks->ct_state || masks->ct_nw_proto ||
        masks->ct_zone  || masks->ct_mark     ||
        !ovs_u128_is_zero(masks->ct_label)) {
        goto err;
    }

    if (masks->conj_id || masks->actset_output) {
        goto err;
    }

    /* Unsupported L2. */
    if (!is_all_zeros(masks->mpls_lse, sizeof masks->mpls_lse)) {
        goto err;
    }

    /* Unsupported L3. */
    if (masks->ipv6_label || masks->ct_nw_src || masks->ct_nw_dst     ||
        !is_all_zeros(&masks->ipv6_src,    sizeof masks->ipv6_src)    ||
        !is_all_zeros(&masks->ipv6_dst,    sizeof masks->ipv6_dst)    ||
        !is_all_zeros(&masks->ct_ipv6_src, sizeof masks->ct_ipv6_src) ||
        !is_all_zeros(&masks->ct_ipv6_dst, sizeof masks->ct_ipv6_dst) ||
        !is_all_zeros(&masks->nd_target,   sizeof masks->nd_target)   ||
        !is_all_zeros(&masks->nsh,         sizeof masks->nsh)         ||
        !is_all_zeros(&masks->arp_sha,     sizeof masks->arp_sha)     ||
        !is_all_zeros(&masks->arp_tha,     sizeof masks->arp_tha)) {
        goto err;
    }

    /* If fragmented, then don't HW accelerate - for now. */
    if (match_zero_wc.flow.nw_frag) {
        goto err;
    }

    /* Unsupported L4. */
    if (masks->igmp_group_ip4 || masks->ct_tp_src || masks->ct_tp_dst) {
        goto err;
    }

    return 0;

err:
    VLOG_ERR("cannot HW accelerate this flow due to unsupported protocols");
    return -1;
}

static int
netdev_offload_dpdk_destroy_flow(struct netdev *netdev,
                                 const ovs_u128 *ufid,
                                 struct rte_flow *rte_flow)
{
    struct ufid_to_rte_flow_data *data;
    struct rte_flow_error error;
    int ret;

    ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);

    if (ret == 0) {
        data = ufid_to_rte_flow_data_find(ufid);
        if (!data) {
            VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow\n",
                      UUID_ARGS((struct uuid *) ufid));
            return -1;
        }
        put_action_resources(&data->act_resources);
        ufid_to_rte_flow_disassociate(data);
        VLOG_DBG("%s: removed rte flow %p associated with ufid " UUID_FMT "\n",
                 netdev_get_name(netdev), rte_flow,
                 UUID_ARGS((struct uuid *)ufid));
    } else {
        VLOG_ERR("%s: rte flow destroy error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
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
    int ret;

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    rte_flow_data = ufid_to_rte_flow_data_find(ufid);
    if (rte_flow_data && rte_flow_data->rte_flow) {
        ret = netdev_offload_dpdk_destroy_flow(netdev, ufid,
                                               rte_flow_data->rte_flow);
        if (ret < 0) {
            return ret;
        }
    }

    ret = netdev_offload_dpdk_validate_flow(match);
    if (ret < 0) {
        return ret;
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
    if (!rte_flow_data || !rte_flow_data->rte_flow) {
        return -1;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return netdev_offload_dpdk_destroy_flow(netdev, ufid,
                                            rte_flow_data->rte_flow);
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
    if (netdev_vport_is_vport_class(netdev->netdev_class)
        && !strcmp(netdev_get_dpif_type(netdev), "system")) {
        VLOG_DBG("%s: vport belongs to the system datapath. Skipping.",
                 netdev_get_name(netdev));
        return EOPNOTSUPP;
    }

    return netdev_dpdk_flow_api_supported(netdev) ? 0 : EOPNOTSUPP;
}

static bool
netdev_offload_dpdk_flow_dump_next(struct netdev_flow_dump *dump,
                                   struct match *match OVS_UNUSED,
                                   struct nlattr **actions OVS_UNUSED,
                                   struct dpif_flow_stats *stats,
                                   struct dpif_flow_attrs *attrs OVS_UNUSED,
                                   ovs_u128 *ufid,
                                   struct ofpbuf *rbuffer OVS_UNUSED,
                                   struct ofpbuf *wbuffer OVS_UNUSED)
{
    struct rte_flow_query_count query = { .reset = 1 };
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_error error;
    int ret;

    rte_flow_data = ufid_to_rte_flow_data_find(ufid);
    if (!rte_flow_data || !rte_flow_data->rte_flow) {
        return false;
    }

    memset(stats, 0, sizeof *stats);
    ret = netdev_dpdk_rte_flow_query(dump->netdev, rte_flow_data->rte_flow,
                                     &query, &error);
    if (ret) {
        VLOG_DBG("ufid "UUID_FMT
                 " flow %p query for '%s' failed\n",
                 UUID_ARGS((struct uuid *)ufid), rte_flow_data->rte_flow,
                 netdev_get_name(dump->netdev));
        return false;
    }
    stats->n_packets += (query.hits_set) ? query.hits : 0;
    stats->n_bytes += (query.bytes_set) ? query.bytes : 0;

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
