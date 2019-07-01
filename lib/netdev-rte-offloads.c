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
#include "netdev-rte-offloads.h"

#include <rte_flow.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "netdev-provider.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"

#define VXLAN_EXCEPTION_MARK (MIN_RESERVED_MARK + 0)
#define VXLAN_TABLE_ID       1

VLOG_DEFINE_THIS_MODULE(netdev_rte_offloads);
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(100, 5);

#define RTE_FLOW_MAX_TABLES (31)
#define INVALID_ODP_PORT (-1)

enum rte_port_type {
    RTE_PORT_TYPE_UNINIT = 0,
    RTE_PORT_TYPE_DPDK,
    RTE_PORT_TYPE_VXLAN
};

/*
 * A mapping from dp_port to flow parameters.
 */
struct netdev_rte_port {
    struct cmap_node node; /* Map by datapath port number. */
    odp_port_t dp_port; /* Datapath port number. */
    uint16_t dpdk_port_id; /* Id of the DPDK port. */
    struct netdev *netdev; /* struct *netdev of this port. */
    enum rte_port_type rte_port_type; /* rte ports types. */
    uint32_t table_id; /* Flow table id per related to this port. */
    uint16_t dpdk_num_queues; /* Number of dpdk queues of this port. */
    uint32_t exception_mark; /* Exception SW handling for this port type. */
    struct cmap ufid_to_rte;
    struct rte_flow *default_rte_flow[RTE_FLOW_MAX_TABLES];
    struct cmap_node mark_node;
};

static struct cmap port_map = CMAP_INITIALIZER;
static struct cmap mark_to_rte_port = CMAP_INITIALIZER;

static uint32_t dpdk_phy_ports_amount = 0;
/*
 * Search for offloaded port data by dp_port no.
 */
static struct netdev_rte_port *
netdev_rte_port_search(odp_port_t dp_port, struct cmap *map)
{
    size_t hash = hash_bytes(&dp_port, sizeof dp_port, 0);
    struct netdev_rte_port *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (dp_port == data->dp_port) {
            return data;
        }
    }

    return NULL;
}

/*
 * Allocate a new entry in port_map for dp_port (if not already allocated)
 * and set it with netdev, dp_port and port_type parameters.
 * rte_port is an output parameter which contains the newly allocated struct
 * or NULL in case it could not be allocated or found.
 *
 * Returns 0 on success, ENOMEM otherwise (in which case rte_port is NULL).
 */
static int
netdev_rte_port_set(struct netdev *netdev, odp_port_t dp_port,
                    enum rte_port_type port_type,
                    struct netdev_rte_port **rte_port)
{
    *rte_port = netdev_rte_port_search(dp_port, &port_map);
    if (*rte_port) {
        VLOG_DBG("Rte_port for datapath port %d already exists.", dp_port);
        goto next;
    }
    *rte_port = xzalloc(sizeof **rte_port);
    if (!*rte_port) {
        VLOG_ERR("Failed to alloctae ret_port for datapath port %d.", dp_port);
        return ENOMEM;
    }
    size_t hash = hash_bytes(&dp_port, sizeof dp_port, 0);
    cmap_insert(&port_map,
                CONST_CAST(struct cmap_node *, &(*rte_port)->node), hash);
    cmap_init(&((*rte_port)->ufid_to_rte));

next:
    (*rte_port)->netdev = netdev;
    (*rte_port)->dp_port = dp_port;
    (*rte_port)->rte_port_type = port_type;

    return 0;
}

struct ufid_hw_offload {
    struct cmap_node node;
    ovs_u128 ufid;
    int max_flows;
    int curr_idx;
    struct rte_flow_params {
        struct rte_flow *flow;
        struct netdev *netdev;
    } rte_flow_data[0];
};

/*
 * fuid hw offload struct contains array of pointers to rte flows.
 * There may be a one OVS flow to many rte flows. For example in case
 * of vxlan OVS flow we add an rte flow per each phsical port.
 *
 * max_flows - number of expected max rte flows for this ufid.
 * ufid - the ufid.
 *
 * Return allocated struct ufid_hw_offload or NULL if allocation failed.
 */
static struct ufid_hw_offload *
netdev_rte_port_ufid_hw_offload_alloc(int max_flows, const ovs_u128 *ufid)
{
    struct ufid_hw_offload *ufidol =
        xzalloc(sizeof(struct ufid_hw_offload) +
                       sizeof(struct rte_flow_params) * max_flows);
    if (ufidol) {
        ufidol->max_flows = max_flows;
        ufidol->curr_idx = 0;
        ufidol->ufid = *ufid;
    }

    return ufidol;
}

/*
 * Given ufid find its hw_offload struct.
 *
 * Return struct ufid_hw_offload or NULL if not found.
 */
static struct ufid_hw_offload *
ufid_hw_offload_find(const ovs_u128 *ufid, struct cmap *map)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_hw_offload *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static struct ufid_hw_offload *
ufid_hw_offload_remove(const ovs_u128 *ufid, struct cmap *map)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_hw_offload *data = ufid_hw_offload_find(ufid,map);

    if (data) {
        cmap_remove(map, CONST_CAST(struct cmap_node *, &data->node), hash);
    }
    return data;
}

static void
ufid_hw_offload_add(struct ufid_hw_offload *hw_offload, struct cmap *map)
{
    size_t hash = hash_bytes(&hw_offload->ufid, sizeof(ovs_u128), 0);
    cmap_insert(map, CONST_CAST(struct cmap_node *, &hw_offload->node), hash);
}

static void
ufid_hw_offload_add_rte_flow(struct ufid_hw_offload *hw_offload,
                             struct rte_flow *rte_flow,
                             struct netdev *netdev)
{
    if (hw_offload->curr_idx < hw_offload->max_flows) {
        hw_offload->rte_flow_data[hw_offload->curr_idx].flow = rte_flow;
        hw_offload->rte_flow_data[hw_offload->curr_idx].netdev = netdev;
        hw_offload->curr_idx++;
    } else {
        struct rte_flow_error error;
        int ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);
        if (ret) {
            VLOG_ERR_RL(&error_rl, "rte flow destroy error: %u : message :"
                       " %s\n", error.type, error.message);
        }
    }
}

/*
 * If hw rules were introduced we make sure we clean them before
 * we free the struct.
 */
static int
netdev_rte_port_ufid_hw_offload_free(struct ufid_hw_offload *hw_offload)
{
    struct rte_flow_error error;

    VLOG_DBG("clean all rte flows for ufid "UUID_FMT".\n",
             UUID_ARGS((struct uuid *)&hw_offload->ufid));

    for (int i = 0 ; i < hw_offload->curr_idx ; i++) {
        if (hw_offload->rte_flow_data[i].flow) {
            VLOG_DBG("rte_destory for flow "UUID_FMT" is called.",
                     UUID_ARGS((struct uuid *)&hw_offload->ufid));
            int ret =
                netdev_dpdk_rte_flow_destroy(hw_offload->rte_flow_data[i].netdev,
                                             hw_offload->rte_flow_data[i].flow,
                                             &error);
            if (ret) {
                VLOG_ERR_RL(&error_rl,
                            "rte flow destroy error: %u : message : %s.\n",
                            error.type, error.message);
            }
        }
        hw_offload->rte_flow_data[i].flow = NULL;
    }

    free(hw_offload);
    return 0;
}

struct ufid_to_odp {
    struct cmap_node node;
    ovs_u128 ufid;
    odp_port_t dp_port;
};

static struct cmap ufid_to_portid_map = CMAP_INITIALIZER;

/*
 * Search for ufid mapping
 *
 * Return ref to object and not a copy.
 */
static struct ufid_to_odp *
ufid_to_portid_get(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_odp *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_portid_map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static odp_port_t
ufid_to_portid_search(const ovs_u128 *ufid)
{
   struct ufid_to_odp *data = ufid_to_portid_get(ufid);

   return (data) ? data->dp_port : INVALID_ODP_PORT;
}

/*
 * Save the ufid->dp_port mapping.
 *
 * Return the port if saved successfully.
 */
static odp_port_t
ufid_to_portid_add(const ovs_u128 *ufid, odp_port_t dp_port)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_odp *data;

    if (ufid_to_portid_search(ufid) != INVALID_ODP_PORT) {
        return dp_port;
    }

    data = xzalloc(sizeof *data);
    if (!data) {
        VLOG_WARN("Failed to add ufid to odp, (ENOMEM)");
        return INVALID_ODP_PORT;
    }

    data->ufid = *ufid;
    data->dp_port = dp_port;

    cmap_insert(&ufid_to_portid_map,
                CONST_CAST(struct cmap_node *, &data->node), hash);

    return dp_port;
}

/*
 * Remove the mapping if exists.
 */
static void
ufid_to_portid_remove(const ovs_u128 *ufid)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_odp *data = ufid_to_portid_get(ufid);

    if (data != NULL) {
        cmap_remove(&ufid_to_portid_map,
                    CONST_CAST(struct cmap_node *, &data->node), hash);
        free(data);
    }
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
free_flow_patterns(struct flow_patterns *patterns)
{
    /* When calling this function 'patterns' must be valid */
    free(patterns->items);
    patterns->items = NULL;
    patterns->cnt = 0;
}

static void
free_flow_actions(struct flow_actions *actions)
{
    /* When calling this function 'actions' must be valid */
    free(actions->actions);
    actions->actions = NULL;
    actions->cnt = 0;
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

struct action_rss_data {
    struct rte_flow_action_rss conf;
    uint16_t queue[0];
};

static struct action_rss_data *
add_flow_rss_action(struct flow_actions *actions,
                    uint16_t num_queues)
{
    int i;
    struct action_rss_data *rss_data;

    rss_data = xmalloc(sizeof *rss_data +
                       num_queues * sizeof rss_data->queue[0]);
    *rss_data = (struct action_rss_data) {
        .conf = (struct rte_flow_action_rss) {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = 0,
            .queue_num = num_queues,
            .queue = rss_data->queue,
            .key_len = 0,
            .key  = NULL
        },
    };

    /* Override queue array with default. */
    for (i = 0; i < num_queues; i++) {
       rss_data->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);

    return rss_data;
}

struct flow_items {
    struct rte_flow_item_eth  eth;
    struct rte_flow_item_vlan vlan;
    struct rte_flow_item_ipv4 ipv4;
    struct rte_flow_item_vxlan vxlan;
    union {
        struct rte_flow_item_tcp  tcp;
        struct rte_flow_item_udp  udp;
        struct rte_flow_item_sctp sctp;
        struct rte_flow_item_icmp icmp;
    };
};

static int
add_flow_patterns(struct flow_patterns *patterns,
                  struct flow_items *spec,
                  struct flow_items *mask,
                  const struct match *match)
{
    /* Eth */
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        memcpy(&spec->eth.dst, &match->flow.dl_dst, sizeof spec->eth.dst);
        memcpy(&spec->eth.src, &match->flow.dl_src, sizeof spec->eth.src);
        spec->eth.type = match->flow.dl_type;

        memcpy(&mask->eth.dst, &match->wc.masks.dl_dst, sizeof mask->eth.dst);
        memcpy(&mask->eth.src, &match->wc.masks.dl_src, sizeof mask->eth.src);
        mask->eth.type = match->wc.masks.dl_type;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH,
                         &spec->eth, &mask->eth);
    } else {
        /* If user specifies a flow (like UDP flow) without L2 patterns,
         * OVS will at least set the dl_type. Normally, it's enough to
         * create an eth pattern just with it. Unluckily, some Intel's
         * NIC (such as XL710) doesn't support that. Below is a workaround,
         * which simply matches any L2 pkts.
         */
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
    }

    /* VLAN */
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        spec->vlan.tci  = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask->vlan.tci  = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* Match any protocols. */
        mask->vlan.inner_type = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VLAN,
                         &spec->vlan, &mask->vlan);
    }

    /* IP v4 */
    uint8_t proto = 0;
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        spec->ipv4.hdr.type_of_service = match->flow.nw_tos;
        spec->ipv4.hdr.time_to_live    = match->flow.nw_ttl;
        spec->ipv4.hdr.next_proto_id   = match->flow.nw_proto;
        spec->ipv4.hdr.src_addr        = match->flow.nw_src;
        spec->ipv4.hdr.dst_addr        = match->flow.nw_dst;

        mask->ipv4.hdr.type_of_service = match->wc.masks.nw_tos;
        mask->ipv4.hdr.time_to_live    = match->wc.masks.nw_ttl;
        mask->ipv4.hdr.next_proto_id   = match->wc.masks.nw_proto;
        mask->ipv4.hdr.src_addr        = match->wc.masks.nw_src;
        mask->ipv4.hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &spec->ipv4, &mask->ipv4);

        /* Save proto for L4 protocol setup. */
        proto = spec->ipv4.hdr.next_proto_id &
                mask->ipv4.hdr.next_proto_id;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        return -1;
    }

    if ((match->wc.masks.tp_src && match->wc.masks.tp_src != OVS_BE16_MAX) ||
        (match->wc.masks.tp_dst && match->wc.masks.tp_dst != OVS_BE16_MAX)) {
        return -1;
    }

    switch (proto) {
    case IPPROTO_TCP:
        spec->tcp.hdr.src_port  = match->flow.tp_src;
        spec->tcp.hdr.dst_port  = match->flow.tp_dst;
        spec->tcp.hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        spec->tcp.hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        mask->tcp.hdr.src_port  = match->wc.masks.tp_src;
        mask->tcp.hdr.dst_port  = match->wc.masks.tp_dst;
        mask->tcp.hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        mask->tcp.hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP,
                         &spec->tcp, &mask->tcp);

        /* proto == TCP and ITEM_TYPE_TCP, thus no need for proto match. */
        mask->ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_UDP:
        spec->udp.hdr.src_port = match->flow.tp_src;
        spec->udp.hdr.dst_port = match->flow.tp_dst;

        mask->udp.hdr.src_port = match->wc.masks.tp_src;
        mask->udp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &spec->udp, &mask->udp);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match. */
        mask->ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_SCTP:
        spec->sctp.hdr.src_port = match->flow.tp_src;
        spec->sctp.hdr.dst_port = match->flow.tp_dst;

        mask->sctp.hdr.src_port = match->wc.masks.tp_src;
        mask->sctp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_SCTP,
                         &spec->sctp, &mask->sctp);

        /* proto == SCTP and ITEM_TYPE_SCTP, thus no need for proto match. */
        mask->ipv4.hdr.next_proto_id = 0;
        break;

    case IPPROTO_ICMP:
        spec->icmp.hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec->icmp.hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask->icmp.hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask->icmp.hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ICMP,
                         &spec->icmp, &mask->icmp);

        /* proto == ICMP and ITEM_TYPE_ICMP, thus no need for proto match. */
        mask->ipv4.hdr.next_proto_id = 0;
        break;
    }

    return 0;
}

static struct netdev_rte_port *
netdev_rte_add_jump_flow_action(const struct nlattr *nlattr,
                                struct rte_flow_action_jump *jump,
                                struct flow_actions *actions)
{
    odp_port_t odp_port;
    struct netdev_rte_port *rte_port;

    odp_port = nl_attr_get_odp_port(nlattr);
    rte_port = netdev_rte_port_search(odp_port, &port_map);
    if (!rte_port) {
        VLOG_DBG("No rte port was found for odp_port %u",
                odp_to_u32(odp_port));
        return NULL;
    }

    jump->group = rte_port->table_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump);

    return rte_port;
}

static void
netdev_rte_add_count_flow_action(struct rte_flow_action_count *count,
                                 struct flow_actions *actions)
{
    count->shared = 0;
    count->id = 0; /* Each flow has a single count action, so no need of id */
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, count);
}

static void
netdev_rte_add_port_id_flow_action(struct rte_flow_action_port_id *port_id,
                                   struct flow_actions *actions)
{
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_PORT_ID, port_id);
}

static struct rte_flow *
netdev_rte_offload_mark_rss(struct netdev *netdev,
                            struct offload_info *info,
                            struct flow_patterns *patterns,
                            struct flow_actions *actions,
                            struct rte_flow_action_port_id *port_id,
                            const struct rte_flow_attr *flow_attr)
{
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;

    struct rte_flow_action_mark mark = {0};
    mark.id = info->flow_mark;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);

    struct action_rss_data *rss = NULL;
    rss = add_flow_rss_action(actions, netdev_n_rxq(netdev));

    if (port_id) {
        netdev_rte_add_port_id_flow_action(port_id, actions);
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    flow = netdev_dpdk_rte_flow_create(netdev, flow_attr, patterns->items,
                                       actions->actions, &error);

    free(rss);
    if (!flow) {
        VLOG_ERR("%s: rte flow create offload error: %u : message : %s\n",
                netdev_get_name(netdev), error.type, error.message);
    }

    return flow;
}

static struct rte_flow *
netdev_rte_offload_flow(struct netdev *netdev,
                        struct offload_info *info,
                        struct flow_patterns *patterns,
                        struct flow_actions *actions,
                        const struct rte_flow_attr *flow_attr)
{
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    flow = netdev_dpdk_rte_flow_create(netdev, flow_attr, patterns->items,
                                       actions->actions, &error);
    if (!flow) {
        VLOG_ERR("%s: rte flow create offload error: %u : message : %s\n",
                netdev_get_name(netdev), error.type, error.message);
    }

    info->is_hwol = (flow) ? true : false;
    return flow;
}

static struct rte_flow *
netdev_rte_offload_add_default_flow(struct netdev_rte_port *rte_port,
                                    struct netdev_rte_port *vport)
{
    /* The default flow has the lowest priority, no
     * pattern (match all) and a Mark action
     */
    const struct rte_flow_attr def_flow_attr = {
        .group = vport->table_id,
        .priority = 1,
        .ingress = 1,
        .egress = 0,
        .transfer = 0,
    };
    struct flow_patterns def_patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions def_actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *def_flow = NULL;
    struct rte_flow_error error;

    add_flow_pattern(&def_patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    struct action_rss_data *rss = NULL;
    rss = add_flow_rss_action(&def_actions, rte_port->dpdk_num_queues);

    struct rte_flow_action_mark mark;
    mark.id = vport->exception_mark;
    add_flow_action(&def_actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);
    add_flow_action(&def_actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    def_flow = netdev_dpdk_rte_flow_create(rte_port->netdev, &def_flow_attr,
                                           def_patterns.items,
                                           def_actions.actions, &error);
    free(rss);
    free_flow_patterns(&def_patterns);
    free_flow_actions(&def_actions);

    if (!def_flow) {
        VLOG_ERR_RL(&error_rl, "%s: rte flow create for default flow error: %u"
            " : message : %s\n", netdev_get_name(rte_port->netdev), error.type,
            error.message);

    }

    return def_flow;
}

static int
get_output_port(const struct nlattr *a,
                struct rte_flow_action_port_id *port_id)
{
    odp_port_t odp_port;
    struct netdev_rte_port *output_rte_port;

    /* Output port should be hardware port number. */
    odp_port = nl_attr_get_odp_port(a);
    output_rte_port = netdev_rte_port_search(odp_port, &port_map);

    if (!output_rte_port) {
        VLOG_DBG("No rte port was found for odp_port %u",
                 odp_to_u32(odp_port));
        return EINVAL;
    }

    port_id->id = output_rte_port->dpdk_port_id;
    port_id->original = 0;

    return 0;
}

static void
netdev_rte_add_raw_encap_flow_action(const struct nlattr *a,
                                     struct rte_flow_action_raw_encap *encap,
                                     struct flow_actions *actions)
{
    const struct ovs_action_push_tnl *tunnel = nl_attr_get(a);
    encap->data = (uint8_t *)tunnel->header;
    encap->preserve = NULL;
    encap->size = tunnel->header_len;

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RAW_ENCAP, encap);
}

static int
netdev_rte_add_clone_flow_action(const struct nlattr *nlattr,
                                 struct rte_flow_action_raw_encap *raw_encap,
                                 struct rte_flow_action_count *count,
                                 struct rte_flow_action_port_id *output,
                                 struct flow_actions *actions)
{
    const struct nlattr *clone_actions = nl_attr_get(nlattr);
    size_t clone_actions_len = nl_attr_get_size(nlattr);
    const struct nlattr *ca;
    unsigned int cleft;
    int result = 0;

    NL_ATTR_FOR_EACH_UNSAFE (ca, cleft, clone_actions, clone_actions_len) {
        int clone_type = nl_attr_type(ca);
        if (clone_type == OVS_ACTION_ATTR_TUNNEL_PUSH) {
            netdev_rte_add_raw_encap_flow_action(ca, raw_encap, actions);
        } else if (clone_type == OVS_ACTION_ATTR_OUTPUT) {
            result = get_output_port(ca, output);
            if (result) {
                break;
            }
            netdev_rte_add_count_flow_action(count, actions);
            netdev_rte_add_port_id_flow_action(output, actions);
        }
    }

    return result;
}

static struct rte_flow *
netdev_rte_offloads_add_flow(struct netdev *netdev,
                             const struct match *match,
                             struct nlattr *nl_actions,
                             size_t actions_len,
                             const ovs_u128 *ufid OVS_UNUSED,
                             struct offload_info *info,
                             struct rte_flow **rte_flow0)
{
    struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    int result = 0;
    struct flow_items spec, mask;

    memset(&spec, 0, sizeof spec);
    memset(&mask, 0, sizeof mask);

    result = add_flow_patterns(&patterns, &spec, &mask, match);
    if (result) {
        goto out;
    }

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    const struct nlattr *a = NULL;
    unsigned int left = 0;

    /* Actions in nl_actions will be asserted in this bitmap,
     * according to their values in ovs_action_attr enum */
    uint64_t action_bitmap = 0;

    struct rte_flow_action_jump jump = {0};
    struct rte_flow_action_count count = {0};
    struct rte_flow_action_port_id output = {0};
    struct rte_flow_action_port_id clone_output = {0};
    struct rte_flow_action_count clone_count = {0};
    struct rte_flow_action_raw_encap clone_raw_encap = {0};
    struct netdev_rte_port *vport = NULL;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, nl_actions, actions_len) {
        int type = nl_attr_type(a);
        if ((enum ovs_action_attr) type == OVS_ACTION_ATTR_TUNNEL_POP) {
            vport = netdev_rte_add_jump_flow_action(a, &jump, &actions);
            if (!vport) {
                result = -1;
                break;
            }
            netdev_rte_add_count_flow_action(&count, &actions);
            action_bitmap |= 1 << OVS_ACTION_ATTR_TUNNEL_POP;
            result = 0;
        } else if ((enum ovs_action_attr) type == OVS_ACTION_ATTR_OUTPUT) {
            result = get_output_port(a, &output);
            if (result) {
                break;
            }
            netdev_rte_add_count_flow_action(&count, &actions);
            netdev_rte_add_port_id_flow_action(&output, &actions);
            action_bitmap |= 1 << OVS_ACTION_ATTR_OUTPUT;
        } else if ((enum ovs_action_attr) type == OVS_ACTION_ATTR_CLONE) {
            result = netdev_rte_add_clone_flow_action(a, &clone_raw_encap,
                                                      &clone_count,
                                                      &clone_output, &actions);
            if (result) {
                break;
            }
            action_bitmap |= 1 << OVS_ACTION_ATTR_CLONE;
        } else {
            /* Unsupported action for offloading */
            result = -1;
            break;
        }
    }

    /* If actions are not supported, try offloading Mark and RSS actions */
    if (result) {
        flow_attr.transfer = 0;
        flow = netdev_rte_offload_mark_rss(netdev, info, &patterns, &actions,
                                           NULL, &flow_attr);
        VLOG_DBG("Flow with Mark and RSS actions: NIC offload was %s",
                 flow ? "succeeded" : "failed");
    } else {
        /* Table 0 does not support encap. Set the encap action in table #1,
         * and the same matches and jump to table #1 in table #0.
         * This is bad for performance and insertion rate but as a WA for
         * SW-STR.
         */

        /* Actions are supported, offload the flow */
        flow_attr.transfer = 1;
        /* The flows for encap should be added to group 1 */
        if (action_bitmap & (1 << OVS_ACTION_ATTR_CLONE)) {
            flow_attr.group = 1;
        }
        flow = netdev_rte_offload_flow(netdev, info, &patterns, &actions,
                                       &flow_attr);
        VLOG_DBG("eSwitch offload was %s", flow ? "succeeded" : "failed");
        if (!flow) {
            goto out;
        }

        if (action_bitmap & (1 << OVS_ACTION_ATTR_CLONE)) {
            struct flow_actions jump_actions = { .actions = NULL, .cnt = 0 };

            jump.group = 1;
            add_flow_action(&jump_actions, RTE_FLOW_ACTION_TYPE_JUMP, &jump);
            add_flow_action(&jump_actions, RTE_FLOW_ACTION_TYPE_END, NULL);

            flow_attr.transfer = 1;
            /* The flows for WA are added to group 0 */
            flow_attr.group = 0;
            *rte_flow0 = netdev_rte_offload_flow(netdev, info, &patterns,
                                                 &jump_actions, &flow_attr);
            VLOG_DBG("Flow with same matches and jump actions: "
                     "eSwitch offload was %s",
                     *rte_flow0 ? "succeeded" : "failed");
            free_flow_actions(&jump_actions);
            if (!*rte_flow0) {
                goto out;
            }
        }

        odp_port_t port_id = match->flow.in_port.odp_port;
        struct netdev_rte_port *rte_port =
            netdev_rte_port_search(port_id, &port_map);

        /* If action is tunnel pop, create another table with a default
         * flow. Do it only once, if default rte flow doesn't exist
         */
        if ((action_bitmap & (1 << OVS_ACTION_ATTR_TUNNEL_POP)) &&
            (!rte_port->default_rte_flow[vport->table_id])) {

            rte_port->default_rte_flow[vport->table_id] =
                netdev_rte_offload_add_default_flow(rte_port, vport);

            /* If default flow creation failed, need to clean up also
             * the previous flow
             */
            if (!rte_port->default_rte_flow[vport->table_id]) {
                VLOG_ERR("ASAF Default flow is expected to fail "
                        "- no support for NIC and group 1 yet");
                goto out; // ASAF TEMP

                result = netdev_dpdk_rte_flow_destroy(netdev, flow,
                                                      &error);
                if (result) {
                    VLOG_ERR_RL(&error_rl,
                            "rte flow destroy error: %u : message : "
                            "%s\n", error.type, error.message);
                }
                flow = NULL;
            }
        }
    }

out:
    free_flow_patterns(&patterns);
    free_flow_actions(&actions);

    return flow;
}

/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_rte_offloads_validate_flow(const struct match *match, bool is_tun)
{
    struct match match_zero_wc;
    const struct flow *masks = &match->wc.masks;

    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (!is_tun && !is_all_zeros(&match_zero_wc.flow.tunnel,
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
netdev_offloads_flow_del(const ovs_u128 *ufid);

int
netdev_rte_offloads_flow_put(struct netdev *netdev, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             const ovs_u128 *ufid, struct offload_info *info,
                             struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct rte_flow *rte_flow, *rte_flow0 = NULL;
    int ret;

    odp_port_t in_port = match->flow.in_port.odp_port;
    struct netdev_rte_port *rte_port =
        netdev_rte_port_search(in_port, &port_map);

    if (!rte_port) {
        VLOG_WARN("Failed to find dpdk port number %d.", in_port);
        return EINVAL;
    }

    /* If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    struct ufid_hw_offload *ufid_hw_offload =
            ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte);

    if (ufid_hw_offload) {
        VLOG_DBG("got modification and destroying previous rte_flow");
        ret = netdev_offloads_flow_del(ufid);
        if (ret) {
            return ret;
        }
    }

    /* Create ufid_to_rte map for the ufid */
    ufid_hw_offload = netdev_rte_port_ufid_hw_offload_alloc(2, ufid);
    if (!ufid_hw_offload) {
        VLOG_WARN("failed to allocate ufid_hw_offlaod, OOM");
        ret = ENOMEM;
        goto err;
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte);
    ufid_to_portid_add(ufid, rte_port->dp_port);

    ret = netdev_rte_offloads_validate_flow(match, false);
    if (ret < 0) {
        VLOG_DBG("flow pattern is not supported");
        ret = EINVAL;
        goto err;
    }

    rte_flow = netdev_rte_offloads_add_flow(netdev, match, actions,
                                            actions_len, ufid, info,
                                            &rte_flow0);
    if (!rte_flow) {
        ret = ENODEV;
        goto err;
    }

    if (rte_flow0) {
        ufid_hw_offload_add_rte_flow(ufid_hw_offload, rte_flow0, netdev);
    }
    ufid_hw_offload_add_rte_flow(ufid_hw_offload, rte_flow, netdev);

    return 0;

err:
    netdev_offloads_flow_del(ufid);
    return ret;
}

static int
netdev_offloads_flow_del(const ovs_u128 *ufid)
{
    odp_port_t port_num = ufid_to_portid_search(ufid);

    if (port_num == INVALID_ODP_PORT) {
        return EINVAL;
    }

    struct netdev_rte_port *rte_port;
    struct ufid_hw_offload *ufid_hw_offload;

    rte_port = netdev_rte_port_search(port_num, &port_map);
    if (!rte_port) {
        VLOG_ERR("failed to find dpdk port for port %d",port_num);
        return ENODEV;
    }

    ufid_to_portid_remove(ufid);
    ufid_hw_offload = ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);
    if (ufid_hw_offload) {
        netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload);
    }

    return 0;
}

int
netdev_rte_offloads_flow_del(struct netdev *netdev OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats OVS_UNUSED)
{
    return netdev_offloads_flow_del(ufid);
}

static int
netdev_rte_vport_flow_del(struct netdev *netdev OVS_UNUSED,
                          const ovs_u128 *ufid,
                          struct dpif_flow_stats *stats OVS_UNUSED)
{
    return netdev_offloads_flow_del(ufid);
}

static int
add_vport_vxlan_flow_patterns(struct flow_patterns *patterns,
                              struct flow_items *spec,
                              struct flow_items *mask,
                              const struct match *match) {
    struct vni {
        union  {
            uint32_t val;
            uint8_t  vni[4];
        };
    };

    /* IP v4 */
    uint8_t proto = 0;
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        memset(&spec->ipv4, 0, sizeof spec->ipv4);
        memset(&mask->ipv4, 0, sizeof mask->ipv4);

        spec->ipv4.hdr.type_of_service = match->flow.tunnel.ip_tos;
        spec->ipv4.hdr.time_to_live    = match->flow.tunnel.ip_ttl;
        spec->ipv4.hdr.next_proto_id   = IPPROTO_UDP;
        spec->ipv4.hdr.src_addr        = match->flow.tunnel.ip_src;
        spec->ipv4.hdr.dst_addr        = match->flow.tunnel.ip_dst;

        mask->ipv4.hdr.type_of_service = match->wc.masks.tunnel.ip_tos;
        mask->ipv4.hdr.time_to_live    = match->wc.masks.tunnel.ip_ttl;
        mask->ipv4.hdr.next_proto_id   = 0xffu;
        mask->ipv4.hdr.src_addr        = match->wc.masks.tunnel.ip_src;
        mask->ipv4.hdr.dst_addr        = match->wc.masks.tunnel.ip_dst;
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, &spec->ipv4,
                         &mask->ipv4);

        /* Save proto for L4 protocol setup */
        proto = spec->ipv4.hdr.next_proto_id &
                mask->ipv4.hdr.next_proto_id;

    } else {
        return -1;
    }

    if (proto == IPPROTO_UDP) {
        memset(&spec->udp, 0, sizeof spec->udp);
        memset(&mask->udp, 0, sizeof mask->udp);
        spec->udp.hdr.src_port = match->flow.tunnel.tp_src;
        spec->udp.hdr.dst_port = match->flow.tunnel.tp_dst;

        mask->udp.hdr.src_port = match->wc.masks.tp_src;
        mask->udp.hdr.dst_port = match->wc.masks.tp_dst;
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &spec->udp, &mask->udp);
    } else {
        VLOG_ERR("flow arrived from vxlan port, but protocol is %d "
                 "and not UDP", proto);
        return -1;
    }

    struct vni vni = { .val = (uint32_t)(match->flow.tunnel.tun_id >> 32)};
    struct vni vni_m = { .val = (uint32_t)
                                    (match->wc.masks.tunnel.tun_id >> 32)};

    /* VXLAN */
    memset(&spec->vxlan, 0, sizeof spec->vxlan);
    memset(&mask->vxlan, 0, sizeof mask->vxlan);
    spec->vxlan.flags  = match->flow.tunnel.flags;
    spec->vxlan.vni[0] = vni.vni[1];
    spec->vxlan.vni[1] = vni.vni[2];
    spec->vxlan.vni[2] = vni.vni[3];

    mask->vxlan.vni[0] = vni_m.vni[1];
    mask->vxlan.vni[1] = vni_m.vni[2];
    mask->vxlan.vni[2] = vni_m.vni[3];

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VXLAN, &spec->vxlan,
                     &mask->vxlan);

    return 0;
}

static void
netdev_rte_add_decap_flow_action(struct flow_actions *actions)
{
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP, NULL);
}

static int
netdev_vport_vxlan_add_rte_flow_offload(struct netdev_rte_port *rte_port,
                                        struct match *match,
                                        struct nlattr *nl_actions,
                                        size_t actions_len,
                                        const ovs_u128 *ufid,
                                        struct offload_info *info,
                                        struct dpif_flow_stats *stats OVS_UNUSED)
{
    if (!actions_len || !nl_actions) {
        VLOG_DBG("skip flow offload without actions\n");
        return 0;
    }

    int ret = 0;

    /* If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    struct ufid_hw_offload *ufid_hw_offload =
        ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte);

    if (ufid_hw_offload) {
        VLOG_DBG("got modification and destroying previous rte_flow");
        ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);
        ret = netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload);
        if (ret < 0) {
            return ret;
        }
    }

    if (!dpdk_phy_ports_amount) {
        VLOG_WARN("offload while no phy ports %d",(int)dpdk_phy_ports_amount);
        return -1;
    }

    ufid_hw_offload =
        netdev_rte_port_ufid_hw_offload_alloc(dpdk_phy_ports_amount, ufid);
    if (ufid_hw_offload == NULL) {
        VLOG_WARN("failed to allocate ufid_hw_offlaod, OOM");
        return -1;
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte);
    ufid_to_portid_add(ufid, rte_port->dp_port);

    struct rte_flow_attr flow_attr = {
        .group = rte_port->table_id,
        .priority = 0,
        .ingress = 1,
        .egress = 0,
        .transfer = 0
    };

    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_items spec_outer, mask_outer;

    memset(&spec_outer, 0, sizeof spec_outer);
    memset(&mask_outer, 0, sizeof mask_outer);

    /* Add patterns from outer header */
    ret = add_vport_vxlan_flow_patterns(&patterns, &spec_outer,
                                        &mask_outer, match);
    if (ret) {
        goto out;
    }

    struct flow_items spec, mask;
    memset(&spec, 0, sizeof spec);
    memset(&mask, 0, sizeof mask);

    /* Add patterns from inner header */
    ret = add_flow_patterns(&patterns, &spec, &mask, match);
    if (ret) {
        goto out;
    }

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    struct rte_flow *flow = NULL;
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow_action_port_id port_id;
    struct rte_flow_action_count count;

    /* Actions in nl_actions will be asserted in this bitmap,
     * according to their values in ovs_action_attr enum
     */
    uint64_t action_bitmap = 0;

    const struct nlattr *a;
    unsigned int left;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, nl_actions, actions_len) {
        int type = nl_attr_type(a);
        if ((enum ovs_action_attr)type == OVS_ACTION_ATTR_OUTPUT) {
            ret = get_output_port(a, &port_id);
            if (ret) {
                goto out;
            }
            action_bitmap |= (1 << OVS_ACTION_ATTR_OUTPUT);
        } else {
            /* Unsupported action for offloading */
            ret = EOPNOTSUPP;
            goto out;
        }
    }

    struct netdev_rte_port *data;
    struct rte_flow_error error;
    CMAP_FOR_EACH (data, node, &port_map) {
        /* Offload only in case the port is DPDK and it's the uplink port */
        if ((data->rte_port_type == RTE_PORT_TYPE_DPDK) &&
            (netdev_dpdk_is_uplink_port(data->netdev))) {

            free_flow_actions(&actions);
            netdev_rte_add_decap_flow_action(&actions);

            if (action_bitmap & (1 << OVS_ACTION_ATTR_OUTPUT)) {
                netdev_rte_add_count_flow_action(&count, &actions);
                netdev_rte_add_port_id_flow_action(&port_id, &actions);
            }

            add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

            flow_attr.transfer = 1;
            flow = netdev_dpdk_rte_flow_create(data->netdev,
                                               &flow_attr, patterns.items,
                                               actions.actions, &error);
            VLOG_DBG("eSwitch offload was %s", flow ? "succeeded" : "failed");

            if (flow) {
                info->is_hwol = true;
            } else {
                VLOG_ERR("%s: rte flow create offload error: %u : "
                         "message : %s\n", netdev_get_name(data->netdev),
                         error.type, error.message);

                /* In case flow cannot be offloaded with decap and output
                 * actions, try to offload decap with mark and rss, and output
                 * will be done in SW
                 */
                free_flow_actions(&actions);

                netdev_rte_add_decap_flow_action(&actions);
                flow_attr.transfer = 0;
                flow = netdev_rte_offload_mark_rss(data->netdev,
                                                   info, &patterns, &actions,
                                                   NULL, &flow_attr);
                VLOG_DBG("NIC offload was %s", flow ? "succeeded" : "failed");
                if (flow) {
                    info->is_hwol = false;
                }
            }

            if (flow) {
                ufid_hw_offload_add_rte_flow(ufid_hw_offload, flow,
                                             data->netdev);
            }
        }
    }

out:
    free_flow_patterns(&patterns);
    return ret;
}

static int
netdev_rte_vport_flow_put(struct netdev *netdev OVS_UNUSED,
                          struct match *match,
                          struct nlattr *actions,
                          size_t actions_len,
                          const ovs_u128 *ufid,
                          struct offload_info *info,
                          struct dpif_flow_stats *stats)
{
    if (netdev_rte_offloads_validate_flow(match, true)) {
        VLOG_DBG("flow pattern is not supported");
        return EOPNOTSUPP;
    }

    int ret = 0;
    odp_port_t in_port = match->flow.in_port.odp_port;
    struct netdev_rte_port *rte_port = netdev_rte_port_search(in_port,
                                                              &port_map);
    if (rte_port != NULL) {
        if (rte_port->rte_port_type == RTE_PORT_TYPE_VXLAN) {
            VLOG_DBG("vxlan offload ufid "UUID_FMT" \n",
                     UUID_ARGS((struct uuid *)ufid));
            ret = netdev_vport_vxlan_add_rte_flow_offload(rte_port, match,
                                                          actions,
                                                          actions_len, ufid,
                                                          info, stats);
        } else {
            VLOG_DBG("unsupported tunnel type");
            ovs_assert(true);
        }
    }

    return ret;
}

/*
 * Vport netdev flow pointers are initialized by default to kernel calls.
 * They should be nullified or be set to a valid netdev (userspace) calls.
 */
static void
netdev_rte_offloads_vxlan_init(struct netdev *netdev)
{
    struct netdev_class *cls = (struct netdev_class *)netdev->netdev_class;
    cls->flow_put = netdev_rte_vport_flow_put;
    cls->flow_del = netdev_rte_vport_flow_del;
    cls->flow_get = NULL;
    cls->init_flow_api = NULL;
}

/*
 * Called when adding a new dpif netdev port.
 */
int
netdev_rte_offloads_port_add(struct netdev *netdev, odp_port_t dp_port)
{
    struct netdev_rte_port *rte_port;
    const char *type = netdev_get_type(netdev);
    int ret = 0;

    if (!strcmp("dpdk", type)) {
        ret = netdev_rte_port_set(netdev, dp_port, RTE_PORT_TYPE_DPDK,
                                  &rte_port);
        if (!rte_port) {
            goto out;
        }

        rte_port->dpdk_num_queues = netdev_n_rxq(netdev);
        rte_port->dpdk_port_id = netdev_dpdk_get_port_id(netdev);
        dpdk_phy_ports_amount++;
        VLOG_INFO("Rte dpdk port %d allocated.", dp_port);
        goto out;
    }
    if (!strcmp("vxlan", type)) {
        ret = netdev_rte_port_set(netdev, dp_port, RTE_PORT_TYPE_VXLAN,
                                  &rte_port);
        if (!rte_port) {
            goto out;
        }
        rte_port->table_id = VXLAN_TABLE_ID;
        rte_port->exception_mark = VXLAN_EXCEPTION_MARK;

        cmap_insert(&mark_to_rte_port,
            CONST_CAST(struct cmap_node *, &rte_port->mark_node),
            hash_bytes(&rte_port->exception_mark,
                       sizeof rte_port->exception_mark,0));

        VLOG_INFO("Rte vxlan port %d allocated, table id %d",
                  dp_port, rte_port->table_id);
        netdev_rte_offloads_vxlan_init(netdev);
        goto out;
    }
out:
    return ret;
}

static void
netdev_rte_port_clean_all(struct netdev_rte_port *rte_port)
{
    struct cmap_cursor cursor;
    struct ufid_hw_offload *data;

    CMAP_CURSOR_FOR_EACH (data, node, &cursor, &rte_port->ufid_to_rte) {
        netdev_rte_port_ufid_hw_offload_free(data);
    }
}

/**
 * @brief - Go over all the default rules and free if exists.
 *
 * @param rte_port
 */
static void
netdev_rte_port_del_default_rules(struct netdev_rte_port *rte_port)
{
    int i = 0;
    int result = 0;
    struct rte_flow_error error = {0};

    for (i = 0 ; i < RTE_FLOW_MAX_TABLES ; i++) {
        if (rte_port->default_rte_flow[i]) {
            result = netdev_dpdk_rte_flow_destroy(rte_port->netdev,
                                                  rte_port->default_rte_flow[i],
                                                  &error);
            if (result) {
                 VLOG_ERR_RL(&error_rl, "rte flow destroy error: %u : "
                             "message : %s\n", error.type, error.message);
            }
            rte_port->default_rte_flow[i] = NULL;
        }
    }
}

/*
 * Called when deleting a dpif netdev port.
 */
int
netdev_rte_offloads_port_del(odp_port_t dp_port)
{
    struct netdev_rte_port *rte_port =
        netdev_rte_port_search(dp_port, &port_map);
    if (rte_port == NULL) {
        VLOG_DBG("port %d has no rte_port", dp_port);
        return ENODEV;
    }

    netdev_rte_port_clean_all(rte_port);

    size_t hash = hash_bytes(&rte_port->dp_port,
                             sizeof rte_port->dp_port, 0);
    VLOG_DBG("Remove datapath port %d.", rte_port->dp_port);
    cmap_remove(&port_map, CONST_CAST(struct cmap_node *, &rte_port->node),
                hash);

    if (rte_port->rte_port_type == RTE_PORT_TYPE_DPDK) {
        netdev_rte_port_del_default_rules(rte_port);
        dpdk_phy_ports_amount--;
    } else if (rte_port->rte_port_type == RTE_PORT_TYPE_VXLAN) {
        cmap_remove(&mark_to_rte_port,
                    CONST_CAST(struct cmap_node *,
                    &rte_port->mark_node),
                    hash_bytes(&rte_port->exception_mark,
                    sizeof rte_port->exception_mark,0));
    }

    free(rte_port);

    return 0;
}

static void
netdev_rte_port_preprocess(struct netdev_rte_port *rte_port,
                           struct dp_packet *packet)
{
    switch (rte_port->rte_port_type) {
        case RTE_PORT_TYPE_VXLAN:
            /* VXLAN table failed to match on HW, but according to port
             * id it can be popped here
             */
            if (rte_port->netdev->netdev_class->pop_header) {
                rte_port->netdev->netdev_class->pop_header(packet);
                packet->md.in_port.odp_port = rte_port->dp_port;
                dp_packet_reset_checksum_ol_flags(packet);
            }
            break;
        case RTE_PORT_TYPE_UNINIT:
        case RTE_PORT_TYPE_DPDK:
        default:
            VLOG_WARN("port type %d has no pre-process",
                    rte_port->rte_port_type);
            break;
    }
}

/**
 * @brief - Once received a packet with special mark, need to run
 *  pre-processing on the it so it could be processed by the OVS SW.

 *  Example for such case in vxlan is where we get match on outer
 *  vxlan so we jump to vxlan table, but then we fail on inner match.
 *  In this case we need to make sure SW processing continues from second flow.
 *
 * @param packet
 * @param mark
 */
void
netdev_rte_offload_preprocess(struct dp_packet *packet, uint32_t mark)
{
    struct netdev_rte_port *rte_port;
    size_t hash = hash_bytes(&mark, sizeof mark,0);

    CMAP_FOR_EACH_WITH_HASH (rte_port, mark_node, hash, &mark_to_rte_port) {
        if (rte_port->exception_mark == mark) {
            netdev_rte_port_preprocess(rte_port, packet);
            return;
        }
    }
    VLOG_WARN("Exception mark %u with no port", mark);
}
