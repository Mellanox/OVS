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
#include <rte_eth_vhost.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "id-pool.h"
#include "netdev-provider.h"
#include "conntrack.h"
#include "netdev-native-tnl.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"
#include "unixctl.h"

extern int
(*ovs_rte_flow_query)(uint16_t port_id,
                      struct rte_flow *flow,
                      const struct rte_flow_action *action,
                      void *data,
                      struct rte_flow_error *error);

struct flow_data;

#define VXLAN_EXCEPTION_MARK (MIN_RESERVED_MARK + 0)
enum table_ids {
    UNKNOWN_TABLE_ID = -1,
    ROOT_TABLE_ID,
    VXLAN_TABLE_ID,
    CONNTRACK_TABLE_ID,
    CONNTRACK_NAT_TABLE_ID,
    MAPPING_TABLE_ID,
    TABLE_ID_LAST
};


VLOG_DEFINE_THIS_MODULE(netdev_rte_offloads);
static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(100, 5);

#define RTE_FLOW_MAX_TABLES (31)
#define INVALID_ODP_PORT (-1)

enum rte_port_type {
    RTE_PORT_TYPE_UNINIT = 0,
    RTE_PORT_TYPE_DPDK,
    RTE_PORT_TYPE_VXLAN
};

#define INVALID_OUTER_ID  0Xffffffff
#define INVALID_HW_ID     0Xffffffff
#define MAX_OUTER_ID  0xffff
#define MAX_HW_TABLE (0xff00)

/*
 * A mapping from dp_port to flow parameters.
 */
enum ufid_to_rte_type_e {
    UFID_TO_RTE_OFFLOADS = 0,
    UFID_TO_RTE_CT,
    UFID_TO_RTE_TYPE_NUM
};

struct netdev_rte_port {
    struct cmap_node node; /* Map by datapath port number. */
    odp_port_t dp_port; /* Datapath port number. */
    uint16_t dpdk_port_id; /* Id of the DPDK port. */
    struct netdev *netdev; /* struct *netdev of this port. */
    enum rte_port_type rte_port_type; /* rte ports types. */
    bool is_uplink; /* Is physical uplink port */
    uint32_t table_id; /* Flow table id per related to this port. */
    uint16_t dpdk_num_queues; /* Number of dpdk queues of this port. */
    uint32_t exception_mark; /* Exception SW handling for this port type. */
    struct cmap ufid_to_rte[UFID_TO_RTE_TYPE_NUM]; /* flows id to dpdk rte flows */
    struct cmap recirc_to_rte; /* HW id of recirc id to dpdk rte flows */
    struct cmap portid_to_rte; /* HW id of port id to dpdk rte flows */
    struct rte_flow *default_rte_flow[RTE_FLOW_MAX_TABLES];
    struct cmap_node mark_node;
};

static struct rte_flow*
netdev_dpdk_offload_put_handle(struct netdev *netdev,
                             struct netdev_rte_port *rte_port,
                             struct flow_data *flow_data, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             struct offload_info *info, bool is_vport);
static int
netdev_rte_update_hwid_mapping(struct netdev_rte_port *rte_port,
                               odp_port_t out_dp_port,
                               uint32_t hwid, bool is_add, bool port);
static void netdev_dpdk_put_recirc_id_hw_id(uint32_t recirc_id);
static void netdev_dpdk_put_port_id_hw_id(uint32_t port_id);
static struct rte_flow *
netdev_rte_offload_add_default_flow(struct netdev_rte_port *rte_port,
                                    struct netdev_rte_port *vport);

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
                    enum rte_port_type port_type, bool is_uplink,
                    struct netdev_rte_port **rte_port)
{
    enum ufid_to_rte_type_e ufid_to_rte_type;

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
    for (ufid_to_rte_type = 0; ufid_to_rte_type < UFID_TO_RTE_TYPE_NUM;
         ufid_to_rte_type++) {
        cmap_init(&((*rte_port)->ufid_to_rte[ufid_to_rte_type]));
    }
    cmap_init(&((*rte_port)->recirc_to_rte));
    cmap_init(&((*rte_port)->portid_to_rte));

next:
    (*rte_port)->netdev = netdev;
    (*rte_port)->dp_port = dp_port;
    (*rte_port)->rte_port_type = port_type;
    (*rte_port)->is_uplink = is_uplink;

    return 0;
}

struct ufid_hw_offload {
    struct cmap_node node;
    ovs_u128 ufid;
    uint32_t mark;
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
 * of vxlan OVS flow we add an rte flow per each physical port.
 *
 * max_flows - number of expected max rte flows for this ufid.
 * ufid - the ufid.
 *
 * Return allocated struct ufid_hw_offload or NULL if allocation failed.
 */
static struct ufid_hw_offload *
netdev_rte_port_ufid_hw_offload_alloc(int max_flows, const ovs_u128 *ufid, uint32_t mark)
{
    struct ufid_hw_offload *ufidol =
        xzalloc(sizeof(struct ufid_hw_offload) +
                       sizeof(struct rte_flow_params) * max_flows);
    if (ufidol) {
        ufidol->max_flows = max_flows;
        ufidol->curr_idx = 0;
        ufidol->ufid = *ufid;
        ufidol->mark = mark;
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

static void
netdev_dpdk_del_miss_ctx(uint32_t mark);

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
    if (hw_offload->mark) {
        netdev_dpdk_del_miss_ctx(hw_offload->mark);
    }

    ovsrcu_postpone(free, hw_offload);
    return 0;
}

struct ufid_to_odp {
    struct cmap_node node;
    ovs_u128 ufid;
    odp_port_t dp_port;
    uint32_t recirc_id;
};

static struct cmap ufid_to_portid_map = CMAP_INITIALIZER;
static struct cmap ctid_to_portid_map = CMAP_INITIALIZER;
static struct ovs_mutex ufid_to_portid_mutex = OVS_MUTEX_INITIALIZER;

/*
 * Search for ufid mapping
 *
 * Return ref to object and not a copy.
 */
static struct ufid_to_odp *
ufid_to_portid_get(const ovs_u128 *uid, struct cmap *map)
{
    size_t hash = hash_bytes(uid, sizeof *uid, 0);
    struct ufid_to_odp *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (ovs_u128_equals(*uid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static odp_port_t
ufid_to_portid_search(const ovs_u128 *ufid, struct cmap *cmap)
{
   struct ufid_to_odp *data = ufid_to_portid_get(ufid, cmap);

   return (data) ? data->dp_port : INVALID_ODP_PORT;
}

/*
 * Save the ufid->dp_port mapping.
 *
 * Return the port if saved successfully.
 */
static odp_port_t
ufid_to_portid_add(const ovs_u128 *ufid, odp_port_t dp_port,
                   uint32_t recirc_id, struct cmap *cmap)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_odp *data;

    if (ufid_to_portid_search(ufid, cmap) != INVALID_ODP_PORT) {
        return dp_port;
    }

    data = xzalloc(sizeof *data);
    if (!data) {
        VLOG_WARN("Failed to add ufid to odp, (ENOMEM)");
        return INVALID_ODP_PORT;
    }

    data->ufid = *ufid;
    data->dp_port = dp_port;
    data->recirc_id = recirc_id;

    cmap_insert(cmap,
                CONST_CAST(struct cmap_node *, &data->node), hash);

    return dp_port;
}

/*
 * Remove the mapping if exists.
 */
static void
ufid_to_portid_remove(const ovs_u128 *ufid, struct cmap *cmap)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_odp *data = ufid_to_portid_get(ufid, cmap);

    ovs_mutex_lock(&ufid_to_portid_mutex);
    if (data != NULL) {
        cmap_remove(cmap,
                    CONST_CAST(struct cmap_node *, &data->node), hash);
        ovsrcu_postpone(free, data);
    }
    ovs_mutex_unlock(&ufid_to_portid_mutex);
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

enum {
    TAG_FIELD_HW_ID = 0,
    TAG_FIELD_CT_STATE,
    TAG_FIELD_CT_ZONE,
    TAG_FIELD_OUTER_ID,
    TAG_FIELD_CT_MARK,
    TAG_FIELD_NUM,
};

/* map tag_id to register index, mask as few tags can share the same register
 * and data field is used as the bit shift needed.
 */
static struct rte_flow_action_set_tag tag_id_maps[] = {
    [TAG_FIELD_HW_ID] = {
        .index = 0,
        .mask = 0xFFFFFFFF,
        .data = 0,
    },
    [TAG_FIELD_CT_STATE] = {
        .index = 1,
        .mask = 0x000000FF,
        .data = 0,
    },
    [TAG_FIELD_CT_ZONE] = {
        .index = 1,
        .mask = 0x0000FF00,
        .data = 8,
    },
    [TAG_FIELD_OUTER_ID] = {
        .index = 1,
        .mask = 0xFFFF0000,
        .data = 16,
    },
    [TAG_FIELD_CT_MARK] = {
        .index = 2,
        .mask = 0xFFFFFFFF,
        .data = 0,
    },
};

struct flow_items {
    struct rte_flow_item_eth  eth;
    struct rte_flow_item_vlan vlan;
    struct rte_flow_item_ipv4 ipv4;
    struct rte_flow_item_ipv6 ipv6;
    struct rte_flow_item_vxlan vxlan;
    union {
        struct rte_flow_item_tcp  tcp;
        struct rte_flow_item_udp  udp;
        struct rte_flow_item_sctp sctp;
        struct rte_flow_item_icmp icmp;
    };
    struct rte_flow_item_meta meta;
    struct rte_flow_item_tag tags[TAG_FIELD_NUM];
    uint8_t num_tags;
};

struct flow_action_items {
    struct rte_flow_action_jump jump;
    struct rte_flow_action_count count;
    struct rte_flow_action_mark mark;
    struct rte_flow_action_set_meta meta;
    struct rte_flow_action_port_id output;
    struct rte_flow_action_port_id clone_output;
    struct rte_flow_action_count clone_count;
    struct rte_flow_action_raw_encap clone_raw_encap;
    struct rte_flow_action_set_tag set_tags[TAG_FIELD_NUM];
    uint8_t num_set_tags;
    struct {
        struct {
            struct rte_flow_action_set_mac src;
            struct rte_flow_action_set_mac dst;
        } mac;
        struct {
            struct rte_flow_action_set_ipv4 src;
            struct rte_flow_action_set_ipv4 dst;
            struct rte_flow_action_set_ttl ttl;
        } ipv4;
    } set;
};

struct flow_data {
    struct flow_items spec;
    struct flow_items mask;
    struct flow_items spec_outer;
    struct flow_items mask_outer;
    struct flow_action_items actions;
    /* WA flow */
    struct rte_flow *flow0;
};


static int
netdev_dpdk_add_pattern_match_reg(struct flow_items *spec,
                                  struct flow_items *mask,
                                  struct flow_patterns *patterns,
                                  uint8_t tag_field,
                                  uint32_t val, uint32_t val_mask)
{
    struct rte_flow_action_set_tag *tag_id_map;

    if (tag_field >= TAG_FIELD_NUM) {
        VLOG_ERR("tag field %d is out of range", tag_field);
        return -1;
    }

    tag_id_map = &tag_id_maps[tag_field];

    spec->tags[spec->num_tags].index = tag_id_map->index;
    spec->tags[spec->num_tags].data = (val << tag_id_map->data) & tag_id_map->mask;
    if (spec->tags[spec->num_tags].data != val << tag_id_map->data) {
        VLOG_ERR_RL(&error_rl, "value is out of range for tag id %d", val);
        return -1;
    }
    mask->tags[mask->num_tags].index = 0xFF;
    mask->tags[mask->num_tags].data = tag_id_map->mask &
                                      (val_mask << tag_id_map->data);
    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TAG,
                     &spec->tags[spec->num_tags],
                     &mask->tags[mask->num_tags]);
    spec->num_tags++;
    mask->num_tags++;
    return 0;
}


static int
netdev_dpdk_add_action_set_reg(struct flow_action_items *action_items,
                               struct flow_actions *actions,
                               uint8_t tag_field, uint32_t val)
{
    struct rte_flow_action_set_tag *tag_id_map;

    if (tag_field >= TAG_FIELD_NUM) {
        VLOG_ERR("tag field %d is out of range", tag_field);
        return -1;
    }

    tag_id_map = &tag_id_maps[tag_field];

    action_items->set_tags[action_items->num_set_tags].index = tag_id_map->index;
    action_items->set_tags[action_items->num_set_tags].data =
        (val << tag_id_map->data) & tag_id_map->mask;
    if (action_items->set_tags[action_items->num_set_tags].data !=
        val << tag_id_map->data) {
        VLOG_ERR_RL(&error_rl, "value is out of range for tag id %d", val);
        return -1;
    }
    action_items->set_tags[action_items->num_set_tags].mask = tag_id_map->mask;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_TAG,
                    &action_items->set_tags[action_items->num_set_tags]);
    action_items->num_set_tags++;

    return 0;
}


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

    /* IP v6 */
    if (match->flow.dl_type == htons(ETH_TYPE_IPV6)) {
        memset(&spec->ipv6, 0, sizeof spec->ipv6);
        memset(&mask->ipv6, 0, sizeof mask->ipv6);

        spec->ipv6.hdr.proto = match->flow.nw_proto;
        spec->ipv6.hdr.hop_limits = match->flow.nw_ttl;
        rte_memcpy(spec->ipv6.hdr.src_addr, match->flow.ipv6_src.s6_addr,
            sizeof spec->ipv6.hdr.src_addr);
        rte_memcpy(spec->ipv6.hdr.dst_addr, match->flow.ipv6_dst.s6_addr,
            sizeof spec->ipv6.hdr.dst_addr);

        mask->ipv6.hdr.proto = match->wc.masks.nw_proto;
        mask->ipv6.hdr.hop_limits = match->wc.masks.nw_ttl;
        rte_memcpy(mask->ipv6.hdr.src_addr, match->wc.masks.ipv6_src.s6_addr,
            sizeof mask->ipv6.hdr.src_addr);
        rte_memcpy(mask->ipv6.hdr.dst_addr, match->wc.masks.ipv6_dst.s6_addr,
            sizeof mask->ipv6.hdr.dst_addr);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6,
                         &spec->ipv6, &mask->ipv6);

        /* Save proto for L4 protocol setup */
        proto = spec->ipv6.hdr.proto &
                mask->ipv6.hdr.proto;
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

    if (match->flow.recirc_id == 0) {
        return 0;
    }

    if (match->wc.masks.ct_state) {
        netdev_dpdk_add_pattern_match_reg(spec, mask, patterns,
                                          TAG_FIELD_CT_STATE,
                                          match->flow.ct_state,
                                          match->wc.masks.ct_state);
    }
    if (match->wc.masks.ct_zone) {
        netdev_dpdk_add_pattern_match_reg(spec, mask, patterns,
                                          TAG_FIELD_CT_ZONE,
                                          match->flow.ct_zone,
                                          match->wc.masks.ct_zone);
    }
    if (match->wc.masks.ct_mark) {
        netdev_dpdk_add_pattern_match_reg(spec, mask, patterns,
                                          TAG_FIELD_CT_MARK,
                                          match->flow.ct_mark,
                                          match->wc.masks.ct_mark);
    }

    return 0;
}

/* When we add a jump to vport table we add a new table.
 * We add a default rule with low priority that if we fail
 * to match on table we set a sepical mark and go to SW.
 */
static int
netdev_rte_vport_add_default_rule(struct netdev_rte_port *rte_port,
                                  struct netdev_rte_port *vport)
{
    int ret = 0;
    /* TODO: RONI, code was copied from previous implementation
     * there is a hidden assumption here that we always jump from
     * phy port so we will never get rte_port which is not the uplink */
    if (rte_port->default_rte_flow[vport->table_id]) {
        return ret;
    }
    rte_port->default_rte_flow[vport->table_id] =
                netdev_rte_offload_add_default_flow(rte_port, vport);

    if (!rte_port->default_rte_flow[vport->table_id]) {
        VLOG_ERR("ASAF Default flow is expected to fail "
                "- no support for NIC and group 1 yet");
        ret = -1;
    }
    return ret;
}

static int
netdev_rte_add_jump_to_vport_flow_action(struct netdev_rte_port *rte_port,
                                struct flow_data *fdata,
                                odp_port_t vport_odp_port,
                                struct flow_actions *actions)
{
    struct netdev_rte_port *vport;

    vport = netdev_rte_port_search(vport_odp_port, &port_map);
    if (!vport) {
        VLOG_DBG("No rte port was found for odp_port %u",
                odp_to_u32(vport_odp_port));
        return -1;
    }

    /* if we fail here, we can't add the rule as will break 
     * flow process on miss */
    if (netdev_rte_vport_add_default_rule(rte_port, vport)) {
        return -1;
    }


    fdata->actions.jump.group = vport->table_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, &fdata->actions.jump);
    return 0;
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
netdev_rte_add_jump_flow_action(struct rte_flow_action_jump *jump,
                                uint32_t group,
                                struct flow_actions *actions)
{
    memset(jump, 0, sizeof *jump);
    jump->group = group;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump);
}

static void
netdev_rte_add_port_id_flow_action(struct rte_flow_action_port_id *port_id,
                                   struct flow_actions *actions)
{
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_PORT_ID, port_id);
}

static void
netdev_rte_add_mark_flow_action(struct rte_flow_action_mark *mark,
                                uint32_t mark_id,
                                struct flow_actions *actions)
{
    memset(mark, 0, sizeof *mark);
    mark->id = mark_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);
}

static void
netdev_rte_add_meta_flow_action(struct rte_flow_action_set_meta *meta,
                                uint32_t data,
                                struct flow_actions *actions)
{
    memset(meta, 0, sizeof *meta);
    meta->data = RTE_BE32(data);
    meta->mask = RTE_BE32(0xffff);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_META, meta);
}

static struct rte_flow *
netdev_rte_offload_mark_rss(struct netdev *netdev,
                            uint32_t mark_id,
                            struct flow_patterns *patterns,
                            struct flow_actions *actions,
                            struct rte_flow_action_port_id *port_id,
                            const struct rte_flow_attr *flow_attr)
{
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;

    struct rte_flow_action_mark mark = {0};
    mark.id = mark_id;
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
                        struct offload_info *info OVS_UNUSED,
                        struct flow_patterns *patterns,
                        struct flow_actions *actions,
                        const struct rte_flow_attr *flow_attr)
{
    struct rte_flow *offloaded_flow = NULL;
    struct rte_flow_error error;

    offloaded_flow = netdev_dpdk_rte_flow_create(netdev, flow_attr, patterns->items,
                                       actions->actions, &error);
    if (!offloaded_flow) {
        VLOG_ERR("%s: rte flow create offload error: %u : message : %s\n",
                netdev_get_name(netdev), error.type, error.message);
    }

    return offloaded_flow;
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
add_jump_to_port_id_action(odp_port_t target_port,
                struct flow_actions *flow_actions,
                struct rte_flow_action_port_id *port_id_action)
{
    struct netdev_rte_port *output_rte_port;

    /* Output port should be hardware port number. */
    output_rte_port = netdev_rte_port_search(target_port, &port_map);

    if (!output_rte_port) {
        VLOG_DBG("No rte port was found for odp_port %u",
                 odp_to_u32(target_port));
        return EINVAL;
    }

    port_id_action->id = output_rte_port->dpdk_port_id;
    port_id_action->original = 0;

    netdev_rte_add_port_id_flow_action(port_id_action, flow_actions);
    return 0;
}

static int netdev_dpdk_get_recirc_hw_id(uint32_t recirc_id, uint32_t *hw_id);
static int netdev_dpdk_get_port_hw_id(uint32_t port_id, uint32_t *hw_id);
static int netdev_dpdk_peek_recirc_hw_id(uint32_t recirc_id, uint32_t *hw_id);
static int netdev_dpdk_peek_port_hw_id(uint32_t port_id, uint32_t *hw_id);

/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_rte_offloads_validate_flow(const struct match *match, bool tun_offload)
{
    struct match match_zero_wc;
    const struct flow *masks = &match->wc.masks;

    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (!tun_offload && !is_all_zeros(&match_zero_wc.flow.tunnel,
                      sizeof match_zero_wc.flow.tunnel)) {
        goto err;
    }

    if (masks->metadata || masks->skb_priority ||
        masks->pkt_mark || masks->dp_hash) {
        goto err;
    }

    /* TODO: check why this test is required */
/*    if (!ct_offload && (masks->ct_state || masks->ct_nw_proto ||
        masks->ct_zone  || masks->ct_mark     ||
        !ovs_u128_is_zero(masks->ct_label))) {
        goto err;
    }*/

    if (masks->conj_id || masks->actset_output) {
        goto err;
    }

    /* Unsupported L2. */
    if (!is_all_zeros(masks->mpls_lse, sizeof masks->mpls_lse)) {
        goto err;
    }

    /* Unsupported L3. */
    if (masks->ct_nw_src || masks->ct_nw_dst     ||
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

static int restore_packet_state(uint32_t flow_mark, struct dp_packet *packet);

int
netdev_rte_offloads_flow_restore(OVS_UNUSED struct netdev *netdev,
                                 uint32_t flow_mark ,
                                 struct dp_packet *packet,
                                 struct nlattr *actions, size_t actions_len,
                                 size_t *offloaded_actions_len)
{
    unsigned int hw_actions_len = 0;
    const struct nlattr *a;
    unsigned int left;

    restore_packet_state(flow_mark, packet);

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);

        /* TODO - this should be generic by quering the PMD capabilities*/
        if (type == OVS_ACTION_ATTR_CT) {
            break;
        }
        hw_actions_len += a->nla_len;
    }

    if (offloaded_actions_len && hw_actions_len < actions_len)
        *offloaded_actions_len = hw_actions_len;
    return 0;
}

int
netdev_rte_offloads_flow_put(struct netdev *netdev, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             const ovs_u128 *ufid, struct offload_info *info,
                             struct dpif_flow_stats *stats)
{
    struct rte_flow *rte_flow /*, *rte_flow0*/ = NULL;
    int ret;
    struct flow_data flow_data;

    memset(&flow_data, 0, sizeof flow_data);

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
            ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte[UFID_TO_RTE_OFFLOADS]);

    if (ufid_hw_offload) {
        VLOG_DBG("got modification and destroying previous rte_flow");
        ret = netdev_rte_offloads_flow_del(netdev, ufid, stats);
        if (ret) {
            return ret;
        }
    }

    /* Create ufid_to_rte map for the ufid */
    ufid_hw_offload = netdev_rte_port_ufid_hw_offload_alloc(2, ufid, info->flow_mark);
    if (!ufid_hw_offload) {
        VLOG_WARN("failed to allocate ufid_hw_offlaod, OOM");
        return ENOMEM;
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte[UFID_TO_RTE_OFFLOADS]);
    ufid_to_portid_add(ufid, rte_port->dp_port, match->flow.recirc_id,
                       &ufid_to_portid_map);

    ret = netdev_rte_offloads_validate_flow(match, false);
    if (ret < 0) {
        VLOG_DBG("flow pattern is not supported");
        ret = EINVAL;
        goto err;
    }

    rte_flow = netdev_dpdk_offload_put_handle(netdev, rte_port, &flow_data,
                                              match, actions,
                                              actions_len, info, false);
    if (!rte_flow) {
        ret = ENODEV;
        goto err;
    }

    if (flow_data.flow0) {
        ufid_hw_offload_add_rte_flow(ufid_hw_offload, flow_data.flow0, netdev);
    }
    ufid_hw_offload_add_rte_flow(ufid_hw_offload, rte_flow, netdev);

    return 0;

err:
    netdev_rte_offloads_flow_del(netdev, ufid, stats);
    return ret;
}

int
netdev_rte_offloads_flow_stats_get(struct netdev *netdev OVS_UNUSED,
                                   const ovs_u128 *ufid,
                                   struct dpif_flow_stats *stats)
{
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow_action_count count = {0};
    struct rte_flow_query_count query;
    struct netdev_rte_port *rte_port;
    struct rte_flow_error error;
    struct ufid_hw_offload *uho;
    struct rte_flow *rte_flow;
    dpdk_port_t dpdk_port_id;
    struct ufid_to_odp *uto;
    struct netdev *netd;
    int i, ret;

    memset(stats, 0, sizeof *stats);

    ovs_mutex_lock(&ufid_to_portid_mutex);

    uto = ufid_to_portid_get(ufid, &ufid_to_portid_map);
    if (!uto) {
        ret = EINVAL;
        goto err;
    }
    rte_port = netdev_rte_port_search(uto->dp_port, &port_map);
    if (!rte_port) {
        ret = EINVAL;
        goto err;
    }
    uho = ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte[UFID_TO_RTE_OFFLOADS]);
    if (!uho) {
        ret = EINVAL;
        goto err;
    }

    netdev_rte_add_count_flow_action(&count, &actions);
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    /*
     * Several HW flows may be related for one ufid. For example for one vport
     * flow we may have created a HW flow per each physical port. Therefore we
     * need to loop over all HW flows related to this ufid and accumulate the
     * statitistics related to it.
     */
    for (i = 0 ; i < uho->curr_idx ; i++) {
        netd = uho->rte_flow_data[i].netdev;
        rte_flow = uho->rte_flow_data[i].flow;
        if (rte_flow) {
            dpdk_port_id = netdev_dpdk_get_port(netd);
            if (dpdk_port_id != DPDK_ETH_PORT_ID_INVALID) {
                memset(&query, 0, sizeof query);
                /* reset counters after query */
                query.reset = 1;
                ret = ovs_rte_flow_query(dpdk_port_id, rte_flow,
                                         actions.actions, &query, &error);
                if (ret) {
                    /* TODO: moved to once as this fails due to current WA */
                    VLOG_DBG_ONCE("ufid "UUID_FMT
                             " flow %p query for port %d failed\n",
                             UUID_ARGS((struct uuid *)ufid), rte_flow,
                             dpdk_port_id);
                    continue;
                }
                stats->n_packets += (query.hits_set) ? query.hits : 0;
                stats->n_bytes += (query.bytes_set) ? query.bytes : 0;
            }
        }
    }

    free_flow_actions(&actions);
    ret = 0;

err:
    ovs_mutex_unlock(&ufid_to_portid_mutex);
    return ret;
}

static int
netdev_offloads_flow_del(const ovs_u128 *ufid, struct cmap *cmap,
                         enum ufid_to_rte_type_e ufid_to_rte_type)
{
    odp_port_t port_num = ufid_to_portid_search(ufid, cmap);
    struct ufid_hw_offload *hw_offload;
    int i=0;

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

    hw_offload = ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte[ufid_to_rte_type]);
    for (i = 0 ; i < hw_offload->curr_idx ; i++) {
            struct netdev *netd = hw_offload->rte_flow_data[i].netdev;

            if (netd == rte_port->netdev && hw_offload->rte_flow_data[i].flow != NULL) {
                struct ufid_to_odp *uto =
                    ufid_to_portid_get(ufid, &ufid_to_portid_map);
                /* If a recirc_id flow was offloaded then remove its hw_id ref */
                if (uto && uto->recirc_id) {
                    bool is_add = false;
                    bool is_port = false;
                    uint32_t hwid;
                    netdev_dpdk_peek_recirc_hw_id(uto->recirc_id, &hwid);
                    netdev_rte_update_hwid_mapping(rte_port, 0, hwid, is_add, is_port);
                    netdev_dpdk_put_recirc_id_hw_id(uto->recirc_id);

            }
       }
    }
    ufid_to_portid_remove(ufid, cmap);
    ufid_hw_offload = ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte[ufid_to_rte_type]);
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
    return netdev_offloads_flow_del(ufid, &ufid_to_portid_map, UFID_TO_RTE_OFFLOADS);
}

static int
netdev_rte_vport_flow_del(struct netdev *netdev OVS_UNUSED,
                          const ovs_u128 *ufid,
                          struct dpif_flow_stats *stats OVS_UNUSED)
{
    return netdev_offloads_flow_del(ufid, &ufid_to_portid_map, UFID_TO_RTE_OFFLOADS);
}

static int
netdev_rte_ct_flow_del(struct netdev *netdev OVS_UNUSED,
                       const ovs_u128 *ufid,
                       struct dpif_flow_stats *stats OVS_UNUSED)
{
    return netdev_offloads_flow_del(ufid, &ctid_to_portid_map, UFID_TO_RTE_CT);
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
    if (match->wc.masks.tunnel.ip_src || match->wc.masks.tunnel.ip_dst) {
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

        //ovs_be64 tun_id = match->flow.tunnel.tun_id;
        //ovs_be64 tun_id_mask = match->wc.masks.tunnel.tun_id;
        // TODO: add_flow_pattern(patterns, RTE_FLOW_ITEM_MD, (tun_id & tun_id_mask));

        /* Save proto for L4 protocol setup */
        proto = spec->ipv4.hdr.next_proto_id &
                mask->ipv4.hdr.next_proto_id;
    } else if (!is_all_zeros(&match->wc.masks.tunnel.ipv6_src,
                   sizeof(struct in6_addr)) ||
               !is_all_zeros(&match->wc.masks.tunnel.ipv6_dst,
                   sizeof(struct in6_addr))) {
        memset(&spec->ipv6, 0, sizeof spec->ipv6);
        memset(&mask->ipv6, 0, sizeof mask->ipv6);

        spec->ipv6.hdr.proto = IPPROTO_UDP;
        spec->ipv6.hdr.hop_limits = match->flow.tunnel.ip_ttl;
        rte_memcpy(spec->ipv6.hdr.src_addr,
            match->flow.tunnel.ipv6_src.s6_addr,
            sizeof spec->ipv6.hdr.src_addr);
        rte_memcpy(spec->ipv6.hdr.dst_addr,
            match->flow.tunnel.ipv6_dst.s6_addr,
            sizeof spec->ipv6.hdr.dst_addr);

        mask->ipv6.hdr.proto = 0xffu;
        mask->ipv6.hdr.hop_limits = match->wc.masks.tunnel.ip_ttl;
        rte_memcpy(mask->ipv6.hdr.src_addr,
            match->wc.masks.tunnel.ipv6_src.s6_addr,
            sizeof mask->ipv6.hdr.src_addr);
        rte_memcpy(mask->ipv6.hdr.dst_addr,
            match->wc.masks.tunnel.ipv6_dst.s6_addr,
            sizeof mask->ipv6.hdr.dst_addr);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6,
                         &spec->ipv6, &mask->ipv6);

        /* Save proto for L4 protocol setup */
        proto = spec->ipv6.hdr.proto &
                mask->ipv6.hdr.proto;
    } else {
        VLOG_ERR_RL(&error_rl, "Tunnel L3 protocol is neither IPv4 nor IPv6");
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
                                        struct dpif_flow_stats *stats)
{
    VLOG_DBG("Adding rte offload for vport vxlan flow ufid "UUID_FMT,
        UUID_ARGS((struct uuid *)ufid));

    if (!actions_len || !nl_actions) {
        VLOG_DBG("skip flow offload without actions\n");
        return 0;
    }

    int ret = 0;

    /* If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    struct ufid_hw_offload *ufid_hw_offload =
        ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte[UFID_TO_RTE_OFFLOADS]);

    if (ufid_hw_offload) {
        VLOG_DBG("got modification and destroying previous rte_flow");
        ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte[UFID_TO_RTE_OFFLOADS]);
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
        netdev_rte_port_ufid_hw_offload_alloc(dpdk_phy_ports_amount, ufid, info->flow_mark);
    if (ufid_hw_offload == NULL) {
        VLOG_WARN("failed to allocate ufid_hw_offlaod, OOM");
        return -1;
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte[UFID_TO_RTE_OFFLOADS]);
    ufid_to_portid_add(ufid, rte_port->dp_port, match->flow.recirc_id,
                       &ufid_to_portid_map);

    struct netdev_rte_port *data;
    struct rte_flow *flow;
    struct flow_data fdata;
    CMAP_FOR_EACH (data, node, &port_map) {
        /* Offload only in case the port is DPDK and it's the uplink port */
        if ((data->rte_port_type == RTE_PORT_TYPE_DPDK) &&
            (netdev_dpdk_is_uplink_port(data->netdev))) {
             memset(&fdata, 0, sizeof fdata);
            flow = netdev_dpdk_offload_put_handle(data->netdev, rte_port, &fdata,
                                              match, nl_actions,
                                              actions_len, info, true);
            if (!flow) {
                goto err;
            }
            ufid_hw_offload_add_rte_flow(ufid_hw_offload, flow, data->netdev);
        }
    }

    return ret;

err:
    netdev_rte_offloads_flow_del(data->netdev, ufid, stats);
    return -1;
}

static void
netdev_rte_add_ipv4_header_rewrite_flow_action(
    struct ct_flow_offload_item *ct_offload,
    struct rte_flow_action_set_ipv4 *ipv4_src,
    struct rte_flow_action_set_ipv4 *ipv4_dst,
    struct rte_flow_action_set_tp *port_src,
    struct rte_flow_action_set_tp *port_dst,
    struct flow_actions *actions)
{
    /* All values are in network order (BE) */

    /* Rewrite ipv4 src address */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_SRC_IP) {
        ipv4_src->ipv4_addr = ct_offload->ct_modify.ipv4.ipv4_src;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC, ipv4_src);
    }

    /* Rewrite ipv4 dst address */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_DST_IP) {
        ipv4_dst->ipv4_addr = ct_offload->ct_modify.ipv4.ipv4_dst;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_DST, ipv4_dst);
    }

    /* Rewrite transport port src */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_SRC_PORT) {
        port_src->port = ct_offload->ct_modify.ipv4.src_port;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_TP_SRC, port_src);
    }

    /* Rewrite transport port dst */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_DST_PORT) {
        port_dst->port = ct_offload->ct_modify.ipv4.dst_port;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_TP_DST, port_dst);
    }
}

static void
netdev_rte_add_ipv6_header_rewrite_flow_action(
    struct ct_flow_offload_item *ct_offload,
    struct rte_flow_action_set_ipv6 *ipv6_src,
    struct rte_flow_action_set_ipv6 *ipv6_dst,
    struct rte_flow_action_set_tp *port_src,
    struct rte_flow_action_set_tp *port_dst,
    struct flow_actions *actions)
{
    /* Rewrite ipv6 src address */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_SRC_IP) {
        memcpy(&ipv6_src->ipv6_addr, &ct_offload->ct_modify.ipv6.ipv6_src,
               sizeof ipv6_src->ipv6_addr);
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC, ipv6_src);
    }

    /* Rewrite ipv6 dst address */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_DST_IP) {
        memcpy(&ipv6_dst->ipv6_addr, &ct_offload->ct_modify.ipv6.ipv6_dst,
               sizeof ipv6_src->ipv6_addr);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_IPV6_DST, ipv6_dst);
    }

    /* Port values are in network order (short BE) */
    /* Rewrite transport port src */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_SRC_PORT) {
        port_src->port = ct_offload->ct_modify.ipv6.src_port;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_TP_SRC, port_src);
    }

    /* Rewrite transport port dst */
    if (ct_offload->mod_flags & CT_OFFLOAD_MODIFY_DST_PORT) {
        port_dst->port = ct_offload->ct_modify.ipv6.dst_port;
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_SET_TP_DST, port_dst);
    }
}

struct ct_stats;

static int
ct_add_rte_flow_offload(struct netdev_rte_port *rte_port,
                        struct match *match,
                        struct ct_flow_offload_item *ct_offload,
                        const ovs_u128 *ctid,
                        uint32_t mark_id,
                        bool nat,
                        struct ct_stats *stats OVS_UNUSED)
{
    struct flow_action_items action_items;
    int ret = 0;

    /* If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    struct ufid_hw_offload *ctid_hw_offload =
        ufid_hw_offload_find(ctid, &rte_port->ufid_to_rte[UFID_TO_RTE_CT]);

    if (ctid_hw_offload) {
        VLOG_DBG("got modification and destroying previous rte_flow");
        ret = netdev_rte_ct_flow_del(rte_port->netdev, ctid, NULL);
        if (ret < 0) {
            return ret;
        }
    }

    uint32_t num_ports = 0;
    if (rte_port->rte_port_type == RTE_PORT_TYPE_DPDK) {
        num_ports = 1;
    } else {
        if (rte_port->rte_port_type == RTE_PORT_TYPE_VXLAN) {
            num_ports = dpdk_phy_ports_amount;
        }
    }
    if (!num_ports) {
        VLOG_WARN("offload while no phy ports %u", num_ports);
        return -1;
    }
    ctid_hw_offload =
        netdev_rte_port_ufid_hw_offload_alloc(num_ports, ctid, 0);
    if (ctid_hw_offload == NULL) {
        VLOG_WARN("failed to allocate ctid_hw_offlaod, OOM");
        return -1;
    }

    ufid_hw_offload_add(ctid_hw_offload, &rte_port->ufid_to_rte[UFID_TO_RTE_CT]);
    ufid_to_portid_add(ctid, rte_port->dp_port, match->flow.recirc_id,
                       &ctid_to_portid_map);

    struct rte_flow_attr flow_attr = {
        .group = nat ? CONNTRACK_NAT_TABLE_ID : CONNTRACK_TABLE_ID,
        .priority = 0,
        .ingress = 1,
        .egress = 0,
        .transfer = 1
    };

    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };

    struct flow_items spec, mask;
    memset(&spec, 0, sizeof spec);
    memset(&mask, 0, sizeof mask);

    ret = add_flow_patterns(&patterns, &spec, &mask, match);
    if (ret) {
        goto out;
    }
    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    /*
     * Actions for a CT-NAT flow: header rewrite
     * Additional actions for both CT and CT-NAT:
     *   1. COUNT
     *   2. JUMP to mapping table.
     */
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow_action_set_ipv4 ipv4_src;
    struct rte_flow_action_set_ipv4 ipv4_dst;
    struct rte_flow_action_set_ipv6 ipv6_src;
    struct rte_flow_action_set_ipv6 ipv6_dst;
    struct rte_flow_action_set_tp port_src;
    struct rte_flow_action_set_tp port_dst;
    struct rte_flow_action_count count;
    struct rte_flow_action_mark mark;
    struct rte_flow_action_jump jump;

    if (nat) {
        if (!ct_offload->ct_ipv6) {
            /* Do ipv4 header rewrite due to NAT */
            netdev_rte_add_ipv4_header_rewrite_flow_action(ct_offload, &ipv4_src,
                                                           &ipv4_dst, &port_src,
                                                           &port_dst, &actions);
        } else {
            /* Do ipv6 header rewrite due to NAT */
            netdev_rte_add_ipv6_header_rewrite_flow_action(ct_offload, &ipv6_src,
                                                           &ipv6_dst, &port_src,
                                                           &port_dst, &actions);
        }
    }

    if (netdev_dpdk_add_action_set_reg(&action_items, &actions,
                                       TAG_FIELD_CT_STATE,
                                       ct_offload->ct_state)) {
        VLOG_DBG("failed to set ct_state");
        return -1;
    }

    netdev_rte_add_count_flow_action(&count, &actions);
    netdev_rte_add_mark_flow_action(&mark, mark_id, &actions);
    netdev_rte_add_jump_flow_action(&jump, MAPPING_TABLE_ID, &actions);
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    struct netdev_rte_port *data;
    struct rte_flow_error error;
    struct rte_flow *flow;

    if (rte_port->rte_port_type == RTE_PORT_TYPE_DPDK) {
        flow = netdev_dpdk_rte_flow_create(rte_port->netdev,
                                           &flow_attr, patterns.items,
                                           actions.actions, &error);
        VLOG_DBG("eSwitch offload was %s", flow ? "succeeded" : "failed");

        if (!flow) {
            VLOG_ERR("%s: rte flow create offload error: %u : "
                     "message : %s\n", netdev_get_name(rte_port->netdev),
                     error.type, error.message);

            /* TODO: OZ: missing error handling */
        }
        if (flow) {
            ufid_hw_offload_add_rte_flow(ctid_hw_offload, flow,
                                         rte_port->netdev);
        }
    }
    if (rte_port->rte_port_type == RTE_PORT_TYPE_VXLAN) {
        CMAP_FOR_EACH (data, node, &port_map) {
            if (!netdev_dpdk_is_uplink_port(data->netdev)) {
                continue;
            }
            if (data->rte_port_type == RTE_PORT_TYPE_DPDK) {
                flow = netdev_dpdk_rte_flow_create(data->netdev,
                                                   &flow_attr, patterns.items,
                                                   actions.actions, &error);
                VLOG_DBG("eSwitch offload was %s", flow ?
                         "succeeded" : "failed");

                if (!flow) {
                    VLOG_ERR("%s: rte flow create offload error: %u : "
                             "message : %s\n", netdev_get_name(data->netdev),
                             error.type, error.message);
                }
                if (flow) {
                    ufid_hw_offload_add_rte_flow(ctid_hw_offload, flow,
                                                 data->netdev);
                }
            }
        }
    }

out:
    free_flow_patterns(&patterns);
    free_flow_actions(&actions);
    return ret;
}

static struct mark_to_miss_ctx_data *
    netdev_dpdk_get_flow_miss_ctx(uint32_t mark, bool create);

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
    cls->flow_stats_get = netdev_rte_offloads_flow_stats_get;
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
        bool is_uplink = netdev_dpdk_is_uplink_port(netdev);
        ret = netdev_rte_port_set(netdev, dp_port, RTE_PORT_TYPE_DPDK,
                                  is_uplink, &rte_port);
        if (!rte_port) {
            goto out;
        }

        rte_port->dpdk_num_queues = netdev_n_rxq(netdev);
        rte_port->dpdk_port_id = netdev_dpdk_get_port_id(netdev);
        dpdk_phy_ports_amount++;
        /* Reserve a hw id for this dp_port */
        uint32_t hw_id;
        netdev_dpdk_get_port_hw_id(dp_port, &hw_id);
        VLOG_INFO("Rte dpdk port %d allocated.", dp_port);
        goto out;
    }
    if (!strcmp("vxlan", type)) {
        ret = netdev_rte_port_set(netdev, dp_port, RTE_PORT_TYPE_VXLAN,
                                  false, &rte_port);
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

    CMAP_CURSOR_FOR_EACH (data, node, &cursor, &rte_port->ufid_to_rte[UFID_TO_RTE_OFFLOADS]) {
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
    int ret;

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
        bool is_add = false;
        bool is_port = true;
        uint32_t hwid;
        ret = netdev_dpdk_peek_port_hw_id(rte_port->dp_port, &hwid);
        if (ret == INVALID_HW_ID) {
            VLOG_ERR("Failed to get dp_port %u mapping to hwid", rte_port->dp_port);
        }
        netdev_rte_update_hwid_mapping(NULL, 0, hwid, is_add, is_port);
        netdev_dpdk_put_port_id_hw_id(dp_port);
    } else if (rte_port->rte_port_type == RTE_PORT_TYPE_VXLAN) {
        cmap_remove(&mark_to_rte_port,
                    CONST_CAST(struct cmap_node *,
                    &rte_port->mark_node),
                    hash_bytes(&rte_port->exception_mark,
                    sizeof rte_port->exception_mark,0));
    }

    ovsrcu_postpone(free, rte_port);

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

#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_byteorder.h>

#define NETDEV_RTE_OFFLOADS_MAX_QPAIRS 16
#define NETDEV_RTE_OFFLOADS_MAX_RELAYS RTE_MAX_ETHPORTS
#define SIZEOF_MBUF (sizeof(struct rte_mbuf *))
#define NETDEV_RTE_OFFLOADS_INVALID_ID 0xFFFF

static struct rte_eth_conf netdev_rte_offloads_port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};

struct qpair_stats {
    uint64_t packets;
    uint64_t bytes;
};

struct netdev_rte_offloads_qpair {
    uint16_t port_id_rx;
    uint16_t port_id_tx;
    uint16_t pr_queue;
    uint8_t mbuf_head;
    uint8_t mbuf_tail;
    struct rte_mbuf *pkts[NETDEV_MAX_BURST * 2];
    struct qpair_stats qp_stats;
};

struct relay_flow {
    struct rte_flow *flow;
    bool queues_en[RTE_MAX_QUEUES_PER_PORT];
    uint32_t priority;
};

struct netdev_pr {
    char *name;
    int n_rxq;
};

struct netdev_rte_offloads_relay {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct netdev_rte_offloads_qpair qpair[NETDEV_RTE_OFFLOADS_MAX_QPAIRS * 2];
        rte_atomic16_t valid;
        uint32_t num_queues;
        struct rte_mempool *mempool;
        struct relay_flow flow_params;
        struct netdev_pr *pr_netdev;
        char vf_pci[15];
        char vm_socket[128];
        int port_id_vm;
        int port_id_vf;
        rte_spinlock_t relay_lock;
        );
};

static struct netdev_rte_offloads_relay *relays;

static int
netdev_rte_offloads_get_port_from_name(const char *name)
{
    int port_id;
    size_t len;

    if (name == NULL) {
        VLOG_ERR("Null pointer is specified\n");
        return -1;
    }
    len = strlen(name);
    for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        if (rte_eth_dev_is_valid_port(port_id) &&
                !strncmp(name, rte_eth_devices[port_id].device->name, len)) {
            return port_id;
        }
    }
    VLOG_ERR("No port was found for %s\n", name);
    return -1;
}

static void
netdev_rte_offloads_clear_relay(struct netdev_rte_offloads_relay *relay)
{
    uint16_t q, i;

    for (q = 0; q < relay->num_queues; q++) {
        for (i = relay->qpair[q].mbuf_head; i < relay->qpair[q].mbuf_tail; ++i) {
            rte_pktmbuf_free(relay->qpair[q].pkts[i]);
        }
        relay->qpair[q].mbuf_head = 0;
        relay->qpair[q].mbuf_tail = 0;
        relay->qpair[q].port_id_rx = 0;
        relay->qpair[q].port_id_tx = 0;
        relay->qpair[q].pr_queue = 0;
        relay->qpair[q].qp_stats.bytes = 0;
        relay->qpair[q].qp_stats.packets = 0;
    }

    memset(relay->vm_socket, 0, sizeof relay->vm_socket);
    memset(relay->vf_pci, 0, sizeof relay->vf_pci);
    relay->port_id_vm = 0;
    relay->port_id_vf = 0;
    relay->num_queues = 0;
    relay->mempool = NULL;
    rte_free(relay->pr_netdev->name);
    rte_free(relay->pr_netdev);
    relay->flow_params.flow = NULL;
    memset(&relay->flow_params, 0, sizeof relay->flow_params);

    rte_atomic16_clear(&relay->valid);
}

static int
netdev_rte_offloads_generate_rss_flow(struct netdev_rte_offloads_relay *relay)
{
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[2];
    struct rte_flow_action action[2];
    static struct rte_flow_action_rss action_rss = {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
            .key_len = 0,
            .key = NULL,
    };
    struct rte_flow *flow = NULL;
    uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
    unsigned int i;
    unsigned int j;
    struct rte_flow_error error;
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    if (relay->flow_params.priority) {
        attr.priority = 0;
    } else {
        attr.priority = 1;
    }

    for (i = 0, j = 0; i < RTE_MAX_QUEUES_PER_PORT; ++i) {
        if (relay->flow_params.queues_en[i] == true) {
            queue[j++] = i;
        }
    }

    action_rss.queue = queue;
    action_rss.queue_num = j;

    action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
    action[0].conf = &action_rss;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].spec = NULL;
    pattern[0].mask = NULL;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

    flow = rte_flow_create(relay->port_id_vf, &attr, pattern, action, &error);
    if (flow == NULL) {
        VLOG_ERR("Failed to create flow. msg: %s\n",
                error.message ? error.message : "(no stated reason)");
        return -1;
    }

    if( relay->flow_params.flow != NULL)
    {
        res = rte_flow_destroy(relay->port_id_vf, relay->flow_params.flow, &error);
        if (res < 0) {
            VLOG_ERR("Failed to destroy flow. msg: %s\n",
                    error.message ? error.message : "(no stated reason)");
            return -1;
        }
    }

    relay->flow_params.flow = flow;
    relay->flow_params.priority = attr.priority;
    return 0;
}

static int
netdev_rte_offloads_queue_state(uint16_t port, uint16_t relay_id)
{
    struct rte_eth_vhost_queue_event event;
    uint32_t q_index;
    int ret = 0;

    while (ret == 0) {
        ret = rte_eth_vhost_get_queue_event(port, &event);
        if (ret < 0) {
            return 0;
        }
        if (event.rx) {
            q_index = event.queue_id * 2;
        } else {
            q_index = event.queue_id * 2 + 1;
        }

        if (event.enable) {
            if(!event.rx) {
                relays[relay_id].flow_params.queues_en[event.queue_id] = true;
                if (netdev_rte_offloads_generate_rss_flow(&relays[relay_id]) < 0) {
                    VLOG_ERR("netdev_rte_offloads_generate_rss_flow failed\n");
                    return -1;
                }
            }
            relays[relay_id].qpair[q_index].pr_queue =
                    q_index % relays[relay_id].pr_netdev->n_rxq;
        }
    }

    return 0;
}

static int
netdev_rte_offloads_queue_state_cb_fn(uint16_t port_id,
                                      enum rte_eth_event_type type,
                                      void *param,
                                      void *ret_param)
{
    int ret;
    struct rte_eth_vhost_queue_event event;
    struct netdev_rte_offloads_relay *relay = param;
    uint32_t q_index;

    RTE_SET_USED(type);
    RTE_SET_USED(ret_param);

    ret = 0;
    while (ret == 0) {
        ret = rte_eth_vhost_get_queue_event(port_id, &event);
        if (ret < 0) {
            return 0;
        }
        if (event.rx) {
            q_index = event.queue_id * 2;
        } else {
            q_index = event.queue_id * 2 + 1;
        }

        if (event.enable) {
            if(!event.rx) {
                relay->flow_params.queues_en[event.queue_id] = true;
                netdev_rte_offloads_generate_rss_flow(relay);
            }
            relay->qpair[q_index].pr_queue =
                    q_index % relay->pr_netdev->n_rxq;
        } else {
            if(!event.rx) {
                relay->flow_params.queues_en[event.queue_id] = false;
                netdev_rte_offloads_generate_rss_flow(relay);
            }
            relay->qpair[q_index].pr_queue =
                    NETDEV_RTE_OFFLOADS_INVALID_ID;
        }
    }

    return 0;
}

static int
netdev_rte_offloads_link_status_cb_fn(uint16_t port_id,
                                      enum rte_eth_event_type type,
                                      void *param,
                                      void *ret_param)
{
    struct rte_eth_link link;
    struct netdev_rte_offloads_relay *relay = param;
    int q;

    RTE_SET_USED(type);
    RTE_SET_USED(ret_param);

    rte_eth_link_get_nowait(port_id, &link);
    if (!link.link_status) {
        for (q = 0; q < NETDEV_RTE_OFFLOADS_MAX_QPAIRS; ++q){
            relay->qpair[q].pr_queue = NETDEV_RTE_OFFLOADS_INVALID_ID;
        }
        for (q = 0; q < RTE_MAX_QUEUES_PER_PORT; ++q){
            relay->flow_params.queues_en[q] = false;
        }
    }

    return 0;
}

static int
netdev_rte_offloads_port_init(uint16_t relay_id,
                              uint16_t port,
                              uint16_t queue_num,
                              struct rte_mempool *mbuf_pool,
                              bool vm)
{
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;
    int ret;

    if (!rte_eth_dev_is_valid_port(port)) {
        VLOG_ERR("port_init invalid port %u\n", port);
        return -1;
    }
    rte_eth_dev_info_get(port, &dev_info);
    netdev_rte_offloads_port_conf.rxmode.offloads = 0;

    /* enable tso for vf: */
    netdev_rte_offloads_port_conf.txmode.offloads = 0;
    if (!vm)
        netdev_rte_offloads_port_conf.txmode.offloads = (DEV_TX_OFFLOAD_TCP_TSO |
                DEV_TX_OFFLOAD_MULTI_SEGS);

    ret = rte_eth_dev_configure(port, queue_num, queue_num,
            &netdev_rte_offloads_port_conf);
    if (ret < 0) {
        VLOG_ERR("rte_eth_dev_configure failed\n");
        return ret;
    }
    for (q = 0; q < queue_num; q++) {
        ret = rte_eth_rx_queue_setup(port, q, 512,
                        rte_eth_dev_socket_id(port),
                        NULL, mbuf_pool);
        if (ret < 0) {
            VLOG_ERR("rte_eth_rx_queue_setup failed with error %i\n", ret);
            rte_eth_dev_close(port);
            return ret;
        }
    }
    txconf = dev_info.default_txconf;
    txconf.offloads = netdev_rte_offloads_port_conf.txmode.offloads;
    for (q = 0; q < queue_num; q++) {
        ret = rte_eth_tx_queue_setup(port, q, 512,
                        rte_eth_dev_socket_id(port),
                        &txconf);
        if (ret < 0) {
            VLOG_ERR("rte_eth_tx_queue_setup failed with error %i\n", ret);
            rte_eth_dev_close(port);
            return ret;
        }
    }

    if (vm)
        netdev_rte_offloads_queue_state(port, relay_id);

    ret = rte_eth_dev_callback_register(port, RTE_ETH_EVENT_QUEUE_STATE,
            netdev_rte_offloads_queue_state_cb_fn, &relays[relay_id]);
    if (ret < 0) {
        VLOG_ERR("rte_eth_dev_callback_register failed with error %i\n", ret);
        return ret;
    }

    ret = rte_eth_dev_callback_register(port, RTE_ETH_EVENT_INTR_LSC,
            netdev_rte_offloads_link_status_cb_fn, &relays[relay_id]);
    if (ret < 0) {
        VLOG_ERR("rte_eth_dev_callback_register failed with error %i\n", ret);
        return ret;
    }

    ret = rte_eth_dev_start(port);
    if (ret < 0) {
        VLOG_ERR("rte_eth_dev_start failed\n");
        rte_eth_dev_close(port);
        return ret;
    }

    return 0;
}

static int
netdev_rte_offloads_update_relay(uint16_t relay_id,
                                 uint32_t num_queues,
                                 int *port_id_vm,
                                 int *port_id_vf,
                                 const char *vf_pci,
                                 const char *vhost_socket)
{
    uint32_t q;
    int ret;

    strcpy(relays[relay_id].vf_pci, vf_pci);
    strcpy(relays[relay_id].vm_socket, vhost_socket);
    relays[relay_id].num_queues = num_queues;
    relays[relay_id].port_id_vf = *port_id_vf;
    relays[relay_id].port_id_vm = *port_id_vm;
    relays[relay_id].flow_params.flow = NULL;
    relays[relay_id].flow_params.priority = 0;
    memset(relays[relay_id].flow_params.queues_en, false,
            sizeof(bool) * RTE_MAX_QUEUES_PER_PORT);
    rte_spinlock_init(&relays[relay_id].relay_lock);

    for (q = 0; q < (num_queues * 2); q++) {
        relays[relay_id].qpair[q].pr_queue = NETDEV_RTE_OFFLOADS_INVALID_ID;
        if (q & 1) {
            relays[relay_id].qpair[q].port_id_rx = *port_id_vm;
            relays[relay_id].qpair[q].port_id_tx = *port_id_vf;
        } else {
            relays[relay_id].qpair[q].port_id_rx = *port_id_vf;
            relays[relay_id].qpair[q].port_id_tx = *port_id_vm;
        }
        relays[relay_id].qpair[q].mbuf_head = 0;
        relays[relay_id].qpair[q].mbuf_tail = 0;
        memset(&relays[relay_id].qpair[q].qp_stats, 0, sizeof(struct qpair_stats));
    }

    ret = netdev_rte_offloads_port_init(relay_id, *port_id_vf, num_queues,
            relays[relay_id].mempool, false);
    if (ret) {
        VLOG_ERR("port_init failed, port_id %u\n", *port_id_vf);
        return ret;
    }

    ret = netdev_rte_offloads_port_init(relay_id, *port_id_vm, num_queues,
            relays[relay_id].mempool, true);
    if (ret) {
        VLOG_ERR("port_init failed, port_id %u\n", *port_id_vm);
        rte_eth_dev_stop(*port_id_vf);
        rte_eth_dev_close(*port_id_vf);
        return ret;
    }
    return 0;
}

static void
parse_packet_fields(struct rte_mbuf *m, uint16_t port_id)
{
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;
    struct rte_ether_hdr *eth_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    uint32_t l2_len = 0;
    uint32_t l3_len = 0;
    uint32_t l4_len = 0;
    uint64_t ol_flags = 0;
    uint8_t l4_proto_id = 0;
    uint16_t mtu = 0;
    int ret = 0;

    if (m->pkt_len < 1400)
        return;

    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    l2_len = sizeof(struct rte_ether_hdr);

    switch (rte_be_to_cpu_16(eth_hdr->ether_type)) {
    case RTE_ETHER_TYPE_IPV4:
        ipv4_hdr = (struct rte_ipv4_hdr *) ((char *)eth_hdr + l2_len);
        l3_len = (ipv4_hdr->version_ihl & 0x0f) * 4;
        l4_proto_id = ipv4_hdr->next_proto_id;
        if (l4_proto_id == IPPROTO_TCP) {
            tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + l3_len);
            l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
            ol_flags |= (PKT_TX_IPV4 | PKT_TX_IP_CKSUM);
        }
        break;
    case RTE_ETHER_TYPE_IPV6:
        ipv6_hdr = (struct rte_ipv6_hdr *) ((char *)eth_hdr + l2_len);
        l4_proto_id = ipv6_hdr->proto;
        if (l4_proto_id == IPPROTO_TCP) {
            l3_len = sizeof(struct rte_ipv6_hdr);
            tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv6_hdr + l3_len);
            l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
            ol_flags |= PKT_TX_IPV6;
        }
        break;
    default:
        return;
    }

    if (l4_proto_id == IPPROTO_TCP) {
        ol_flags |= (PKT_TX_TCP_SEG | PKT_TX_TCP_CKSUM);
        m->l2_len = l2_len;
        m->l3_len = l3_len;
        m->l4_len = l4_len;
        m->ol_flags = ol_flags;
        ret = rte_eth_dev_get_mtu(port_id, &mtu);
        if (ret < 0) {
            mtu = 1500;
        }
        m->tso_segsz = mtu - l3_len - l4_len;
    }
}

static int
netdev_rte_offloads_forward_traffic(struct netdev_rte_offloads_qpair *qpair,
                                    uint16_t queue_id)
{
    int burst_success;
    int diff;
    uint32_t fwd_rx = 0;
    int i;
    bool tx_vf = (queue_id & 1) ? true : false;

    queue_id = queue_id >> 1;
    diff = qpair->mbuf_tail - qpair->mbuf_head;
    if (diff >= NETDEV_MAX_BURST) {
        goto send;
    }

    /*copy pkts to start*/
    if (unlikely(qpair->mbuf_tail > NETDEV_MAX_BURST)) {
        rte_memcpy(&qpair->pkts[0], &qpair->pkts[qpair->mbuf_head],
                   diff * SIZEOF_MBUF);
        qpair->mbuf_head = 0;
        qpair->mbuf_tail = diff;
    }

    /*receive burst:*/
    burst_success = rte_eth_rx_burst(qpair->port_id_rx, queue_id,
                                     qpair->pkts + qpair->mbuf_tail,
                                     NETDEV_MAX_BURST);
    qpair->mbuf_tail += burst_success;
    diff += burst_success;
    fwd_rx += burst_success;

    /*send:*/
send:
    if (diff == 0){
        return 0;
    }

    diff = MIN(diff, NETDEV_MAX_BURST);
    if (tx_vf) {
        for (i = 0; i < diff; ++i) {
            parse_packet_fields(qpair->pkts[qpair->mbuf_head + i], qpair->port_id_tx);
        }
    }

    burst_success = rte_eth_tx_burst(qpair->port_id_tx, queue_id,
            qpair->pkts+qpair->mbuf_head, diff);

    /* update stats */
    if (likely(burst_success)) {
        unsigned bytes = 0;
        for (i = 0; i < burst_success; ++i) {
            bytes += qpair->pkts[qpair->mbuf_head + i]->pkt_len;
        }
        qpair->qp_stats.packets += burst_success;
        qpair->qp_stats.bytes += bytes;
    }

    qpair->mbuf_head += burst_success;
    if (likely(qpair->mbuf_head == qpair->mbuf_tail)) {
        qpair->mbuf_head = 0;
        qpair->mbuf_tail = 0;
    }
    return fwd_rx;
}

static int
netdev_rte_offloads_check_valid_params(const char *pci,
                                       const char *vhost_socket,
                                       uint16_t relay_id)
{
    if (strcmp (relays[relay_id].vm_socket, vhost_socket) == 0 ) {
        VLOG_ERR("vhost %s already exists, can't add relay\n",
                vhost_socket);
        return -1;
    }
    if (strcmp (relays[relay_id].vf_pci, pci) == 0 ) {
        VLOG_ERR("PCI %s already exists, can't add relay\n",
                pci);
        return -1;
    }
    return 0;
}

static int
netdev_rte_offloads_get_relay_id(const char *pci,
                                 const char *vhost_socket)
{
    uint16_t relay_id = 0;
    uint16_t next_valid = NETDEV_RTE_OFFLOADS_INVALID_ID;

    for (relay_id = 0; relay_id < NETDEV_RTE_OFFLOADS_MAX_RELAYS; relay_id++) {
        /* find a free index in the relays array */
        if (next_valid == NETDEV_RTE_OFFLOADS_INVALID_ID) {
            if (rte_atomic16_test_and_set(&relays[relay_id].valid)) {
                next_valid = relay_id;
            }
        }
        /* check that the socket/PCI doesn't exist */
        if (netdev_rte_offloads_check_valid_params(pci, vhost_socket, relay_id) < 0) {
            if (next_valid != NETDEV_RTE_OFFLOADS_INVALID_ID) {
                rte_atomic16_clear(&relays[next_valid].valid);
            }
            return -1;
        }
    }
    return next_valid;
}

static int
netdev_rte_offloads_add_relay(const char *pci,
                              const char *vhost_socket,
                              const char *pr,
                              uint32_t max_queues)
{
    struct netdev *netdev = NULL;
    char vhost_name[40];
    char vhost_args[128];
    int relay_id = 0;
    int port_id_vm, port_id_vf;
    int len = 0;
    int ret = 0;

    relay_id = netdev_rte_offloads_get_relay_id(pci, vhost_socket);
    if (relay_id < 0) {
        VLOG_ERR("netdev_rte_offloads_get_relay_id falied\n");
        return -1;
    }
    /* add new relay */
    netdev = netdev_from_name(pr);
    if (netdev == NULL) {
        VLOG_ERR("Port %s doesn't exist\n", pr);
        rte_atomic16_clear(&relays[relay_id].valid);
        return -1;
    }

    relays[relay_id].pr_netdev = xmalloc(sizeof *relays[relay_id].pr_netdev);
    relays[relay_id].pr_netdev->name = xmalloc(sizeof *relays[relay_id].pr_netdev->name);
    relays[relay_id].pr_netdev->n_rxq = netdev->n_rxq;
    strcpy(relays[relay_id].pr_netdev->name, pr);
    relays[relay_id].mempool = netdev_dpdk_hw_forwarder_get_mempool(pr);

    sprintf(vhost_name, "net_vhost%d", relay_id);
    len += sprintf(vhost_args, "iface=%s,queues=%d,client=1",
                   vhost_socket, max_queues);

    /* create virtio vdev:*/
    ret = rte_eal_hotplug_add("vdev", vhost_name, vhost_args);
    if (ret) {
        VLOG_ERR("rte_eal_hotplug_add vdev failed\n");
        goto err_vdev;
    }
    port_id_vm = netdev_rte_offloads_get_port_from_name(vhost_name);
    if (port_id_vm < 0 ) {
        VLOG_ERR("No port id found for vm %s\n", vhost_name);
        ret = -1;
        goto err_vdev;
    }

    /* create vf:*/
    ret = rte_eal_hotplug_add("pci", pci, "");
    if (ret) {
        VLOG_ERR("rte_eal_hotplug_add pci failed\n");
        goto err_vf;
    }

    port_id_vf = netdev_rte_offloads_get_port_from_name(pci);
    if (port_id_vf < 0) {
        VLOG_ERR("No port id found for vf %s\n", pci);
        ret = -1;
        goto err_update_relay;
    }

    ret = netdev_rte_offloads_update_relay(relay_id, max_queues, &port_id_vm, &port_id_vf, pci,
                                           vhost_socket);
    if (ret) {
        VLOG_ERR("update_relay failed\n"
                  "relay id %u, vhost socket %s, vhost name %s, PCI %s\n",
                  relay_id, vhost_socket, vhost_name, pci);
        goto err_update_relay;
    }

    /* add the relay to the pr */
    netdev_dpdk_hw_forwarder_update(pr, relay_id, netdev_rte_offloads_hw_pr_fwd,
                                    netdev_rte_offloads_hw_pr_remove);
    goto out;

err_update_relay:
    rte_eal_hotplug_remove("pci", pci);
err_vf:
    rte_eal_hotplug_remove("vdev", vhost_name);
err_vdev:
    netdev_rte_offloads_clear_relay(&relays[relay_id]);
out:
    netdev_close(netdev);
    return ret;
}

static int
netdev_rte_offloads_remove_relay(const char *vhost_path, bool remove_dev)
{
    uint16_t relay_id;
    int found = 0;
    int port_id;
    char vhost_name[40];

    for (relay_id = 0; relay_id < NETDEV_RTE_OFFLOADS_MAX_RELAYS; relay_id++) {
        if (strcmp (relays[relay_id].vm_socket, vhost_path) == 0 ) {
            found = 1;
            break;
        }
    }
    if (!found) {
        VLOG_ERR("Could not find relay for %s", vhost_path);
        return -1;
    }

    rte_spinlock_lock(&relays[relay_id].relay_lock);
    /* if the PR still exist, remove the relay from the pr */
    if (!remove_dev) {
        netdev_dpdk_hw_forwarder_update(relays[relay_id].pr_netdev->name, relay_id,
                NULL, NULL);
    }

    port_id = relays[relay_id].port_id_vm;
    rte_eth_dev_stop(port_id);
    rte_eth_dev_callback_unregister(port_id, RTE_ETH_EVENT_QUEUE_STATE,
            netdev_rte_offloads_queue_state_cb_fn, &relays[relay_id]);
    rte_eth_dev_callback_unregister(port_id, RTE_ETH_EVENT_INTR_LSC,
            netdev_rte_offloads_link_status_cb_fn, &relays[relay_id]);
    rte_eth_dev_close(port_id);

    port_id = relays[relay_id].port_id_vf;
    rte_eth_dev_stop(port_id);
    rte_eth_dev_callback_unregister(port_id, RTE_ETH_EVENT_QUEUE_STATE,
            netdev_rte_offloads_queue_state_cb_fn, &relays[relay_id]);
    rte_eth_dev_callback_unregister(port_id, RTE_ETH_EVENT_INTR_LSC,
            netdev_rte_offloads_link_status_cb_fn, &relays[relay_id]);
    rte_eth_dev_close(port_id);

    if (relays[relay_id].flow_params.flow != NULL ) {
        struct rte_flow_error error;
        rte_flow_destroy(port_id, relays[relay_id].flow_params.flow, &error);
    }

    sprintf(vhost_name, "net_vhost%d", relay_id);
    rte_eal_hotplug_remove("vdev", vhost_name);
    rte_eal_hotplug_remove("pci", relays[relay_id].vf_pci);

    netdev_rte_offloads_clear_relay(&relays[relay_id]);
    rte_spinlock_unlock(&relays[relay_id].relay_lock);
    return 0;
}

static void
netdev_rte_offloads_show_statistics_vm(struct ds *reply)
{
    uint32_t relay_id;
    uint32_t qp_index;
    struct netdev_rte_offloads_qpair *qp;
    enum stats_array {RX_PKTS, RX_BYTES, TX_PKTS, TX_BYTES, STATS_LAST};
    uint64_t count_stats[STATS_LAST] = {0};

    ds_put_cstr(reply,"############################## STATISTICS ##############################\n\n");
    for (relay_id = 0; relay_id < NETDEV_RTE_OFFLOADS_MAX_RELAYS; ++relay_id) {
        if (rte_atomic16_read(&relays[relay_id].valid) == 1) {
            rte_spinlock_lock(&relays[relay_id].relay_lock);
            ds_put_format(reply, "relay id: %u, VM:  %s, VF:  %s\n",
                    relay_id, relays[relay_id].vm_socket,
                    relays[relay_id].vf_pci);

            memset(count_stats, 0, sizeof count_stats);
            for (qp_index = 0; qp_index < NETDEV_RTE_OFFLOADS_MAX_QPAIRS; qp_index++) {
                qp = &relays[relay_id].qpair[qp_index];
                if (qp_index & 1) {
                    count_stats[TX_PKTS] += qp->qp_stats.packets;
                    count_stats[TX_BYTES] += qp->qp_stats.bytes;
                } else{
                    count_stats[RX_PKTS] += qp->qp_stats.packets;
                    count_stats[RX_BYTES] += qp->qp_stats.bytes;
                }
            }
            rte_spinlock_unlock(&relays[relay_id].relay_lock);

            ds_put_format(reply,"\tRX-packets: %" PRId64 " RX-bytes: %" PRId64 " \n",
                    count_stats[RX_PKTS], count_stats[RX_BYTES]);
            ds_put_format(reply,"\tTX-packets: %" PRId64 " TX-bytes: %" PRId64 " \n",
                    count_stats[TX_PKTS], count_stats[TX_BYTES]);
        }
    }
    ds_put_cstr(reply,"\n########################################################################\n\n");
}

static void
netdev_rte_offloads_show_statistics_queue(struct ds *reply)
{
    uint32_t relay_id;
    uint32_t q_index;
    struct netdev_rte_offloads_qpair *qp;

    ds_put_cstr(reply,"############################## STATISTICS ##############################\n\n");
    for (relay_id = 0; relay_id < NETDEV_RTE_OFFLOADS_MAX_RELAYS; ++relay_id) {
        if (rte_atomic16_read(&relays[relay_id].valid) == 1) {
            rte_spinlock_lock(&relays[relay_id].relay_lock);
            ds_put_format(reply, "relay id: %u, VM:  %s, VF:  %s\n",
                    relay_id, relays[relay_id].vm_socket,
                    relays[relay_id].vf_pci);

            for (q_index = 0; q_index < NETDEV_RTE_OFFLOADS_MAX_QPAIRS; q_index++) {
                if (relays[relay_id].flow_params.queues_en[q_index>>1]) {
                    qp = &relays[relay_id].qpair[q_index];
                    if (q_index&1) {
                        ds_put_format(reply,"\t\tTX-packets: %" PRId64 " TX-bytes: %" PRId64 " \n",
                                qp->qp_stats.packets, qp->qp_stats.bytes);
                        ds_put_cstr(reply,"\n");
                    } else{
                        ds_put_format(reply,"\tqueue %u:\n", (q_index>>1));
                        ds_put_format(reply,"\t\tRX-packets: %" PRId64 " RX-bytes: %" PRId64 " \n",
                                qp->qp_stats.packets, qp->qp_stats.bytes);
                    }
                }
            }
            rte_spinlock_unlock(&relays[relay_id].relay_lock);
        }
    }
    ds_put_cstr(reply,"\n########################################################################\n\n");
}

static void
netdev_rte_offloads_show_relays(struct ds *reply)
{
    uint32_t relay_id;

    for (relay_id = 0; relay_id < NETDEV_RTE_OFFLOADS_MAX_RELAYS; ++relay_id) {
        if (rte_atomic16_read(&relays[relay_id].valid) == 1) {
            ds_put_format(reply, "relay id: %u\nVM: %s port id %u\n"
                    "VF: %s port id %u\n\n",
                    relay_id,
                    relays[relay_id].vm_socket,
                    relays[relay_id].port_id_vm,
                    relays[relay_id].vf_pci,
                    relays[relay_id].port_id_vf );
        }
    }
}

static void
netdev_rte_offloads_cmd(struct unixctl_conn *conn,
                        int argc,
                        const char *argv[],
                        void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    uint32_t max_queues = 0;
    uint32_t i;

    for (i = 0; i < argc; i++) {
        ds_put_cstr(&reply, argv[i]);
        ds_put_cstr(&reply, " ");
    }
    ds_put_cstr(&reply, "\n");

    if (strcmp(argv[0], "hw-offload/set-forwarder") == 0) {
        max_queues = atoi(argv[3]);
        if (netdev_rte_offloads_add_relay(argv[1], argv[2], argv[4], max_queues) != 0) {
            VLOG_ERR("netdev_rte_offloads_add_relay failed\n");
        }
    } else if (strcmp(argv[0], "hw-offload/remove-forwarder") == 0) {
        if (netdev_rte_offloads_remove_relay(argv[1], false) != 0) {
            VLOG_ERR("netdev_rte_offloads_remove_relay failed\n");
        }
    } else if (strcmp(argv[0], "hw-offload/show-stats") == 0) {
        if ((strcmp(argv[1],"vm") == 0) || (strcmp(argv[1],"VM") == 0)) {
            netdev_rte_offloads_show_statistics_vm(&reply);
        }else if ((strcmp(argv[1],"queue") == 0) || (strcmp(argv[1],"QUEUE") == 0) ||
                (strcmp(argv[1],"Queue") == 0)) {
            netdev_rte_offloads_show_statistics_queue(&reply);
        } else {
            ds_put_cstr(&reply, "No such option for show-stats\n");
        }
    } else if (strcmp(argv[0], "hw-offload/show") == 0) {
        netdev_rte_offloads_show_relays(&reply);
    }

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

void
netdev_rte_offloads_init(void)
{
    static int initialized = 0;

    if ( initialized) {
        return;
    }
    relays = rte_zmalloc(NULL, sizeof(*relays)*NETDEV_RTE_OFFLOADS_MAX_RELAYS, RTE_CACHE_LINE_SIZE);

    unixctl_command_register("hw-offload/set-forwarder",
                             "[dpdk-devargs] [vhost-server-path] [vhost-queues] [representor]",
                             4, 4, netdev_rte_offloads_cmd,
                             NULL);

    unixctl_command_register("hw-offload/remove-forwarder",
                             "[vhost-server-path]",
                             1, 1, netdev_rte_offloads_cmd,
                             NULL);

    unixctl_command_register("hw-offload/show-stats",
                             "level",
                             1, 1, netdev_rte_offloads_cmd,
                             NULL);

    unixctl_command_register("hw-offload/show",
                             "",
                             0, 0, netdev_rte_offloads_cmd,
                             NULL);
    initialized = 1;
}

int
netdev_rte_offloads_hw_pr_fwd(int queue_id, int relay_id)
{
    uint32_t q;
    uint32_t fwd_rx = 0;
    for (q = 0; q < (relays[relay_id].num_queues * 2); ++q) {
        if (relays[relay_id].qpair[q].pr_queue == queue_id) {
            fwd_rx = netdev_rte_offloads_forward_traffic(&relays[relay_id].qpair[q], q);
        }
    }
    return fwd_rx;
}

void
netdev_rte_offloads_hw_pr_remove(int relay_id)
{
    if (netdev_rte_offloads_remove_relay(relays[relay_id].vm_socket, true) != 0) {
        VLOG_ERR("netdev_rte_offloads_remove_relay failed\n");
    }
}

/* Connection tracking code */
static int
netdev_dpdk_add_pattern_match_meta(struct flow_items *spec,
                                   struct flow_patterns *patterns,
                                   ovs_be32 val)
{
    spec->meta.data = RTE_BE32(val);
    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_META, &spec->meta, NULL);
    return 0;
}

#define INVALID_OUTER_ID  0Xffffffff
#define INVALID_HW_ID     0Xffffffff
#define MAX_OUTER_ID  0xffff
#define MAX_HW_TABLE (0xff00)

struct tun_ctx_outer_id_data {
    struct cmap_node node;
    uint32_t outer_id;
    ovs_be32 ip_dst;
    ovs_be32 ip_src;
    ovs_be64 tun_id;
    uint32_t tun_vport;
    int      ref_count;
};

struct tun_ctx_outer_id {
    struct cmap outer_id_to_tun_map;
    struct cmap tun_to_outer_id_map;
    struct id_pool *pool;
};

struct tun_ctx_outer_id tun_ctx_outer_id = {
    .outer_id_to_tun_map = CMAP_INITIALIZER,
    .tun_to_outer_id_map = CMAP_INITIALIZER,
};

static struct
tun_ctx_outer_id_data *netdev_dpdk_tun_data_find(uint32_t outer_id)
{
    size_t hash = hash_add(0,outer_id);
    struct tun_ctx_outer_id_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
             &tun_ctx_outer_id.outer_id_to_tun_map) {
        if (data->outer_id == outer_id) {
            return data;
        }
    }

    return NULL;
}

static void
netdev_dpdk_tun_data_del(uint32_t outer_id)
{
    size_t hash = hash_add(0,outer_id);
    struct tun_ctx_outer_id_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
            &tun_ctx_outer_id.outer_id_to_tun_map) {
        if (data->outer_id == outer_id) {
                cmap_remove(&tun_ctx_outer_id.outer_id_to_tun_map,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
                ovsrcu_postpone(free, data);
                return;
        }
    }
}

static void
netdev_dpdk_tun_data_insert(uint32_t outer_id, odp_port_t tun_vport,
                            ovs_be32 ip_dst,
                            ovs_be32 ip_src,
                            ovs_be64 tun_id)
{
    size_t hash = hash_add(0,outer_id);
    struct tun_ctx_outer_id_data *data = xzalloc(sizeof *data);

    data->outer_id = outer_id;
    data->tun_vport = tun_vport;
    data->ip_dst = ip_dst;
    data->ip_src = ip_src;
    data->tun_id = tun_id;

    cmap_insert(&tun_ctx_outer_id.outer_id_to_tun_map,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

static inline uint32_t netdev_dpdk_tun_hash(ovs_be32 ip_dst, ovs_be32 ip_src,
                              ovs_be64 tun_id)
{
    uint32_t hash = 0;
    hash = hash_add(hash,ip_dst);
    hash = hash_add(hash,ip_src);
    hash = hash_add64(hash,tun_id);
    return hash;
}

static uint32_t
netdev_dpdk_tun_outer_id_get_ref(odp_port_t tun_vport,
                                 ovs_be32 ip_dst, ovs_be32 ip_src,
                              ovs_be64 tun_id)
{
    struct tun_ctx_outer_id_data *data;
    uint32_t hash = netdev_dpdk_tun_hash(ip_dst, ip_src, tun_id);

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                    &tun_ctx_outer_id.tun_to_outer_id_map) {
        if (data->tun_id == tun_id && 
            data->ip_dst == ip_dst &&
            data->ip_src == ip_src &&
            data->tun_vport == tun_vport) {
            data->ref_count++;
            return data->outer_id;
        }
    }

    return INVALID_OUTER_ID;
}

static uint32_t
netdev_dpdk_tun_outer_id_alloc(odp_port_t tun_vport,
                               ovs_be32 ip_dst, ovs_be32 ip_src,
                               ovs_be64 tun_id)
{
    struct tun_ctx_outer_id_data *data;
    uint32_t outer_id;
    uint32_t hash = 0;

    if (!tun_ctx_outer_id.pool) {
        tun_ctx_outer_id.pool = id_pool_create(1, MAX_OUTER_ID);
    }

    if (!id_pool_alloc_id(tun_ctx_outer_id.pool, &outer_id)) {
        return INVALID_OUTER_ID;
    }

    hash = netdev_dpdk_tun_hash(ip_dst, ip_src, tun_id);

    data = xzalloc(sizeof *data);
    data->tun_vport = tun_vport;
    data->ip_dst = ip_dst;
    data->ip_src = ip_src;
    data->tun_id = tun_id;
    data->outer_id = outer_id;
    data->ref_count  = 1;

    cmap_insert(&tun_ctx_outer_id.tun_to_outer_id_map,
                CONST_CAST(struct cmap_node *, &data->node), hash);

    netdev_dpdk_tun_data_insert(outer_id, tun_vport, ip_dst,ip_src, tun_id);

    return outer_id;
}

static void
netdev_dpdk_tun_outer_id_unref(ovs_be32 ip_dst, ovs_be32 ip_src,
                                       ovs_be64 tun_id)
{
    struct tun_ctx_outer_id_data *data;
    uint32_t hash = netdev_dpdk_tun_hash(ip_dst, ip_src, tun_id);

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                    &tun_ctx_outer_id.tun_to_outer_id_map) {
        if (data->tun_id == tun_id && data->ip_dst == ip_dst
                        && data->ip_src == ip_src) {
            data->ref_count--;
            if (data->ref_count == 0) {
                netdev_dpdk_tun_data_del(data->outer_id);
                cmap_remove(&tun_ctx_outer_id.tun_to_outer_id_map,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
                id_pool_free_id(tun_ctx_outer_id.pool, data->outer_id);
                ovsrcu_postpone(free, data);
            }
            return;
        }
    }
}

/* A tunnel meta data has 3 tuple. src ip, dst ip and tun.
 * We need to replace each 3-tuple with an id.
 * If we have already allocated outer_id for the tun we just inc the refcnt.
 * If no such tun exits we allocate a new outer id and set refcnt to 1.
 * every offloaded flow that has tun on match should use outer_id
 */
static uint32_t
netdev_dpdk_tun_id_get_ref(odp_port_t tun_vport,
                           ovs_be32 ip_dst, ovs_be32 ip_src,
                           ovs_be64 tun_id)
{
    uint32_t outer_id = netdev_dpdk_tun_outer_id_get_ref(tun_vport, ip_dst,
                                                         ip_src, tun_id);
    if (outer_id == INVALID_OUTER_ID) {
        return netdev_dpdk_tun_outer_id_alloc(tun_vport, ip_dst,
                                              ip_src, tun_id);
    }
    return outer_id;
}

static void
netdev_dpdk_outer_id_unref(uint32_t outer_id)
{
    struct tun_ctx_outer_id_data *data = netdev_dpdk_tun_data_find(outer_id);
    if (data) {
        netdev_dpdk_tun_outer_id_unref(data->ip_dst, data->ip_src,
                                       data->tun_id);
    }
}

static int
netdev_rte_vxlan_restore(uint32_t outer_id, struct dp_packet *packet)
{
    struct tun_ctx_outer_id_data *data = netdev_dpdk_tun_data_find(outer_id);
    if (!data) {
        return -1;
    }
    /* Override odp_port with vport number */
    packet->md.in_port.odp_port = data->tun_vport;
    memset(&packet->md.tunnel, 0, sizeof packet->md.tunnel);
    packet->md.tunnel.ip_dst = data->ip_dst;
    packet->md.tunnel.ip_src = data->ip_src;
    packet->md.tunnel.tun_id = data->tun_id;
    /*
     * The following tunnel information is not used for matching metadata.
     * struct in6_addr ipv6_dst;
     * struct in6_addr ipv6_src;
     * uint16_t flags;
     * uint8_t ip_tos;
     * uint8_t ip_ttl;
     * uint16_t tp_dst;
     * uint16_t tp_src;
     * ovs_be16 gbp_id;
     * uint8_t  gbp_flags;
     * uint8_t erspan_ver;
     * uint32_t erspan_idx;
     * uint8_t erspan_dir;
     * uint8_t erspan_hwid;
     */

    return 0;
}

enum ct_offload_dir {
    CT_OFFLOAD_DIR_INIT = 0,
    CT_OFFLOAD_DIR_REP = 1,
    CT_OFFLOAD_NUM = 2
};

/* TODO - make sure each of the below 4 preprocesses is fully implemented */
enum mark_preprocess_type {
    MARK_PREPROCESS_CT = 1 << 0,
    MARK_PREPROCESS_FLOW_WITH_CT = 1 << 1,
    MARK_PREPROCESS_FLOW = 1 << 2,
    MARK_PREPROCESS_VXLAN = 1 << 3
};

/*
 * A mapping from ufid to to CT rte_flow.
 */
static struct cmap mark_to_miss_ctx = CMAP_INITIALIZER;

#define INVALID_IN_PORT 0xffff

struct mark_to_miss_ctx_data {
    struct cmap_node node;
    uint32_t mark;
    int type;
    union {
        struct {
            uint32_t ct_mark;
            uint16_t ct_zone;
            struct ct_flow_offload_item *ct_offload[CT_OFFLOAD_NUM];
            uint32_t outer_id[CT_OFFLOAD_NUM];
            uint16_t odp_port[CT_OFFLOAD_NUM];
            bool rteflow[CT_OFFLOAD_NUM];
         } ct;
        struct {
            uint16_t outer_id;
            uint32_t hw_id;
            uint32_t recirc_id;
            bool     is_port;
            uint32_t in_port;
        } flow;
    };
};

static void
build_ctid(uint32_t mark, int dir, bool nat, ovs_u128 *ctid)
{
    /* Use the mark, direction and nat option as connection identifiers */
    memset(ctid, 0, sizeof *ctid);
    ctid->u32[0] = mark;
    ctid->u32[1] = dir;
    ctid->u32[2] = nat;
}

static inline void
netdev_dpdk_release_ct_flow(struct mark_to_miss_ctx_data *data,
                            enum ct_offload_dir dir)
{
    ovs_u128 ctid;

    if (data->ct.ct_offload[dir]) {
        build_ctid(data->mark, dir, false, &ctid);
        netdev_rte_ct_flow_del(NULL, &ctid, NULL);
        if (data->ct.ct_offload[dir]) {
            if (data->ct.ct_offload[dir]->mod_flags) {
                build_ctid(data->mark, dir, true, &ctid);
                netdev_rte_ct_flow_del(NULL, &ctid, NULL);
            }
            free(data->ct.ct_offload[dir]);
            data->ct.ct_offload[dir] = NULL;
        }
    }
    data->ct.odp_port[dir] = INVALID_IN_PORT;
    if (data->ct.outer_id[dir] != INVALID_OUTER_ID) {
        netdev_dpdk_outer_id_unref(data->ct.outer_id[dir]);
        data->ct.outer_id[dir] = INVALID_OUTER_ID;
    }
}

static bool
netdev_dpdk_find_miss_ctx(uint32_t mark, struct mark_to_miss_ctx_data **ctx)
{
    size_t hash = hash_add(0,mark);
    struct mark_to_miss_ctx_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
            &mark_to_miss_ctx) {
        if (data->mark == mark) {
            *ctx = data;
            return true;
        }
    }

    return false;
}

static struct mark_to_miss_ctx_data *
netdev_dpdk_get_flow_miss_ctx(uint32_t mark, bool create)
{
    struct mark_to_miss_ctx_data * data = NULL;

    if (!netdev_dpdk_find_miss_ctx(mark, &data) && create) {
        size_t hash = hash_add(0,mark);
        data = xzalloc(sizeof *data);
        data->mark = mark;
        data->ct.outer_id[CT_OFFLOAD_DIR_REP] = INVALID_OUTER_ID;
        data->ct.outer_id[CT_OFFLOAD_DIR_INIT] = INVALID_OUTER_ID;
        data->ct.odp_port[CT_OFFLOAD_DIR_REP] = INVALID_IN_PORT;
        data->ct.odp_port[CT_OFFLOAD_DIR_INIT] = INVALID_IN_PORT;
        cmap_insert(&mark_to_miss_ctx,
                CONST_CAST(struct cmap_node *, &data->node), hash);
    }

   return data;
}

static int
netdev_dpdk_save_flow_miss_ctx(uint32_t mark, uint32_t hw_id, uint32_t recirc_id,
                               uint32_t outer_id, uint32_t in_port,
                               int miss_type)
{
    struct mark_to_miss_ctx_data *data = netdev_dpdk_get_flow_miss_ctx(mark, true);
    if (!data) {
        return -1;
    }

    data->type = miss_type;
    data->mark = mark;
    data->flow.outer_id = outer_id;
    data->flow.hw_id = hw_id;
    data->flow.recirc_id = recirc_id;
    data->flow.is_port = !recirc_id;
    data->flow.in_port = in_port;
    return 0;
}

static void
netdev_dpdk_del_miss_ctx(uint32_t mark)
{
    size_t hash = hash_add(0,mark);
    struct mark_to_miss_ctx_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                      &mark_to_miss_ctx) {
        if (data->mark == mark) {
                cmap_remove(&mark_to_miss_ctx,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
                ovsrcu_postpone(free, data);
                return;
        }
    }
}

static inline void
netdev_dpdk_tun_recover_meta_data(struct dp_packet *p, uint32_t outer_id)
{
    struct tun_ctx_outer_id_data *data = netdev_dpdk_tun_data_find(outer_id);
    memset(&p->md.tunnel, 0, sizeof p->md.tunnel);
    if (data) {
        p->md.tunnel.ip_dst = data->ip_dst;
        p->md.tunnel.ip_src = data->ip_src;
        p->md.tunnel.tun_id = data->tun_id;
        p->md.in_port.odp_port = data->tun_vport;
    }
}

struct hw_table_id_node {
    struct cmap_node node;
    uint32_t id;
    int      hw_id;
    int      is_port;
    int      ref_cnt;
};

struct hw_table_id {
    /* struct cmap recirc_id_to_tbl_id_map; */
    /* struct cmap port_id_to_tbl_id_map; */
    struct id_pool *pool;
    uint32_t hw_id_to_sw[MAX_OUTER_ID];
};

static struct cmap recirc_id_to_tbl_id_map = CMAP_INITIALIZER;
static struct cmap port_id_to_tbl_id_map = CMAP_INITIALIZER;
static struct hw_table_id hw_table_id = {
    .pool = NULL,
};

static int
netdev_dpdk_get_id_from_hw_id(uint32_t hw_id, bool is_port, uint32_t *id)
{
    struct hw_table_id_node *data = NULL;
    struct cmap *smap = is_port ? &port_id_to_tbl_id_map:
                                  &recirc_id_to_tbl_id_map;

    CMAP_FOR_EACH (data, node, smap) {
    /* TODO: create a cmap of hwid to id for faster search */
        if (data->hw_id == hw_id && data->is_port == is_port) {
            *id = data->id;
            return 0;
        }
    }

    return -1;
}

static int
netdev_dpdk_get_hw_id(uint32_t id, uint32_t *hw_id, bool is_port, bool peek)
{
    size_t hash = hash_bytes(&id, sizeof id, 0);
    struct hw_table_id_node *data = NULL;
    struct cmap *smap = is_port ? &port_id_to_tbl_id_map:
                                  &recirc_id_to_tbl_id_map;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, smap) {
        if (data->id == id && data->is_port == is_port) {
            *hw_id = data->hw_id;
            if (!peek) {
                data->ref_cnt++;
            }
            return 0;
        }
    }

    return -1;
}

static void
netdev_dpdk_put_hw_id(uint32_t id, bool is_port)
{
    size_t hash = hash_bytes(&id, sizeof id, 0);
    struct hw_table_id_node *data;
    struct cmap *smap = is_port? &port_id_to_tbl_id_map:
                                 &recirc_id_to_tbl_id_map;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, smap) {
        if (data->id == id && data->is_port == is_port) {
            data->ref_cnt--;
            if (data->ref_cnt <= 0) {
                /*TODO: delete table (if recirc_id). DONE -- implicitly */
                /*TODO: update mapping table. - DONE -- during flow_put and flow_del */
                /* Both tables should be updated under flow_del() */
                id_pool_free_id(hw_table_id.pool, data->hw_id);
                cmap_remove(smap,
                            CONST_CAST(struct cmap_node *, &data->node), hash);
                ovsrcu_postpone(free, data);
            }
            return;
        }
    }
}

static uint32_t
netdev_dpdk_alloc_hw_id(uint32_t id, bool is_port, bool peek)
{
    size_t hash = hash_bytes(&id, sizeof id, 0);
    uint32_t hw_id;
    struct cmap *smap = is_port? &port_id_to_tbl_id_map:
                               &recirc_id_to_tbl_id_map;
    struct hw_table_id_node *data;

    if (!id_pool_alloc_id(hw_table_id.pool, &hw_id)) {
        return INVALID_HW_ID;
    }

    data = xzalloc(sizeof *data);
    data->hw_id = hw_id;
    data->is_port = is_port;
    data->id = id;
    data->ref_cnt = peek ? 0 : 1;

    cmap_insert(smap, CONST_CAST(struct cmap_node *, &data->node), hash);

    /*  create HW table with the id. update mapping table */
   /*TODO: create new table in HW with that id (if not port).*/
   /*TODO: fill mapping table with the new information.*/
   /* Both tables should be filled in during flow_put() */


    return hw_id;
}

static inline void
netdev_dpdk_hw_id_init(void)
{
     if (!hw_table_id.pool) {
        /*TODO: set it default, also make sure we don't overflow - see below */
        /* we don't overflow by this check:
         * if (!id_pool_alloc_id(hw_table_id.pool, &hw_id)) 
         */
        hw_table_id.pool = id_pool_create(TABLE_ID_LAST, MAX_HW_TABLE);
        memset(hw_table_id.hw_id_to_sw, 0, sizeof hw_table_id.hw_id_to_sw);
    }
}

static int
netdev_dpdk_recirc_port_to_hw_id(uint32_t id, uint32_t *hw_id,
                                 bool is_port, bool peek)
{
    int ret = 0;

    netdev_dpdk_hw_id_init();
    ret = netdev_dpdk_get_hw_id(id, hw_id, is_port, peek);
    if (ret) {
        *hw_id = netdev_dpdk_alloc_hw_id(id, is_port, peek);
    }
    return 0;
}

static int
netdev_dpdk_get_recirc_hw_id(uint32_t recirc_id, uint32_t *hw_id)
{
    return netdev_dpdk_recirc_port_to_hw_id(recirc_id, hw_id, false, false);
}

static int
netdev_dpdk_peek_recirc_hw_id(uint32_t recirc_id, uint32_t *hw_id)
{
    return netdev_dpdk_recirc_port_to_hw_id(recirc_id, hw_id, false, true);
}

static int
netdev_dpdk_get_port_hw_id(uint32_t port_id, uint32_t *hw_id)
{
    return netdev_dpdk_recirc_port_to_hw_id(port_id, hw_id, true, false);
}

static int
netdev_dpdk_peek_port_hw_id(uint32_t port_id, uint32_t *hw_id)
{
    return netdev_dpdk_recirc_port_to_hw_id(port_id, hw_id, true, true);
}

static void
netdev_dpdk_put_recirc_id_hw_id(uint32_t recirc_id)
{
    netdev_dpdk_put_hw_id(recirc_id, false);
}
static void
netdev_dpdk_put_port_id_hw_id(uint32_t port_id)
{
    netdev_dpdk_put_hw_id(port_id, true);
}

enum {
  MATCH_OFFLOAD_TYPE_UNDEFINED    =  0,
  MATCH_OFFLOAD_TYPE_ROOT         =  1 << 0,
  MATCH_OFFLOAD_TYPE_VPORT_ROOT   =  1 << 1,
  MATCH_OFFLOAD_TYPE_RECIRC       =  1 << 2,
  ACTION_OFFLOAD_TYPE_TNL_POP     =  1 << 3,
  ACTION_OFFLOAD_TYPE_CT          =  1 << 4,
  ACTION_OFFLOAD_TYPE_OUTPUT      =  1 << 5,
  ACTION_OFFLOAD_TYPE_TNL_PUSH    =  1 << 6,
  ACTION_OFFLOAD_TYPE_DROP        =  1 << 7,
};

struct offload_item_cls_info {
    struct {
        uint32_t recirc_id;
        ovs_be32 ip_dst;
        ovs_be32 ip_src;
        ovs_be64 tun_id;
        int type;
        bool vport;
        uint32_t outer_id;
        uint32_t hw_id;
    } match;

    struct {
        bool has_ct;
        bool has_nat;
        uint16_t zone;
        uint32_t recirc_id;
        uint32_t hw_id;
        uint32_t odp_port;
        bool valid;
        int type;
        bool pop_tnl;
        const struct ovs_action_push_tnl *push_tnl;
        const struct nlattr *set_actions;
        size_t set_actions_len;
    } actions;
};

static void
netdev_dpdk_offload_fill_cls_info(struct netdev_rte_port *rte_port,
                             struct offload_item_cls_info *cls_info,
                             struct match *match, struct nlattr *actions,
                             size_t actions_len)

{
    unsigned int left;
    const struct nlattr *a;
    struct match match_zero_wc;

    cls_info->actions.valid = true;

    /*TODO: find if in_port is vport or not. (DONE)*/
    cls_info->match.vport = (rte_port->rte_port_type == RTE_PORT_TYPE_VXLAN);

    /* Create a wc-zeroed version of flow. */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    /* if we have recirc_id in match */
    if (match_zero_wc.flow.recirc_id) {
        cls_info->match.recirc_id = match->flow.recirc_id;
    }

    if (!is_all_zeros(&match_zero_wc.flow.tunnel,
                      sizeof match_zero_wc.flow.tunnel)) {
        cls_info->match.ip_dst = match->flow.tunnel.ip_dst;
        cls_info->match.ip_src = match->flow.tunnel.ip_src;
        cls_info->match.tun_id = match->flow.tunnel.tun_id;
    }

    NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
        int type = nl_attr_type(a);
        bool last_action = (left <= NLA_ALIGN(a->nla_len));

        switch ((enum ovs_action_attr) type) {
            case OVS_ACTION_ATTR_CT: {
                unsigned int left_ct;
                const struct nlattr *b;
                cls_info->actions.has_ct = true;

                NL_ATTR_FOR_EACH_UNSAFE (b, left_ct, nl_attr_get(a),
                                 nl_attr_get_size(a)) {
                    enum ovs_ct_attr sub_type = nl_attr_type(b);

                    switch (sub_type) {
                            case OVS_CT_ATTR_NAT:
                                cls_info->actions.has_nat = true;
                                break;
                            case OVS_CT_ATTR_FORCE_COMMIT:
                                break;
                            case OVS_CT_ATTR_COMMIT:
                                break;
                            case OVS_CT_ATTR_ZONE:
                                cls_info->actions.zone = nl_attr_get_u16(b);
                                break;
                            case OVS_CT_ATTR_HELPER:
                            case OVS_CT_ATTR_MARK:
                            case OVS_CT_ATTR_LABELS:
                            case OVS_CT_ATTR_EVENTMASK:
                            case OVS_CT_ATTR_UNSPEC:
                            case __OVS_CT_ATTR_MAX:
                            default:
                                break;
                       }
                    }
                }
                break;
            case OVS_ACTION_ATTR_OUTPUT:
                cls_info->actions.odp_port = nl_attr_get_odp_port(a);
                if (!last_action) {
                    cls_info->actions.valid = false;
                }
                break;
            case OVS_ACTION_ATTR_RECIRC:
                    cls_info->actions.recirc_id = nl_attr_get_u32(a);
                if (!last_action) {
                    cls_info->actions.valid = false;
                }
                break;

                case OVS_ACTION_ATTR_PUSH_VLAN:
                /*TODO: need it*/
                    break;
                case OVS_ACTION_ATTR_POP_VLAN:     /* No argument. */
                /*TODO: need it*/
                    break;
                case OVS_ACTION_ATTR_TUNNEL_POP:    /* u32 port number. */
                    cls_info->actions.pop_tnl = true;
                    cls_info->actions.odp_port = nl_attr_get_odp_port(a);
                    break;
                case OVS_ACTION_ATTR_SET:
                case OVS_ACTION_ATTR_SET_MASKED:
                    cls_info->actions.set_actions = nl_attr_get(a);
                    cls_info->actions.set_actions_len = nl_attr_get_size(a);
                    break;
                /*TODO: verify if tnl_pop or tnl_push, (DONE)*/
                case OVS_ACTION_ATTR_CLONE:{
                    const struct nlattr *clone_actions =
                                               nl_attr_get(a);
                    size_t clone_actions_len = nl_attr_get_size(a);
                    const struct nlattr *ca;
                    unsigned int cleft;

                    NL_ATTR_FOR_EACH_UNSAFE (ca, cleft, clone_actions, clone_actions_len) {
                        int clone_type = nl_attr_type(ca);
                        if (clone_type == OVS_ACTION_ATTR_TUNNEL_PUSH) {
                            cls_info->actions.push_tnl = nl_attr_get(ca);
                        } else if (clone_type == OVS_ACTION_ATTR_OUTPUT) {
                            cls_info->actions.odp_port = nl_attr_get_odp_port(ca);
                        } else {
                            cls_info->actions.valid = false;
                            break;
                        }
                    }
                }
                break;
                case OVS_ACTION_ATTR_HASH:
                case OVS_ACTION_ATTR_UNSPEC:
                case OVS_ACTION_ATTR_USERSPACE:
                case OVS_ACTION_ATTR_SAMPLE:
                case OVS_ACTION_ATTR_PUSH_MPLS:
                case OVS_ACTION_ATTR_POP_MPLS:
                case OVS_ACTION_ATTR_TRUNC:
                case OVS_ACTION_ATTR_PUSH_ETH:
                case OVS_ACTION_ATTR_POP_ETH:
                case OVS_ACTION_ATTR_CT_CLEAR:
                case OVS_ACTION_ATTR_PUSH_NSH:
                case OVS_ACTION_ATTR_POP_NSH:
                case OVS_ACTION_ATTR_METER:
                case OVS_ACTION_ATTR_CHECK_PKT_LEN:
                case OVS_ACTION_ATTR_TUNNEL_PUSH:
                    /*TODO: replace with counter. so log won't be flooded */
                    VLOG_WARN("unsupported offload action %d",type);
                    cls_info->actions.valid = false;
                    break;
                case __OVS_ACTION_ATTR_MAX:
                default:
                    VLOG_ERR("action %d",type);
        }
    }

}


static int
netdev_dpdk_offload_classify(struct netdev_rte_port *rte_port,
                             struct offload_item_cls_info *cls_info,
                             struct match *match, struct nlattr *actions,
                             size_t actions_len)

{
    int ret = 0;

    netdev_dpdk_offload_fill_cls_info(rte_port, cls_info, match, actions, actions_len);

    /* some scenario we cannot support */
    if (!cls_info->actions.valid) {
        return -1;
    }

    if (cls_info->match.recirc_id == 0) {
        if (cls_info->match.vport) {
            cls_info->match.type = MATCH_OFFLOAD_TYPE_VPORT_ROOT;
            /*todo: NEED TO VALIDATE THIS IS VXLAN PORT OR ELSE */
            /*OFFLOAD IS NOT VALID */
        } else {
            cls_info->match.type = MATCH_OFFLOAD_TYPE_ROOT;
        }
    } else {
            cls_info->match.type = MATCH_OFFLOAD_TYPE_RECIRC;
    }

    if (cls_info->actions.pop_tnl) {
        cls_info->actions.type = ACTION_OFFLOAD_TYPE_TNL_POP;
        /*TODO: validate tnl pop type (VXLAN/GRE....) is supported and we*/
    } else if (cls_info->actions.has_ct) {
        cls_info->actions.type = ACTION_OFFLOAD_TYPE_CT;
    } else if (cls_info->actions.push_tnl) {
        cls_info->actions.type = ACTION_OFFLOAD_TYPE_TNL_PUSH;
    } else if (cls_info->actions.odp_port) {
        cls_info->actions.type = ACTION_OFFLOAD_TYPE_OUTPUT;
    }
    return ret;
}

static int
netdev_dpdk_offload_add_root_patterns(struct flow_data *fdata,
                                     struct flow_patterns *patterns,
                                     struct match *match)
{
    int result;
    /*TODO: here we should add all eth/ip/....etc patterns (DONE)*/
    result = add_flow_patterns(patterns, &fdata->spec, &fdata->mask, match);
    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
    return result;
}

static int
netdev_dpdk_offload_add_vport_root_patterns(struct flow_data *fdata,
                             struct flow_patterns *patterns,
                             struct match *match,
                             struct offload_item_cls_info *cls_info)
{
    struct tun_ctx_outer_id_data *data;

    cls_info->match.outer_id = netdev_dpdk_tun_id_get_ref(
                                       match->flow.in_port.odp_port,
                                       cls_info->match.ip_dst,
                                       cls_info->match.ip_src,
                                       cls_info->match.tun_id);

    if (cls_info->match.outer_id == INVALID_OUTER_ID) {
        return -1;
    }

    if (add_vport_vxlan_flow_patterns(patterns, &fdata->spec_outer,
                                        &fdata->mask_outer, match)) {
        return -1;
    }

    /* save the vport ID of the tunnel */
    data = netdev_dpdk_tun_data_find(cls_info->match.outer_id);
    data->tun_vport = match->flow.in_port.odp_port;


    if (add_flow_patterns(patterns, &fdata->spec, &fdata->mask, match)) {
        return -1;
    }

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);
    /*TODO: here we add all TUN info (match->flow.tnl....) (DONE)*/
    /*TODO: we then call the regular root to add the rest (DONE)*/
    return 0;
}

static int
netdev_dpdk_offload_add_recirc_patterns(struct flow_data *fdata,
                             struct flow_patterns *patterns,
                             struct match *match,
                             struct offload_item_cls_info *cls_info)
{
    /* find available hw_id for recirc_id */
    if (netdev_dpdk_get_recirc_hw_id(cls_info->match.recirc_id,
                                     &cls_info->match.hw_id) ==
                                     INVALID_HW_ID) {
        return -1;
    }

    if (cls_info->match.tun_id) {
        /* if we should match tun id */
        cls_info->match.outer_id = netdev_dpdk_tun_id_get_ref(
                                       match->flow.in_port.odp_port,
                                       cls_info->match.ip_dst,
                                       cls_info->match.ip_src,
                                       cls_info->match.tun_id);
        if (cls_info->match.outer_id == INVALID_OUTER_ID) {
            return -1;
        }
        netdev_dpdk_add_pattern_match_reg(&fdata->spec, &fdata->mask, patterns,
                                          TAG_FIELD_OUTER_ID,
                                          cls_info->match.outer_id,
                                          0xFFFFFFFF);
    }

    /* TODO: here we add match on outer_id -- DONE */
    netdev_dpdk_offload_add_root_patterns(fdata, patterns, match);

    return 0;
}

static int
netdev_dpdk_offload_tnl_push(struct flow_data *fdata,
                             struct flow_actions *flow_actions,
                             struct offload_item_cls_info *cls_info)
{
    /* TODO: encap (Done) */
    fdata->actions.clone_raw_encap.data =
                             (uint8_t *)cls_info->actions.push_tnl->header;
    fdata->actions.clone_raw_encap.preserve = NULL;
    fdata->actions.clone_raw_encap.size =
                                       cls_info->actions.push_tnl->header_len;
    add_flow_action(flow_actions, RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
                                            &fdata->actions.clone_raw_encap);

    /* TODO: count (Done) */
    netdev_rte_add_count_flow_action(&fdata->actions.count, flow_actions);

    /* TODO: OUTPUT (Done) */
    return add_jump_to_port_id_action(cls_info->actions.odp_port,
                flow_actions,
                &fdata->actions.output);
}

static int
netdev_dpdk_offload_vxlan_actions(struct netdev_rte_port *rte_port,
                                  struct flow_data *fdata,
                                  struct flow_actions *flow_actions,
                                  struct offload_item_cls_info *cls_info)
{
    /*TODO: getv xlan portt id, create table for the port.(DONE)*/
    /*TODO: add counter on flow  (DONE)*/
    netdev_rte_add_count_flow_action(&fdata->actions.count, flow_actions);
    /*TODO: add jump to vport table. (DONE) */
    return netdev_rte_add_jump_to_vport_flow_action(rte_port, fdata,
                                cls_info->actions.odp_port,
                                flow_actions);

}

static inline int
netdev_dpdk_offload_get_hw_id(struct offload_item_cls_info *cls_info)
{
    int ret =0;
    if (cls_info->actions.recirc_id) {
        if (netdev_dpdk_peek_recirc_hw_id(cls_info->actions.recirc_id,
                                          &cls_info->actions.hw_id) ==
                                          INVALID_HW_ID) {
            ret = -1;
        }
    } else {
        if (netdev_dpdk_peek_port_hw_id(cls_info->actions.odp_port,
                                        &cls_info->actions.hw_id) ==
                                        INVALID_HW_ID) {
            ret = -1;
        }
    }
    return ret;
}

#define get_mask(a, type) ((const type *)(const void *)(a + 1) + 1)
static int
netdev_rte_offloads_add_set_actions(struct flow_data *fdata,
                                    struct flow_actions *flow_actions,
                                    struct offload_item_cls_info *cls_info)
{
    const struct nlattr *sa;
    unsigned int sleft;
    int ret = 0;

    NL_ATTR_FOR_EACH_UNSAFE(sa, sleft, cls_info->actions.set_actions,
                            cls_info->actions.set_actions_len) {
        int set_type = nl_attr_type(sa);

        switch ((enum ovs_key_attr) set_type) {
        case OVS_KEY_ATTR_UNSPEC:
        case OVS_KEY_ATTR_ENCAP:
        case OVS_KEY_ATTR_PRIORITY:
        case OVS_KEY_ATTR_IN_PORT:
        case OVS_KEY_ATTR_VLAN:
            VLOG_DBG_RL(&error_rl,
                        "Unsupported set action. set_type=%d", set_type);
            ret = -1;
            break;
        case OVS_KEY_ATTR_ETHERNET: {
            const struct ovs_key_ethernet *key = nl_attr_get(sa);
            const struct ovs_key_ethernet *mask =
                get_mask(sa, struct ovs_key_ethernet);

            if (!mask || !eth_addr_is_zero(mask->eth_src)) {
                memcpy(fdata->actions.set.mac.src.mac_addr, key->eth_src.ea,
                       ETH_ADDR_LEN);
                add_flow_action(flow_actions, RTE_FLOW_ACTION_TYPE_SET_MAC_SRC,
                                &fdata->actions.set.mac.src);
            }
            if (!mask || !eth_addr_is_zero(mask->eth_dst)) {
                memcpy(fdata->actions.set.mac.dst.mac_addr, key->eth_dst.ea,
                       ETH_ADDR_LEN);
                add_flow_action(flow_actions, RTE_FLOW_ACTION_TYPE_SET_MAC_DST,
                                &fdata->actions.set.mac.dst);
            }
            } break;
        case OVS_KEY_ATTR_ETHERTYPE:
            VLOG_DBG_RL(&error_rl,
                        "Unsupported set action. set_type=%d", set_type);
            ret = -1;
            break;
        case OVS_KEY_ATTR_IPV4:{
            const struct ovs_key_ipv4 *key = nl_attr_get(sa);
            const struct ovs_key_ipv4 *mask =
                get_mask(sa, struct ovs_key_ipv4);
            if (!mask || !mask->ipv4_src) {
                fdata->actions.set.ipv4.src.ipv4_addr = key->ipv4_src;
                add_flow_action(flow_actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC,
                                &fdata->actions.set.ipv4.src);
            }
            if (!mask || !mask->ipv4_dst) {
                fdata->actions.set.ipv4.dst.ipv4_addr = key->ipv4_dst;
                add_flow_action(flow_actions, RTE_FLOW_ACTION_TYPE_SET_IPV4_DST,
                                &fdata->actions.set.ipv4.dst);
            }
            if (!mask || !mask->ipv4_ttl) {
                fdata->actions.set.ipv4.ttl.ttl_value = key->ipv4_ttl;
                add_flow_action(flow_actions, RTE_FLOW_ACTION_TYPE_SET_TTL,
                                &fdata->actions.set.ipv4.ttl);
            }
            if (!mask || !mask->ipv4_proto || !mask->ipv4_tos ||
                !mask->ipv4_frag) {
                VLOG_DBG_RL(&error_rl, "Unsupported IPv4 set action");
                return -1;
            }
            } break;
        case OVS_KEY_ATTR_IPV6:
        case OVS_KEY_ATTR_TCP:
        case OVS_KEY_ATTR_UDP:
        case OVS_KEY_ATTR_ICMP:
        case OVS_KEY_ATTR_ICMPV6:
        case OVS_KEY_ATTR_ARP:
        case OVS_KEY_ATTR_ND:
        case OVS_KEY_ATTR_SKB_MARK:
        case OVS_KEY_ATTR_TUNNEL:
        case OVS_KEY_ATTR_SCTP:
        case OVS_KEY_ATTR_TCP_FLAGS:
        case OVS_KEY_ATTR_DP_HASH:
        case OVS_KEY_ATTR_RECIRC_ID:
        case OVS_KEY_ATTR_MPLS:
        case OVS_KEY_ATTR_CT_STATE:
        case OVS_KEY_ATTR_CT_ZONE:
        case OVS_KEY_ATTR_CT_MARK:
        case OVS_KEY_ATTR_CT_LABELS:
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4:
        case OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6:
        case OVS_KEY_ATTR_NSH:
        case OVS_KEY_ATTR_PACKET_TYPE:
        case OVS_KEY_ATTR_ND_EXTENSIONS:
        case __OVS_KEY_ATTR_MAX:
            VLOG_DBG_RL(&error_rl,
                        "Unsupported set action. set_type=%d", set_type);
            ret = -1;
            break;
        }
    }
    return ret;
}

static int
netdev_dpdk_offload_ct_actions(struct flow_data *fdata,
                               struct flow_actions *flow_actions,
                               struct offload_item_cls_info *cls_info,
                               struct nlattr *actions OVS_UNUSED,
                               size_t actions_len OVS_UNUSED,
                               uint32_t flow_mark)
{
    int ret = 0;

    if (cls_info->actions.zone) {
        if (netdev_dpdk_add_action_set_reg(&fdata->actions, flow_actions,
                                           TAG_FIELD_CT_ZONE,
                                           cls_info->actions.zone))
            return -1;
    }

    netdev_rte_add_mark_flow_action(&fdata->actions.mark, flow_mark, flow_actions);

    netdev_rte_add_count_flow_action(&fdata->actions.count, flow_actions);
    /* translate recirc_id or port_id to hw_id */
    if (netdev_dpdk_offload_get_hw_id(cls_info)) {
        return -1;
    }

    /* TODO: set hw_id in meta data, will be used by mapping table -- DONE */
    netdev_dpdk_add_action_set_reg(&fdata->actions, flow_actions,
                                   TAG_FIELD_HW_ID,
                                   cls_info->actions.hw_id);
    netdev_rte_add_meta_flow_action(&fdata->actions.meta,
                                    cls_info->actions.hw_id,
                                    flow_actions);

    /* TODO: add all actions until CT
     * read all actions for actions and add them to rte_flow
     * can push_vlan, set_eth...etc */
    if (cls_info->actions.has_nat) {
        /* TODO: we need to create the table if doesn't exists -- will be done implicitly with the first flow */
        /* TODO: jump to nat table -- DONE */
        netdev_rte_add_jump_flow_action(&fdata->actions.jump,
                                        CONNTRACK_NAT_TABLE_ID,
                                        flow_actions);
    } else {
        /*TODO: we need to create the table if doesn't exists -- will be done implicitly with the first flow */
        /*TODO: jump to CT table -- DONE */
        netdev_rte_add_jump_flow_action(&fdata->actions.jump,
                                CONNTRACK_TABLE_ID,
                                flow_actions);
    }
    return ret;
}

static int
netdev_dpdk_offload_output_actions(struct flow_data *fdata,
                                   struct flow_actions *flow_actions,
                                   struct offload_item_cls_info *cls_info,
                                   struct nlattr *actions OVS_UNUSED,
                                   size_t actions_len OVS_UNUSED)
{
    /* TODO: add counter (DONE)*/
    netdev_rte_add_count_flow_action(&fdata->actions.count, flow_actions);

    /* TODO: add all actions including output ??? */
    /* TODO: add output (DONE)*/
    return add_jump_to_port_id_action(cls_info->actions.odp_port,
                flow_actions,
                &fdata->actions.output);
}

static int
netdev_dpdk_offload_put_add_patterns(struct flow_data *fdata,
                                  struct flow_patterns *patterns,
                                  struct match *match,
                                  struct offload_item_cls_info *cls_info)
{
    switch (cls_info->match.type) {
        case MATCH_OFFLOAD_TYPE_ROOT:
            return netdev_dpdk_offload_add_root_patterns(fdata, patterns,
                                                          match);
        case MATCH_OFFLOAD_TYPE_VPORT_ROOT:
            return netdev_dpdk_offload_add_vport_root_patterns(fdata,
                                            patterns, match,cls_info);
        case MATCH_OFFLOAD_TYPE_RECIRC:
            return netdev_dpdk_offload_add_recirc_patterns(fdata, patterns,
                                                          match, cls_info);
    }

    VLOG_WARN("unexpected offload match type %d",cls_info->match.type);
    return -1;
}

static int
netdev_dpdk_offload_put_add_actions(struct netdev_rte_port *rte_port,
                                    struct flow_data *fdata,
                                    struct flow_actions *flow_actions,
                                    struct match *match OVS_UNUSED,
                                    struct nlattr *actions,
                                    size_t actions_len,
                                    struct offload_item_cls_info *cls_info,
                                    uint32_t flow_mark)
{
    int ret;

    /* match on vport recirc_id = 0, we must decap first */
    if (cls_info->match.type == MATCH_OFFLOAD_TYPE_VPORT_ROOT) {
        netdev_rte_add_decap_flow_action(flow_actions);
    }

    ret = netdev_rte_offloads_add_set_actions(fdata, flow_actions, cls_info);
    if (ret) {
        return ret;
    }

    switch (cls_info->actions.type) {
        case ACTION_OFFLOAD_TYPE_TNL_POP:
            /*TODO: need to verify the POP is the only action here. ??? */
            ret = netdev_dpdk_offload_vxlan_actions(rte_port, fdata,
                                                 flow_actions,cls_info);
            break;
        case ACTION_OFFLOAD_TYPE_CT:
            ret = netdev_dpdk_offload_ct_actions(fdata, flow_actions, cls_info,
                                                 actions, actions_len, flow_mark);
            break;
        case ACTION_OFFLOAD_TYPE_TNL_PUSH:
            ret = netdev_dpdk_offload_tnl_push(fdata, flow_actions,
                                                cls_info);
            break;
        case ACTION_OFFLOAD_TYPE_OUTPUT:
            ret = netdev_dpdk_offload_output_actions(fdata, flow_actions,
                                                    cls_info, actions,
                                                    actions_len);
            break;
        default:
            if (cls_info->actions.type) {
                VLOG_ERR("unexpected offload action type %d",cls_info->actions.type);
            } else {
                /* Currently no support for offloaded DROP action */
                VLOG_DBG("offload action type 0, namely no actions (DROP)");
            }
            ret = -1;
            break;
    }
    if (!ret)
        add_flow_action(flow_actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    return ret;
}

static struct rte_flow *
netdev_dpdk_offload_add_wa(struct netdev *netdev,
                           struct rte_flow_attr *flow_attr,
                           struct flow_patterns *patterns)
{
        struct rte_flow *flow;
        struct flow_actions jump_actions = { .actions = NULL, .cnt = 0 };
        struct rte_flow_action_jump jump = {0};

        jump.group = 1;
        add_flow_action(&jump_actions, RTE_FLOW_ACTION_TYPE_JUMP, &jump);
        add_flow_action(&jump_actions, RTE_FLOW_ACTION_TYPE_END, NULL);

        /* The flows for WA are added to group 0 */
        flow_attr->transfer = 1;
        flow_attr->group = 0;
        flow = netdev_rte_offload_flow(netdev, NULL, patterns,
                                             &jump_actions, flow_attr);
        VLOG_DBG("Flow with same matches and jump actions: "
                 "eSwitch offload was %s",
                 flow ? "succeeded" : "failed");
        free_flow_actions(&jump_actions);
        return flow;
}

static int
netdev_dpdk_offload_set_group_id(struct netdev_rte_port *rte_port,
                                 struct offload_item_cls_info *cls_info,
                                 struct rte_flow_attr *flow_attr,
                                 bool workaround_needed)
{
    enum rte_port_type port_type = rte_port->rte_port_type;
    switch (cls_info->match.type) {
        case MATCH_OFFLOAD_TYPE_ROOT:
              flow_attr->group = ROOT_TABLE_ID;
              if (!flow_attr->group && workaround_needed) {
                  flow_attr->group++;
              }
              return 0;
        case MATCH_OFFLOAD_TYPE_VPORT_ROOT:
              if (port_type == RTE_PORT_TYPE_VXLAN) {
                  flow_attr->group = VXLAN_TABLE_ID;
              } else {
                  return -1;
              }
              return 0;
        case MATCH_OFFLOAD_TYPE_RECIRC:
            flow_attr->group = cls_info->match.hw_id;
            return 0;
    }

    return -1;
}

static int
netdev_rte_update_mapping_table(struct offload_item_cls_info *cls_info,
                                struct netdev_rte_port *rte_port)
{
    bool is_add = true;
    uint32_t hwid;
    /*
     * If there was a recirc_id match (mapped to hw_id) -
     * check if need to update the MAPPING table.
     */
    hwid  = cls_info->match.hw_id;
    if (cls_info->match.type == MATCH_OFFLOAD_TYPE_RECIRC && hwid) {
        /*
         * Flow is going to be added to a recirc_id table.
         * Update MAPPING table per port.
         */
        bool is_port = false;
        if (netdev_rte_update_hwid_mapping(rte_port, 0, hwid,
                                           is_add, is_port)) {
            return -1;
        }
    }

    /*
     * If there was an OUTPUT action (mapped to hw id) -
     * check if need to update the MAPPING table.
     */
    hwid = cls_info->actions.hw_id;
    if (!cls_info->actions.recirc_id && hwid) {
        /*
         * Flow action is to output packet.
         * Update MAPPING table for this port.
         */
        bool is_port = true;
        if (netdev_rte_update_hwid_mapping(rte_port,
                                           cls_info->actions.odp_port,
                                           hwid, is_add, is_port)) {
            return -1;
        }
    }
    return 0;
}

static struct rte_flow *
netdev_dpdk_offload_put_handle(struct netdev *netdev,
                             struct netdev_rte_port *rte_port,
                             struct flow_data *fdata, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             struct offload_info *info, bool is_vport)
{
    struct offload_item_cls_info cls_info;
    memset(&cls_info, 0, sizeof cls_info);
    int ret = 0;
    struct rte_flow *flow;

    struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0,
        .transfer = 1
    };


    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions  flow_actions = { .actions = NULL, .cnt = 0 };
    bool workaround_needed;

    if (netdev_dpdk_offload_classify(rte_port, &cls_info, match,
                                       actions, actions_len)) {
        goto roll_back;
    }

    if (netdev_dpdk_offload_put_add_patterns(fdata, &patterns, match,
                                              &cls_info)) {
        goto roll_back;
    }

    if (netdev_dpdk_offload_put_add_actions(rte_port, fdata, &flow_actions,
                                    match, actions, actions_len, &cls_info,
                                    info->flow_mark)) {
        goto roll_back;
    }

    workaround_needed = !is_vport &&
        (cls_info.actions.type == ACTION_OFFLOAD_TYPE_TNL_PUSH ||
         cls_info.actions.type == ACTION_OFFLOAD_TYPE_OUTPUT) &&
         cls_info.match.type != MATCH_OFFLOAD_TYPE_RECIRC;
    if(netdev_dpdk_offload_set_group_id(rte_port, &cls_info, &flow_attr, workaround_needed)) {
        goto roll_back;
    }

    int miss_type;
    switch (cls_info.actions.type) {
    case ACTION_OFFLOAD_TYPE_CT:
        miss_type = MARK_PREPROCESS_FLOW_WITH_CT;
        break;
    case ACTION_OFFLOAD_TYPE_OUTPUT:
    case ACTION_OFFLOAD_TYPE_TNL_PUSH:
        miss_type = MARK_PREPROCESS_FLOW;
        break;
    case ACTION_OFFLOAD_TYPE_TNL_POP:
        miss_type = MARK_PREPROCESS_VXLAN;
        break;
    default:
        VLOG_ERR("Illegal classified action type %d", cls_info.actions.type);
        goto roll_back;
        break;
    }
    /* Save flow related meta data with mark as key */
    if (netdev_dpdk_save_flow_miss_ctx(info->flow_mark,
                                       cls_info.actions.hw_id,
                                       cls_info.actions.recirc_id,
                                       cls_info.match.outer_id,
                                       match->flow.in_port.odp_port,
                                       miss_type)) {
        goto roll_back;
    }

    /* TODO: OFFLOAD FLOW HERE -- DONE in calling API? */
    /* if fail goto roleback. */
    flow = netdev_rte_offload_flow(netdev, NULL, &patterns, &flow_actions,
                                   &flow_attr);

    if (flow) {
        ret = netdev_rte_update_mapping_table(&cls_info, rte_port);
        if (ret) {
            goto roll_back;
        }
    }

    /* failed, we try only mark rss, no actions */
rss:
    if (!flow) {
        free_flow_actions(&flow_actions);
        flow_attr.transfer = 0;
        if (cls_info.match.vport) {
            netdev_rte_add_decap_flow_action(&flow_actions);
        }
        flow = netdev_rte_offload_mark_rss(netdev, info->flow_mark, &patterns,
                                           &flow_actions, NULL, &flow_attr);
    /* CALL WA - IF FLOW IS VF WE NEED TO JUMP TO TABLE 1
     * WITH same MATCH */
    } else if (workaround_needed) {
        fdata->flow0 = netdev_dpdk_offload_add_wa(netdev, &flow_attr,
                                                  &patterns);
        if (!fdata->flow0) {
            struct rte_flow_error error;

            ret = netdev_dpdk_rte_flow_destroy(netdev, flow, &error);
            if (ret)
                VLOG_ERR_RL(&error_rl, "rte flow destroy error: %u : message :"
                            " %s\n", error.type, error.message);
            flow = NULL;
            goto rss;
        }
    }
    info->is_hwol = (flow_attr.transfer && flow) ? true : false;


    free_flow_patterns(&patterns);
    free_flow_actions(&flow_actions);
    return flow;
roll_back:
    /* release references that were allocated */
    if (cls_info.match.outer_id != INVALID_OUTER_ID) {
        netdev_dpdk_tun_outer_id_unref(cls_info.match.ip_dst,
                                       cls_info.match.ip_src,
                                       cls_info.match.tun_id);
    }

    if (cls_info.match.hw_id != INVALID_HW_ID) {
        netdev_dpdk_put_recirc_id_hw_id(cls_info.match.hw_id);
    }

    netdev_dpdk_del_miss_ctx(info->flow_mark);
    free_flow_patterns(&patterns);
    free_flow_actions(&flow_actions);
    return NULL;
}

static inline enum ct_offload_dir
netdev_dpdk_offload_ct_opposite_dir(enum ct_offload_dir dir)
{
    return dir == CT_OFFLOAD_DIR_INIT?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
}

static struct ct_flow_offload_item *
netdev_dpdk_offload_ct_dup(struct ct_flow_offload_item *ct_offload)
{
    struct ct_flow_offload_item *item = xzalloc(sizeof *item);
    if (item) {
        memcpy(item, ct_offload, sizeof *item);
    }
    return item;
}

static inline void
netdev_dpdk_reset_patterns(struct flow_patterns *patterns)
{
    free(patterns->items);
    patterns->cnt = 0;
    patterns->items = NULL;
}

static inline void
netdev_dpdk_reset_actions(struct flow_actions *actions)
{
    free(actions->actions);
    actions->cnt = 0;
    actions->actions = NULL;
}

static void
netdev_dpdk_ct_ctx_unref_outer_id(struct mark_to_miss_ctx_data *data,
                                  struct ct_flow_offload_item *ct_offload1,
                                  struct ct_flow_offload_item *ct_offload2)
{
    int dir1 = ct_offload1->reply ? CT_OFFLOAD_DIR_REP : CT_OFFLOAD_DIR_INIT;
    int dir2 = ct_offload2->reply ? CT_OFFLOAD_DIR_REP : CT_OFFLOAD_DIR_INIT;

    if (data->ct.outer_id[dir1] != INVALID_OUTER_ID) {
        VLOG_DBG("dir=%d, netdev_dpdk_tun_outer_id_unref for "
                 "dst="IP_FMT", src="IP_FMT", tun_id=%"PRIu64,
                 dir1,
                 IP_ARGS(ct_offload1->tun.ip_dst),
                 IP_ARGS(ct_offload1->tun.ip_src),
                 ct_offload1->tun.tun_id);
        netdev_dpdk_tun_outer_id_unref(ct_offload1->tun.ip_dst,
                                       ct_offload1->tun.ip_src,
                                       ct_offload1->tun.tun_id);
        data->ct.outer_id[dir1] = INVALID_OUTER_ID;
    }
    if (data->ct.outer_id[dir2] != INVALID_OUTER_ID) {
        VLOG_DBG("dir=%d, netdev_dpdk_tun_outer_id_unref for "
                 "dst="IP_FMT", src="IP_FMT", tun_id=%"PRIu64,
                 dir2,
                 IP_ARGS(ct_offload2->tun.ip_dst),
                 IP_ARGS(ct_offload2->tun.ip_src),
                 ct_offload2->tun.tun_id);
        netdev_dpdk_tun_outer_id_unref(ct_offload2->tun.ip_dst,
                                       ct_offload2->tun.ip_src,
                                       ct_offload2->tun.tun_id);
        data->ct.outer_id[dir2] = INVALID_OUTER_ID;
    }
}

static int
netdev_dpdk_ct_ctx_get_ref_outer_id(struct mark_to_miss_ctx_data *data,
                                    struct ct_flow_offload_item *ct_offload1,
                                    struct ct_flow_offload_item *ct_offload2)
{
    int dir1 = ct_offload1->reply ? CT_OFFLOAD_DIR_REP : CT_OFFLOAD_DIR_INIT;
    int dir2 = ct_offload2->reply ? CT_OFFLOAD_DIR_REP : CT_OFFLOAD_DIR_INIT;

    if (ct_offload1->tun.ip_dst) {
        data->ct.outer_id[dir1] = netdev_dpdk_tun_id_get_ref(
                                       ct_offload1->odp_port,
                                       ct_offload1->tun.ip_dst,
                                       ct_offload1->tun.ip_src,
                                       ct_offload1->tun.tun_id);
        if (data->ct.outer_id[dir1] == INVALID_OUTER_ID) {
            VLOG_ERR("dir=%d, netdev_dpdk_tun_id_get_ref failed for "
                     "dst="IP_FMT", src="IP_FMT", tun_id=%"PRIu64,
                     dir1,
                     IP_ARGS(ct_offload1->tun.ip_dst),
                     IP_ARGS(ct_offload1->tun.ip_src),
                     ct_offload1->tun.tun_id);
            goto err;
        }
    }
    if (ct_offload2->tun.ip_dst) {
        data->ct.outer_id[dir2] = netdev_dpdk_tun_id_get_ref(
                                       ct_offload2->odp_port,
                                       ct_offload2->tun.ip_dst,
                                       ct_offload2->tun.ip_src,
                                       ct_offload2->tun.tun_id);
        if (data->ct.outer_id[dir2] == INVALID_OUTER_ID) {
            VLOG_ERR("dir=%d, netdev_dpdk_tun_id_get_ref failed for "
                     "dst="IP_FMT", src="IP_FMT", tun_id=%"PRIu64,
                     dir2, IP_ARGS(ct_offload2->tun.ip_dst),
                     IP_ARGS(ct_offload2->tun.ip_src),
                     ct_offload2->tun.tun_id);
            goto err;
        }
    }
    return 0;

err:
    netdev_dpdk_ct_ctx_unref_outer_id(data, ct_offload1, ct_offload2);
    return -1;
}

static void
fill_ct_match(struct match *match, struct ct_flow_offload_item *item)
{
    memset(match, 0, sizeof *match);
    if (item->ct_ipv6) {
        /* Fill in ipv6 5-tuples */
        match->flow.dl_type = htons(ETH_TYPE_IPV6);
        match->flow.nw_proto = item->ct_match.ipv6.ipv6_proto;
        memcpy(&match->flow.ipv6_src,
               &item->ct_match.ipv6.ipv6_src,
               sizeof match->flow.ipv6_src);
        memcpy(&match->flow.ipv6_dst,
               &item->ct_match.ipv6.ipv6_dst,
               sizeof match->flow.ipv6_dst);
        memset(&match->wc.masks.ipv6_src, 0xFF, sizeof match->wc.masks.ipv6_src);
        memset(&match->wc.masks.ipv6_dst, 0xFF, sizeof match->wc.masks.ipv6_dst);
        match->flow.tp_src = item->ct_match.ipv6.src_port;
        match->flow.tp_dst = item->ct_match.ipv6.dst_port;
    } else {
        /* Fill in ipv4 5-tuples */
        match->flow.dl_type = htons(ETH_TYPE_IP);
        match->flow.nw_proto = item->ct_match.ipv4.ipv4_proto;
        match->flow.nw_src = item->ct_match.ipv4.ipv4_src;
        match->flow.nw_dst = item->ct_match.ipv4.ipv4_dst;
        match->wc.masks.nw_src = 0xFFFFFFFF;
        match->wc.masks.nw_dst = 0xFFFFFFFF;
        match->flow.tp_src = item->ct_match.ipv4.src_port;
        match->flow.tp_dst = item->ct_match.ipv4.dst_port;
    }
    match->wc.masks.dl_type = 0xFFFF;
    match->wc.masks.nw_proto = 0xFF;
    if (match->flow.nw_proto == IPPROTO_TCP) {
        match->wc.masks.tcp_flags = htons(TCP_RST | TCP_FIN);
    }
    match->wc.masks.tp_src = 0xFFFF;
    match->wc.masks.tp_dst = 0xFFFF;
    match->flow.ct_zone = item->zone;
    match->wc.masks.ct_zone = 0xFFFF;
}

/* Build 2 HW flows, one per direction and offload to relevant port.
 * (Each side of the flow will be offloded to different port id).
 * If NAT is also configured than two additional flows should be
 * configured.
 *
 * resource allocation:
 * TODO: if offload has TUN data, an outer_id should be allocated and used.
 *
 */
static int
netdev_dpdk_offload_ct_session(struct mark_to_miss_ctx_data *data,
                               struct ct_flow_offload_item *ct_offload1,
                               struct ct_flow_offload_item *ct_offload2)
{
    int ret = 0;
    int dir1 = ct_offload1->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
    int dir2 = ct_offload2->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;

    if (dir1 == dir2) {
        /* TODO: add warning */
        VLOG_ERR("got two established events on same dir");
        return -1;
    }

    if (netdev_dpdk_ct_ctx_get_ref_outer_id(data, ct_offload1, ct_offload2)) {
        return -1;
    }

    struct netdev_rte_port *rte_port;
    struct match match;
    ovs_u128 ctid;

    rte_port = netdev_rte_port_search(ct_offload1->odp_port, &port_map);
    if (!rte_port) {
        VLOG_DBG("dir=INIT, port %d has no rte_port", ct_offload1->odp_port);
        goto err_port1;
    }
    fill_ct_match(&match, ct_offload1);
    /* Add flow to CT table */
    build_ctid(data->mark, dir1, false, &ctid);
    ret =  ct_add_rte_flow_offload(rte_port, &match, ct_offload1, &ctid, data->mark,
                                   false, NULL /*struct ct_stats *stats OVS_UNUSED*/);
    if (ret) {
        VLOG_DBG("failed to offload CT mark=%u dir=INIT", data->mark);
        goto err_port1;
    }
    if (ct_offload1->mod_flags) {
        /* Add flow to CT-NAT table */
        build_ctid(data->mark, dir1, true, &ctid);
        /* Add flow to CT-NAT table */
        ret =  ct_add_rte_flow_offload(rte_port, &match, ct_offload1, &ctid, data->mark,
                                       true, NULL /*struct ct_stats *stats OVS_UNUSED*/);
        if (ret) {
            VLOG_DBG("failed to offload CT-NAT mark=%u dir=INIT", data->mark);
            goto err_dir1;
        }
    }
    data->ct.rteflow[dir1] = true;
    data->ct.odp_port[dir1] = ct_offload1->odp_port;

    rte_port = netdev_rte_port_search(ct_offload2->odp_port, &port_map);
    if (!rte_port) {
        VLOG_DBG("dir=REP, port %d has no rte_port", ct_offload2->odp_port);
        goto err_dir1;
    }
    fill_ct_match(&match, ct_offload2);
    /* Add flow to CT table in the other direction */
    build_ctid(data->mark, dir2, false, &ctid);
    ret =  ct_add_rte_flow_offload(rte_port, &match, ct_offload2, &ctid, data->mark,
                                   false, NULL /*struct ct_stats *stats OVS_UNUSED*/);
    if (ret) {
        VLOG_DBG("failed to offload CT mark=%u dir=REP", data->mark);
        goto err_dir1;
    }
    if (ct_offload2->mod_flags) {
        /* Add flow to CT-NAT table in the other direction */
        build_ctid(data->mark, dir2, true, &ctid);
        ret =  ct_add_rte_flow_offload(rte_port, &match, ct_offload2, &ctid, data->mark,
                                       true, NULL /*struct ct_stats *stats OVS_UNUSED*/);
        if (ret) {
            VLOG_DBG("failed to offload CT-NAT mark=%u dir=REP", data->mark);
            goto err_dir2;
        }
    }

    data->ct.rteflow[dir2] = true;
    data->ct.odp_port[dir2] = ct_offload2->odp_port;

    /* TODO: hanlde NAT -- DONE inside ct_add_rte_flow_offload()
     * for nat we need the exact same match, but we need to add
     * modify action on the needed header fields */
    return 0;

err_dir2:
    netdev_dpdk_release_ct_flow(data, dir2);
err_dir1:
    netdev_dpdk_release_ct_flow(data, dir1);
err_port1:
    netdev_dpdk_ct_ctx_unref_outer_id(data, ct_offload1, ct_offload2);
    return -1;
}

static void
netdev_dpdk_offload_ct_ctx_update(struct mark_to_miss_ctx_data *data,
                               struct ct_flow_offload_item *ct_offload1,
                               struct ct_flow_offload_item *ct_offload2)
{
    /* all are paremeters of the session ctx, if it is not zero
     * it is expedted that both will have same value */
    data->ct.ct_zone = ct_offload1->zone?ct_offload1->zone:ct_offload2->zone;
    data->ct.ct_mark = ct_offload1->setmark?
                       ct_offload1->setmark:ct_offload2->setmark;
}


/* Offload connection tracking session event.
 * We offload both directions on same time, so
 * first message on a session we just need to store.
 * We don't allocate any resource before the offload.
 */
int
netdev_dpdk_offload_ct_put(struct ct_flow_offload_item *ct_offload,
                           uint32_t mark)
{
    struct mark_to_miss_ctx_data *data =
        netdev_dpdk_get_flow_miss_ctx(mark, true);
    if (!data) {
        return -1;
    }
    int dir = ct_offload->reply?CT_OFFLOAD_DIR_REP:CT_OFFLOAD_DIR_INIT;
    int dir_opp = netdev_dpdk_offload_ct_opposite_dir(dir);

    if (data->ct.rteflow[dir]) {
        /* TODO: maybe add warn here because it shouldn't happen */
        /* TODO: we should offload once on established. Roni - to advise how to check 'once' */
        netdev_dpdk_release_ct_flow(data, dir);
        data->ct.rteflow[dir] = false;
    }
    data->ct.ct_offload[dir] = netdev_dpdk_offload_ct_dup(ct_offload);

    /* we offload only when we have both sides */
    /* this might need to change if we want to support single dir flow */
    /* but then we should define established differently */
    if (data->ct.ct_offload[dir_opp]) {
        struct ct_flow_offload_item *ct_off_opp = data->ct.ct_offload[dir_opp];

        /* TODO ************
         * For NAT, the approach was to get the NAT information from the packet
         * itself, upon the first packet. The connection is still at NEW state
         * at this point.
         * When we get the other direction, the connection is already
         * ESTABLISHED, so we update the opposite direction it is ESTABLISHED
         * and not new.
         * Alternative approach is to have more than two callbacks, or get
         * callbacks only upon ESTABLISHED, and extract the NAT info in another
         * way.
         */
        if (ct_offload->ct_state & CS_ESTABLISHED &&
            !(data->ct.ct_offload[dir_opp]->ct_state & CS_ESTABLISHED)) {
            data->ct.ct_offload[dir_opp]->ct_state |= CS_ESTABLISHED;
            data->ct.ct_offload[dir_opp]->ct_state &= ~CS_NEW;
        }
        if (!(ct_offload->ct_state & CS_ESTABLISHED) &&
            data->ct.ct_offload[dir_opp]->ct_state & CS_ESTABLISHED) {
            ct_offload->ct_state |= CS_ESTABLISHED;
            ct_offload->ct_state &= ~CS_NEW;
        }
        if (!(ct_offload->ct_state & CS_ESTABLISHED) ||
            netdev_dpdk_offload_ct_session(data, ct_off_opp, ct_offload)) {
            free(ct_off_opp);
            free(data->ct.ct_offload[dir]);
            return -1;
        }
        netdev_dpdk_offload_ct_ctx_update(data, ct_off_opp, ct_offload);
        data->type = MARK_PREPROCESS_CT;
        data->mark = mark;
    }

    return 0;
}

int
netdev_dpdk_offload_ct_del(uint32_t mark)
{
    struct mark_to_miss_ctx_data *data;
    if (!netdev_dpdk_find_miss_ctx(mark, &data)) {
        return 0;
    }
    netdev_dpdk_release_ct_flow(data, CT_OFFLOAD_DIR_REP);
    netdev_dpdk_release_ct_flow(data, CT_OFFLOAD_DIR_INIT);

    /* Destroy FLOWS  from NAT and CT NAT */
    netdev_dpdk_del_miss_ctx(mark);
    /* TODO - destroy rte_flows from tables -- DONE in netdev_dpdk_release_ct_flow()
     */
    return 0;
}

struct hwid_to_flow {
    struct cmap_node node;
    uint32_t hwid;
    int refcnt;
    struct rte_flow *rte_flow;
};

static struct rte_flow *
netdev_rte_create_hwid_flow(struct netdev *netdev, uint32_t hwid, uint16_t dpdk_port, bool port)
{
    struct rte_flow_attr flow_attr = {
        .group = MAPPING_TABLE_ID,
        .priority = 0,
        .ingress = 1,
        .egress = 0,
        .transfer = 1
    };
    int ret = 0;

    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };

    struct flow_items spec, mask;
    memset(&spec, 0, sizeof spec);
    memset(&mask, 0, sizeof mask);

    /* Match on hwid by setting meta data */
    ret = netdev_dpdk_add_pattern_match_reg(&spec, &mask, &patterns,
                                            TAG_FIELD_HW_ID,
                                            hwid, 0xFFFFFFFF);
    if (ret) {
        return NULL;
    }
    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow_action_jump jump;
    struct rte_flow_action_port_id port_id;

    if (port) {
        /* OUTPUT to dpdk port ID */
        port_id.id = dpdk_port;
        port_id.original = 0;
        netdev_rte_add_port_id_flow_action(&port_id, &actions);
    } else {
        /* Jump to recircid table */
        netdev_rte_add_jump_flow_action(&jump, hwid, &actions);
    }
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    struct rte_flow_error error;
    struct rte_flow *flow;

    flow = netdev_dpdk_rte_flow_create(netdev,
                                       &flow_attr, patterns.items,
                                       actions.actions, &error);
    VLOG_DBG("eSwitch offload was %s", flow ? "succeeded" : "failed");
    return flow;
}

static struct hwid_to_flow *
netdev_rte_hwid_search(uint32_t hwid, struct cmap *map)
{
    size_t hash = hash_bytes(&hwid, sizeof hwid, 0);
    struct hwid_to_flow *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (hwid == data->hwid) {
            return data;
        }
    }

    return NULL;
}

static int
netdev_rte_add_hwid_mapping(struct netdev_rte_port *rte_port, odp_port_t out_dp_port,
                            uint32_t hwid, bool is_port, struct rte_flow **rte_flow)
{
    *rte_flow = NULL;
    struct cmap *map = is_port ? &rte_port->portid_to_rte : &rte_port->recirc_to_rte;
    struct hwid_to_flow *htf =
        netdev_rte_hwid_search(hwid, map);
    if (is_port && htf) {
        return 0;
    }
    if (!htf) {
        uint16_t dpdk_port_id = 0;
        if (is_port) {
            struct netdev_rte_port *out_rte_port =
                netdev_rte_port_search(out_dp_port, &port_map);
            if (!out_rte_port) {
                return 0;
            }
            dpdk_port_id = out_rte_port->dpdk_port_id;
        }
        /* Create a DPDK flow for this hwid in the MAPPING table */
        *rte_flow =
            netdev_rte_create_hwid_flow(rte_port->netdev, hwid,
                                        dpdk_port_id, is_port);
        if (!*rte_flow) {
            VLOG_ERR("Mapping table: rte_flow == NULL\n");
            return -1;
        }

        /* Insert a new hwid entry with the flow and refcnt = 1. */
        size_t hash = hash_bytes(&hwid, sizeof hwid, 0);
        htf = xzalloc(sizeof *htf);
        if (!htf) {
            VLOG_WARN("Failed to add recirc to flow, (ENOMEM)");
            return -1;
        }
        htf->hwid = hwid;
        htf->refcnt = 1;
        htf->rte_flow = *rte_flow;
        cmap_insert(map,
            CONST_CAST(struct cmap_node *, &htf->node), hash);
    } else {
        /* Increase refcnt */
        htf->refcnt++;
    }

    return 0;
}

static int
netdev_rte_del_hwid_mapping(struct netdev_rte_port *rte_port, uint32_t hwid,
                            bool port)
{
    int ret = 0;
    struct rte_flow *flow;
    struct cmap *map = port ? &rte_port->portid_to_rte : &rte_port->recirc_to_rte;
    struct hwid_to_flow *htf =
        netdev_rte_hwid_search(hwid, map);
    if (!htf) {
        /* No error if mapping is deleted before it was inserted */
        return 0;
    }
    /* Decrease refcnt */
    htf->refcnt--;
    if (htf->refcnt) {
        return 0;
    }

    /* If refcnt equals 0 - delete this entry and destroy the rte flow */
    flow = htf->rte_flow;
    htf->rte_flow = NULL;
    size_t hash = hash_bytes(&hwid, sizeof hwid, 0);
    cmap_remove(map,
            CONST_CAST(struct cmap_node *, &htf->node), hash);
    ovsrcu_postpone(free, htf);
    struct rte_flow_error error;
    ret = netdev_dpdk_rte_flow_destroy(rte_port->netdev, flow, &error);
    if (ret) {
        VLOG_ERR("rte flow destroy error: %u : message :"
                " %s\n", error.type, error.message);
    }
    return ret;
}

#define SAVE_FLOW(N_FLOWS, NETDEV, RTE_FLOW) \
    do { \
        if (RTE_FLOW) { \
            flows[N_FLOWS].netdev = NETDEV; \
            flows[N_FLOWS].rte_flow = RTE_FLOW; \
            N_FLOWS++; \
        } \
    } while (0);

static int
netdev_rte_update_hwid_mapping(struct netdev_rte_port *rte_port,
                               odp_port_t out_dp_port,
                               uint32_t hwid, bool is_add, bool port)
{
    int ret = 0;
    struct netdev_rte_port *data;
    struct rte_flow *rte_flow;
    struct rte_flow_error error;

    struct {
        struct netdev *netdev;
        struct rte_flow *rte_flow;
    } flows[dpdk_phy_ports_amount];
    int n_flows = 0;

    if (port) {
        goto port_handling;
    } else {
        goto recirc_handling;
    }

port_handling:
    CMAP_FOR_EACH (data, node, &port_map) {
        if (n_flows == dpdk_phy_ports_amount) {
            goto roll_back;
        }
        /* Go over all DPDK ports except the output port itself */
        if (data->rte_port_type == RTE_PORT_TYPE_DPDK &&
            data->dp_port != out_dp_port) {
            if (is_add) {
                ret = netdev_rte_add_hwid_mapping(data, out_dp_port,
                                                  hwid, port, &rte_flow);
                SAVE_FLOW (n_flows, data->netdev, rte_flow);
                if (ret) {
                    goto roll_back;
                }
            } else {
                if (netdev_rte_del_hwid_mapping(data, hwid, port)) {
                    goto roll_back;
                }
            }
        }
    }
    return ret;

recirc_handling:
    if (rte_port->rte_port_type == RTE_PORT_TYPE_VXLAN) {
        CMAP_FOR_EACH (data, node, &port_map) {
            if (n_flows == dpdk_phy_ports_amount) {
                goto roll_back;
            }
            /* For vport type consier all uplink DPDK types. */
            if (data->is_uplink) {
                if (is_add) {
                    ret = netdev_rte_add_hwid_mapping(data, 0, hwid,
                                                      port, &rte_flow);
                    SAVE_FLOW (n_flows, data->netdev, rte_flow);
                    if (ret) {
                        goto roll_back;
                    }
                } else {
                    if (netdev_rte_del_hwid_mapping(data, hwid, port)) {
                        goto roll_back;
                    }
                }
            }
        }
    }

    if (rte_port->rte_port_type == RTE_PORT_TYPE_DPDK) {
        if (is_add) {
            ret = netdev_rte_add_hwid_mapping(rte_port, 0, hwid,
                                              port, &rte_flow);
            SAVE_FLOW (n_flows, rte_port->netdev, rte_flow);
            if (ret) {
                goto roll_back;
            }
        } else {
            if (netdev_rte_del_hwid_mapping(rte_port, hwid, port)) {
                goto roll_back;
            }
        }
    }

    return 0;

roll_back:
    for (int i = 0; i < n_flows; i++) {
        ret = netdev_dpdk_rte_flow_destroy(flows[i].netdev,
                                           flows[i].rte_flow,
                                           &error);
        if (ret) {
            VLOG_ERR("%s: rte flow destroy error: %u : message : %s\n",
                     netdev_get_name(flows[i].netdev), error.type, error.message);
        }
    }
    return -1;
}

static int
restore_packet_state(uint32_t flow_mark, struct dp_packet *packet)
{
    struct mark_to_miss_ctx_data *miss_ctx;
    uint16_t outer_id;
    uint32_t hw_id;
    struct ct_flow_offload_item *ct_offload = NULL;
    struct ct_flow_offload_item *ct_init, *ct_rep;
    struct netdev_rte_port *rte_port;
    int dir;

    miss_ctx = netdev_dpdk_get_flow_miss_ctx(flow_mark, false);
    if (!miss_ctx)
        return -1;

    switch (miss_ctx->type) {
    case MARK_PREPROCESS_VXLAN:
        /* 
         * No need for individual mark handling. There is a
         * default rule in VXLAN table for default Mark+RSS
         * */
        break;

    case MARK_PREPROCESS_CT:
        ct_init = miss_ctx->ct.ct_offload[CT_OFFLOAD_DIR_INIT];
        ct_rep = miss_ctx->ct.ct_offload[CT_OFFLOAD_DIR_REP];
        rte_port = netdev_rte_port_search(packet->md.in_port.odp_port, &port_map);
        if ((packet->md.in_port.odp_port == ct_init->odp_port) ||
           (rte_port->is_uplink && ct_init->tun.ip_dst)) {
            dir = CT_OFFLOAD_DIR_INIT;
        }
        else if ((packet->md.in_port.odp_port == ct_rep->odp_port) ||
                (rte_port->is_uplink && ct_rep->tun.ip_dst)) {
            dir = CT_OFFLOAD_DIR_REP;
        } else {
            VLOG_DBG("Could not match any direction for CT miss handling");
            return -1;
        }
        ct_offload = miss_ctx->ct.ct_offload[dir];

        packet->md.ct_zone = miss_ctx->ct.ct_zone;
        packet->md.ct_state = ct_offload->ct_state;
        packet->md.in_port.odp_port = ct_offload->odp_port;
        packet->md.recirc_id = 0;
        if (!dp_packet_has_flow_meta(packet, &hw_id)) {
            hw_id = 0;
        }
        if (hw_id && netdev_dpdk_get_id_from_hw_id(hw_id, false,
                                                   &packet->md.recirc_id)) {
            VLOG_DBG("Failed to get recirc_id from hw_id %u", hw_id);
            return -1;
        }
        netdev_dpdk_tun_recover_meta_data(packet, miss_ctx->ct.outer_id[dir]);
    break;

    case MARK_PREPROCESS_FLOW_WITH_CT:
        packet->md.in_port.odp_port = miss_ctx->flow.in_port;
        outer_id = miss_ctx->flow.outer_id;
        if (outer_id && netdev_rte_vxlan_restore(outer_id, packet)) {
            VLOG_DBG("Failed to restore VXLAN tunnel for outer_id %u", outer_id );
            return -1;
        }
    break;

    case MARK_PREPROCESS_FLOW:
        /* No use case here */
        break;

    default:
        VLOG_ERR("Unknown preprocess type %d", miss_ctx->type);
        return -1;
    break;
    }

    return 0;
}
