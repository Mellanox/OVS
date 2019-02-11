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
#include "netdev-rte-offloads.h"
#include "netdev-provider.h"
#include "dpif-netdev.h"
#include "cmap.h"
#include "openvswitch/vlog.h"
#include "openvswitch/match.h"
#include "packets.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(netdev_rte_offloads);

/*
 * A mapping from ufid to dpdk rte_flow.
 */
static struct cmap ufid_to_rte_flow = CMAP_INITIALIZER;

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct rte_flow *rte_flow;
};


/* Find rte_flow with @ufid */
static struct rte_flow *
ufid_to_rte_flow_find(const ovs_u128 *ufid) {
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data->rte_flow;
        }
    }

    return NULL;
}

static inline void
ufid_to_rte_flow_associate(const ovs_u128 *ufid,
                           struct rte_flow *rte_flow) {
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_rte_flow_data *data = xzalloc(sizeof(*data));

    /*
     * We should not simply overwrite an existing rte flow.
     * We should have deleted it first before re-adding it.
     * Thus, if following assert triggers, something is wrong:
     * the rte_flow is not destroyed.
     */
    ovs_assert(ufid_to_rte_flow_find(ufid) == NULL);

    data->ufid = *ufid;
    data->rte_flow = rte_flow;

    cmap_insert(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

static inline void
ufid_to_rte_flow_disassociate(const ovs_u128 *ufid) {
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            cmap_remove(&ufid_to_rte_flow,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return;
        }
    }

    VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow\n",
              UUID_ARGS((struct uuid *)ufid));
}

/*
 * To avoid individual xrealloc calls for each new element, a 'curent_max'
 * is used to keep track of current allocated number of elements. Starts
 * by 8 and doubles on each xrealloc call
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
dump_flow_pattern(struct rte_flow_item *item)
{
    struct ds s;

    if (!VLOG_IS_DBG_ENABLED() || item->type == RTE_FLOW_ITEM_TYPE_END) {
        return;
    }

    ds_init(&s);

    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        ds_put_cstr(&s, "rte flow eth pattern:\n");
        if (eth_spec) {
            ds_put_format(&s,
                     "  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                     "type=0x%04" PRIx16"\n",
                     ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                     ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                     ntohs(eth_spec->type));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (eth_mask) {
            ds_put_format(&s,
                     "  Mask: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                     "type=0x%04"PRIx16"\n",
                     ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                     ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                     eth_mask->type);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        ds_put_cstr(&s, "rte flow vlan pattern:\n");
        if (vlan_spec) {
            ds_put_format(&s,
                     "  Spec: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                     ntohs(vlan_spec->inner_type), ntohs(vlan_spec->tci));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }

        if (vlan_mask) {
            ds_put_format(&s,
                     "  Mask: inner_type=0x%"PRIx16", tci=0x%"PRIx16"\n",
                     ntohs(vlan_mask->inner_type), ntohs(vlan_mask->tci));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        ds_put_cstr(&s, "rte flow ipv4 pattern:\n");
        if (ipv4_spec) {
            ds_put_format(&s,
                     "  Spec: tos=0x%"PRIx8", ttl=%"PRIx8", proto=0x%"PRIx8
                     ", src="IP_FMT", dst="IP_FMT"\n",
                     ipv4_spec->hdr.type_of_service,
                     ipv4_spec->hdr.time_to_live,
                     ipv4_spec->hdr.next_proto_id,
                     IP_ARGS(ipv4_spec->hdr.src_addr),
                     IP_ARGS(ipv4_spec->hdr.dst_addr));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (ipv4_mask) {
            ds_put_format(&s,
                     "  Mask: tos=0x%"PRIx8", ttl=%"PRIx8", proto=0x%"PRIx8
                     ", src="IP_FMT", dst="IP_FMT"\n",
                     ipv4_mask->hdr.type_of_service,
                     ipv4_mask->hdr.time_to_live,
                     ipv4_mask->hdr.next_proto_id,
                     IP_ARGS(ipv4_mask->hdr.src_addr),
                     IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(&s, "rte flow udp pattern:\n");
        if (udp_spec) {
            ds_put_format(&s,
                     "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                     ntohs(udp_spec->hdr.src_port),
                     ntohs(udp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (udp_mask) {
            ds_put_format(&s,
                     "  Mask: src_port=0x%"PRIx16", dst_port=0x%"PRIx16"\n",
                     udp_mask->hdr.src_port,
                     udp_mask->hdr.dst_port);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        ds_put_cstr(&s, "rte flow sctp pattern:\n");
        if (sctp_spec) {
            ds_put_format(&s,
                     "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                     ntohs(sctp_spec->hdr.src_port),
                     ntohs(sctp_spec->hdr.dst_port));
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (sctp_mask) {
            ds_put_format(&s,
                     "  Mask: src_port=0x%"PRIx16", dst_port=0x%"PRIx16"\n",
                     sctp_mask->hdr.src_port,
                     sctp_mask->hdr.dst_port);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        ds_put_cstr(&s, "rte flow icmp pattern:\n");
        if (icmp_spec) {
            ds_put_format(&s,
                     "  Spec: icmp_type=%"PRIu8", icmp_code=%"PRIu8"\n",
                     icmp_spec->hdr.icmp_type,
                     icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (icmp_mask) {
            ds_put_format(&s,
                     "  Mask: icmp_type=0x%"PRIx8", icmp_code=0x%"PRIx8"\n",
                     icmp_spec->hdr.icmp_type,
                     icmp_spec->hdr.icmp_code);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        ds_put_cstr(&s, "rte flow tcp pattern:\n");
        if (tcp_spec) {
            ds_put_format(&s,
                     "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                     ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                     ntohs(tcp_spec->hdr.src_port),
                     ntohs(tcp_spec->hdr.dst_port),
                     tcp_spec->hdr.data_off,
                     tcp_spec->hdr.tcp_flags);
        } else {
            ds_put_cstr(&s, "  Spec = null\n");
        }
        if (tcp_mask) {
            ds_put_format(&s,
                     "  Mask: src_port=%"PRIx16", dst_port=%"PRIx16
                     ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                     tcp_mask->hdr.src_port,
                     tcp_mask->hdr.dst_port,
                     tcp_mask->hdr.data_off,
                     tcp_mask->hdr.tcp_flags);
        } else {
            ds_put_cstr(&s, "  Mask = null\n");
        }
    }

    VLOG_DBG("%s", ds_cstr(&s));
    ds_destroy(&s);
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask) {
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof(struct rte_flow_item));
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof(struct rte_flow_item));
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = NULL;
    dump_flow_pattern(&patterns->items[cnt]);
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
                                   sizeof(struct rte_flow_action));
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof(struct rte_flow_action));
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
                    struct netdev *netdev) {
    int i;
    struct action_rss_data *rss_data;

    rss_data = xmalloc(sizeof(struct action_rss_data) +
                       sizeof(uint16_t) * netdev->n_rxq);
    *rss_data = (struct action_rss_data) {
        .conf = (struct rte_flow_action_rss) {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = 0,
            .queue_num = netdev->n_rxq,
            .queue = rss_data->queue,
            .key_len = 0,
            .key  = NULL
        },
    };

    /* Override queue array with default */
    for (i = 0; i < netdev->n_rxq; i++) {
       rss_data->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);

    return rss_data;
}

static int
netdev_dpdk_add_rte_flow_offload(struct netdev *netdev,
                                 const struct match *match,
                                 struct nlattr *nl_actions OVS_UNUSED,
                                 size_t actions_len OVS_UNUSED,
                                 const ovs_u128 *ufid,
                                 struct offload_info *info) {
    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow;
    struct rte_flow_error error;
    uint8_t *ipv4_next_proto_mask = NULL;
    int ret = 0;

    /* Eth */
    struct rte_flow_item_eth eth_spec;
    struct rte_flow_item_eth eth_mask;
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        memset(&eth_spec, 0, sizeof eth_spec);
        memset(&eth_mask, 0, sizeof eth_mask);
        rte_memcpy(&eth_spec.dst, &match->flow.dl_dst, sizeof eth_spec.dst);
        rte_memcpy(&eth_spec.src, &match->flow.dl_src, sizeof eth_spec.src);
        eth_spec.type = match->flow.dl_type;

        rte_memcpy(&eth_mask.dst, &match->wc.masks.dl_dst,
                   sizeof eth_mask.dst);
        rte_memcpy(&eth_mask.src, &match->wc.masks.dl_src,
                   sizeof eth_mask.src);
        eth_mask.type = match->wc.masks.dl_type;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ETH,
                         &eth_spec, &eth_mask);
    } else {
        /*
         * If user specifies a flow (like UDP flow) without L2 patterns,
         * OVS will at least set the dl_type. Normally, it's enough to
         * create an eth pattern just with it. Unluckily, some Intel's
         * NIC (such as XL710) doesn't support that. Below is a workaround,
         * which simply matches any L2 pkts.
         */
        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ETH, NULL, NULL);
    }

    /* VLAN */
    struct rte_flow_item_vlan vlan_spec;
    struct rte_flow_item_vlan vlan_mask;
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        memset(&vlan_spec, 0, sizeof vlan_spec);
        memset(&vlan_mask, 0, sizeof vlan_mask);
        vlan_spec.tci  = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        vlan_mask.tci  = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* match any protocols */
        vlan_mask.inner_type = 0;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_VLAN,
                         &vlan_spec, &vlan_mask);
    }

    /* IP v4 */
    uint8_t proto = 0;
    struct rte_flow_item_ipv4 ipv4_spec;
    struct rte_flow_item_ipv4 ipv4_mask;
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        memset(&ipv4_spec, 0, sizeof ipv4_spec);
        memset(&ipv4_mask, 0, sizeof ipv4_mask);

        ipv4_spec.hdr.type_of_service = match->flow.nw_tos;
        ipv4_spec.hdr.time_to_live    = match->flow.nw_ttl;
        ipv4_spec.hdr.next_proto_id   = match->flow.nw_proto;
        ipv4_spec.hdr.src_addr        = match->flow.nw_src;
        ipv4_spec.hdr.dst_addr        = match->flow.nw_dst;

        ipv4_mask.hdr.type_of_service = match->wc.masks.nw_tos;
        ipv4_mask.hdr.time_to_live    = match->wc.masks.nw_ttl;
        ipv4_mask.hdr.next_proto_id   = match->wc.masks.nw_proto;
        ipv4_mask.hdr.src_addr        = match->wc.masks.nw_src;
        ipv4_mask.hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &ipv4_spec, &ipv4_mask);

        /* Save proto for L4 protocol setup */
        proto = ipv4_spec.hdr.next_proto_id &
                ipv4_mask.hdr.next_proto_id;

        /* Remember proto mask address for later modification */
        ipv4_next_proto_mask = &ipv4_mask.hdr.next_proto_id;
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

    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
    if (proto == IPPROTO_TCP) {
        memset(&tcp_spec, 0, sizeof tcp_spec);
        memset(&tcp_mask, 0, sizeof tcp_mask);
        tcp_spec.hdr.src_port  = match->flow.tp_src;
        tcp_spec.hdr.dst_port  = match->flow.tp_dst;
        tcp_spec.hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        tcp_spec.hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        tcp_mask.hdr.src_port  = match->wc.masks.tp_src;
        tcp_mask.hdr.dst_port  = match->wc.masks.tp_dst;
        tcp_mask.hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        tcp_mask.hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_TCP,
                         &tcp_spec, &tcp_mask);

        /* proto == TCP and ITEM_TYPE_TCP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

    struct rte_flow_item_udp udp_spec;
    struct rte_flow_item_udp udp_mask;
    if (proto == IPPROTO_UDP) {
        memset(&udp_spec, 0, sizeof udp_spec);
        memset(&udp_mask, 0, sizeof udp_mask);
        udp_spec.hdr.src_port = match->flow.tp_src;
        udp_spec.hdr.dst_port = match->flow.tp_dst;

        udp_mask.hdr.src_port = match->wc.masks.tp_src;
        udp_mask.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &udp_spec, &udp_mask);

        /* proto == UDP and ITEM_TYPE_UDP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

    struct rte_flow_item_sctp sctp_spec;
    struct rte_flow_item_sctp sctp_mask;
    if (proto == IPPROTO_SCTP) {
        memset(&sctp_spec, 0, sizeof sctp_spec);
        memset(&sctp_mask, 0, sizeof sctp_mask);
        sctp_spec.hdr.src_port = match->flow.tp_src;
        sctp_spec.hdr.dst_port = match->flow.tp_dst;

        sctp_mask.hdr.src_port = match->wc.masks.tp_src;
        sctp_mask.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_SCTP,
                         &sctp_spec, &sctp_mask);

        /* proto == SCTP and ITEM_TYPE_SCTP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

    struct rte_flow_item_icmp icmp_spec;
    struct rte_flow_item_icmp icmp_mask;
    if (proto == IPPROTO_ICMP) {
        memset(&icmp_spec, 0, sizeof icmp_spec);
        memset(&icmp_mask, 0, sizeof icmp_mask);
        icmp_spec.hdr.icmp_type = (uint8_t)ntohs(match->flow.tp_src);
        icmp_spec.hdr.icmp_code = (uint8_t)ntohs(match->flow.tp_dst);

        icmp_mask.hdr.icmp_type = (uint8_t)ntohs(match->wc.masks.tp_src);
        icmp_mask.hdr.icmp_code = (uint8_t)ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_ICMP,
                         &icmp_spec, &icmp_mask);

        /* proto == ICMP and ITEM_TYPE_ICMP, thus no need for proto match */
        if (ipv4_next_proto_mask) {
            *ipv4_next_proto_mask = 0;
        }
        goto end_proto_check;
    }

end_proto_check:

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    struct rte_flow_action_mark mark;
    struct action_rss_data *rss;

    mark.id = info->flow_mark;
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);


    rss = add_flow_rss_action(&actions, netdev);
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    flow = netdev_dpdk_rte_flow_create(netdev, &flow_attr,patterns.items,
                            actions.actions, &error);

    free(rss);
    if (!flow) {
        VLOG_ERR("%s: rte flow creat error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
        ret = -1;
        goto out;
    }
    ufid_to_rte_flow_associate(ufid, flow);
    VLOG_DBG("%s: installed flow %p by ufid "UUID_FMT"\n",
             netdev_get_name(netdev), flow, UUID_ARGS((struct uuid *)ufid));

out:
    free(patterns.items);
    free(actions.actions);
    return ret;
}



static bool
is_all_zero(const void *addr, size_t n) {
    size_t i = 0;
    const uint8_t *p = (uint8_t *)addr;

    for (i = 0; i < n; i++) {
        if (p[i] != 0) {
            return false;
        }
    }

    return true;
}

/*
 * Check if any unsupported flow patterns are specified.
 */
static int
netdev_dpdk_validate_flow(const struct match *match) {
    struct match match_zero_wc;

    /* Create a wc-zeroed version of flow */
    match_init(&match_zero_wc, &match->flow, &match->wc);

    if (!is_all_zero(&match_zero_wc.flow.tunnel,
                     sizeof(match_zero_wc.flow.tunnel))) {
        goto err;
    }

    if (match->wc.masks.metadata ||
        match->wc.masks.skb_priority ||
        match->wc.masks.pkt_mark ||
        match->wc.masks.dp_hash) {
        goto err;
    }

    /* recirc id must be zero */
    if (match_zero_wc.flow.recirc_id) {
        goto err;
    }

    if (match->wc.masks.ct_state ||
        match->wc.masks.ct_nw_proto ||
        match->wc.masks.ct_zone ||
        match->wc.masks.ct_mark ||
        match->wc.masks.ct_label.u64.hi ||
        match->wc.masks.ct_label.u64.lo) {
        goto err;
    }

    if (match->wc.masks.conj_id ||
        match->wc.masks.actset_output) {
        goto err;
    }

    /* unsupported L2 */
    if (!is_all_zero(&match->wc.masks.mpls_lse,
                     sizeof(match_zero_wc.flow.mpls_lse))) {
        goto err;
    }

    /* unsupported L3 */
    if (match->wc.masks.ipv6_label ||
        match->wc.masks.ct_nw_src ||
        match->wc.masks.ct_nw_dst ||
        !is_all_zero(&match->wc.masks.ipv6_src, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.ipv6_dst, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.ct_ipv6_src, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.ct_ipv6_dst, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.nd_target, sizeof(struct in6_addr)) ||
        !is_all_zero(&match->wc.masks.nsh, sizeof(struct ovs_key_nsh)) ||
        !is_all_zero(&match->wc.masks.arp_sha, sizeof(struct eth_addr)) ||
        !is_all_zero(&match->wc.masks.arp_tha, sizeof(struct eth_addr))) {
        goto err;
    }

    /* If fragmented, then don't HW accelerate - for now */
    if (match_zero_wc.flow.nw_frag) {
        goto err;
    }

    /* unsupported L4 */
    if (match->wc.masks.igmp_group_ip4 ||
        match->wc.masks.ct_tp_src ||
        match->wc.masks.ct_tp_dst) {
        goto err;
    }

    return 0;

err:
    VLOG_ERR("cannot HW accelerate this flow due to unsupported protocols");
    return -1;
}

static int
netdev_dpdk_destroy_rte_flow(struct netdev *netdev,
                             const ovs_u128 *ufid,
                             struct rte_flow *rte_flow) {
    struct rte_flow_error error;
    int ret = netdev_dpdk_rte_flow_destroy(netdev, rte_flow, &error);

    if (ret == 0) {
        ufid_to_rte_flow_disassociate(ufid);
        VLOG_DBG("%s: removed rte flow %p associated with ufid " UUID_FMT "\n",
                 netdev_get_name(netdev), rte_flow,
                 UUID_ARGS((struct uuid *)ufid));
    } else {
        VLOG_ERR("%s: rte flow destroy error: %u : message : %s\n",
                 netdev_get_name(netdev), error.type, error.message);
    }

    return ret;
}

int
netdev_dpdk_flow_put(struct netdev *netdev, struct match *match,
                     struct nlattr *actions, size_t actions_len,
                     const ovs_u128 *ufid, struct offload_info *info,
                     struct dpif_flow_stats *stats OVS_UNUSED) {
    struct rte_flow *rte_flow;
    int ret;

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    rte_flow = ufid_to_rte_flow_find(ufid);
    if (rte_flow) {
        ret = netdev_dpdk_destroy_rte_flow(netdev, ufid, rte_flow);
        if (ret < 0) {
            return ret;
        }
    }

    ret = netdev_dpdk_validate_flow(match);
    if (ret < 0) {
        return ret;
    }

    return netdev_dpdk_add_rte_flow_offload(netdev, match, actions,
                                            actions_len, ufid, info);
}

int
netdev_dpdk_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                     struct dpif_flow_stats *stats OVS_UNUSED) {

    struct rte_flow *rte_flow = ufid_to_rte_flow_find(ufid);

    if (!rte_flow) {
        return -1;
    }

    return netdev_dpdk_destroy_rte_flow(netdev, ufid, rte_flow);
}

