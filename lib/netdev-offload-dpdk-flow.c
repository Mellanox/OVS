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
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk_flow);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(100, 5);

void
netdev_dpdk_flow_patterns_free(struct flow_patterns *patterns)
{
    /* When calling this function 'patterns' must be valid */
    int i;

    for (i = 0; i < patterns->cnt; i++) {
        if (patterns->items[i].spec) {
            free((void *)patterns->items[i].spec);
        }
        if (patterns->items[i].mask) {
            free((void *)patterns->items[i].mask);
        }
    }
    free(patterns->items);
    patterns->items = NULL;
    patterns->cnt = 0;
}

void
netdev_dpdk_flow_actions_free(struct flow_actions *actions)
{
    /* When calling this function 'actions' must be valid */
    int i;

    for (i = 0; i < actions->cnt; i++) {
        if (actions->actions[i].conf) {
            free((void *)actions->actions[i].conf);
        }
    }
    free(actions->actions);
    actions->actions = NULL;
    actions->cnt = 0;
}

static void
ds_put_flow_attr(struct ds *s, const struct rte_flow_attr *attr)
{
    ds_put_format(s,
                  "  Attributes: "
                  "ingress=%d, egress=%d, prio=%d, group=%d, transfer=%d\n",
                  attr->ingress, attr->egress, attr->priority, attr->group,
                  attr->transfer);
}

static void
ds_put_flow_pattern(struct ds *s, const struct rte_flow_item *item)
{
    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        ds_put_cstr(s, "rte flow eth pattern:\n");
        if (eth_spec) {
            ds_put_format(s,
                          "  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                          "type=0x%04" PRIx16"\n",
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
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
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
        if (ipv4_spec) {
            ds_put_format(s,
                          "  Spec: tos=0x%"PRIx8", ttl=%"PRIu8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
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
                          "  Mask: tos=0x%"PRIx8", ttl=%"PRIu8
                          ", proto=0x%"PRIx8
                          ", src="IP_FMT", dst="IP_FMT"\n",
                          ipv4_mask->hdr.type_of_service,
                          ipv4_mask->hdr.time_to_live,
                          ipv4_mask->hdr.next_proto_id,
                          IP_ARGS(ipv4_mask->hdr.src_addr),
                          IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(s, "rte flow udp pattern:\n");
        if (udp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
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
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
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
        if (tcp_spec) {
            ds_put_format(s,
                          "  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                          ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                          ntohs(tcp_spec->hdr.src_port),
                          ntohs(tcp_spec->hdr.dst_port),
                          tcp_spec->hdr.data_off,
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
        } else {
            ds_put_cstr(s, "  Mask = null\n");
        }
    } else {
        ds_put_format(s, "unknown rte flow pattern (%d)\n", item->type);
    }
}

static void
ds_put_flow_action(struct ds *s, const struct rte_flow_action *actions)
{
    if (actions->type == RTE_FLOW_ACTION_TYPE_MARK) {
        const struct rte_flow_action_mark *mark = actions->conf;

        ds_put_cstr(s, "rte flow mark action:\n");
        if (mark) {
            ds_put_format(s,
                          "  Mark: id=%d\n",
                          mark->id);
        } else {
            ds_put_cstr(s, "  Mark = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RSS) {
        const struct rte_flow_action_rss *rss = actions->conf;

        ds_put_cstr(s, "rte flow RSS action:\n");
        if (rss) {
            ds_put_format(s,
                          "  RSS: queue_num=%d\n", rss->queue_num);
        } else {
            ds_put_cstr(s, "  RSS = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_COUNT) {
        const struct rte_flow_action_count *count = actions->conf;

        ds_put_cstr(s, "rte flow count action:\n");
        if (count) {
            ds_put_format(s,
                          "  Count: shared=%d, id=%d\n",
                          count->shared, count->id);
        } else {
            ds_put_cstr(s, "  Count = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
        const struct rte_flow_action_port_id *port_id = actions->conf;

        ds_put_cstr(s, "rte flow port-id action:\n");
        if (port_id) {
            ds_put_format(s,
                          "  Port-id: original=%d, id=%d\n",
                          port_id->original, port_id->id);
        } else {
            ds_put_cstr(s, "  Port-id = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_DROP) {
        ds_put_cstr(s, "rte flow drop action\n");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
        const struct rte_flow_action_set_mac *set_mac = actions->conf;

        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST
                       ? "dst" : "src";

        ds_put_format(s, "rte flow set-mac-%s action:\n", dirstr);
        if (set_mac) {
            ds_put_format(s,
                          "  Set-mac-%s: "ETH_ADDR_FMT"\n",
                          dirstr, ETH_ADDR_BYTES_ARGS(set_mac->mac_addr));
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
                          "  Set-ipv4-%s: "IP_FMT"\n",
                          dirstr, IP_ARGS(set_ipv4->ipv4_addr));
        } else {
            ds_put_format(s, "  Set-ipv4-%s = null\n", dirstr);
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TTL) {
        const struct rte_flow_action_set_ttl *set_ttl = actions->conf;

        ds_put_cstr(s, "rte flow set-ttl action:\n");
        if (set_ttl) {
            ds_put_format(s,
                          "  Set-ttl: %d\n", set_ttl->ttl_value);
        } else {
            ds_put_cstr(s, "  Set-ttl = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
        const struct rte_flow_action_raw_encap *raw_encap = actions->conf;

        ds_put_cstr(s, "rte flow raw-encap action:\n");
        if (raw_encap) {
            ds_put_format(s,
                          "  Raw-encap: size=%ld\n",
                          raw_encap->size);
            ds_put_format(s,
                          "  Raw-encap: encap=\n");
            ds_put_hex_dump(s, raw_encap->data, raw_encap->size, 0, false);
        } else {
            ds_put_cstr(s, "  Raw-encap = null\n");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST) {
        const struct rte_flow_action_set_tp *set_tp = actions->conf;
        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST
                       ? "dst" : "src";

        ds_put_format(s, "rte flow set-tcp/udp-port-%s action:\n", dirstr);
        if (set_tp) {
            ds_put_format(s,
                          "  Set-%s-tcp/udp-port: %"PRIu16"\n",
                          dirstr, ntohs(set_tp->port));
        } else {
            ds_put_format(s, "  Set-%s-tcp/udp-port = null\n", dirstr);
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_JUMP) {
        const struct rte_flow_action_jump *jump = actions->conf;

        ds_put_cstr(s, "rte flow jump action\n");
        if (jump) {
            ds_put_format(s,
                          "  Jump: group=%"PRIu32"\n",
                          jump->group);
        }
    } else {
        ds_put_format(s, "unknown rte flow action (%d)\n", actions->type);
    }
}

struct ds *
netdev_dpdk_flow_ds_put_flow(struct ds *s,
                             const struct rte_flow_attr *attr,
                             const struct rte_flow_item *items,
                             const struct rte_flow_action *actions)
{
    if (attr) {
        ds_put_flow_attr(s, attr);
    }
    while (items && items->type != RTE_FLOW_ITEM_TYPE_END) {
        ds_put_flow_pattern(s, items++);
    }
    while (actions && actions->type != RTE_FLOW_ACTION_TYPE_END) {
        ds_put_flow_action(s, actions++);
    }

    return s;
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

void
netdev_dpdk_flow_actions_add_mark_rss(struct flow_actions *actions,
                                      struct netdev *netdev,
                                      uint32_t mark_id)
{
    struct rte_flow_action_mark *mark;
    struct action_rss_data {
        struct rte_flow_action_rss conf;
        uint16_t queue[0];
    } *rss_data;
    int i;

    mark = xmalloc(sizeof *mark);
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

    mark->id = mark_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
}

int
netdev_dpdk_flow_patterns_add(struct flow_patterns *patterns,
                              struct match *match)
{
    struct flow *consumed_masks;
    struct flow zero_masks;
    uint8_t proto = 0;
    int ret = 0;

    consumed_masks = &match->wc.masks;

    memset(&zero_masks, 0, sizeof zero_masks);
    memset(&consumed_masks->in_port, 0, sizeof consumed_masks->in_port);
    if (match->flow.recirc_id != 0) {
        ret = -1;
        goto out;
    }
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
        consumed_masks->dl_type = 0;

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
    consumed_masks->vlans[0].tci = 0;

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
        proto = spec->hdr.next_proto_id & mask->hdr.next_proto_id;
    }
    /* ignore mask match for now */
    consumed_masks->nw_frag = 0;

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
    }

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    if (memcmp(consumed_masks, &zero_masks, sizeof *consumed_masks)) {
        VLOG_DBG_RL(&error_rl,
                    "Cannot match all matches. dl_type=0x%04x",
                    ntohs(match->flow.dl_type));
        ret = -1;
    }
out:
    return ret;
}

static void
netdev_dpdk_flow_add_count_action(struct flow_actions *actions)
{
    struct rte_flow_action_count *count = xzalloc(sizeof *count);

    count->shared = 0;
    /* Each flow has a single count action, so no need of id */
    count->id = 0;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, count);
}

static int
netdev_dpdk_flow_add_port_id_action(struct flow_actions *actions,
                                    struct netdev *outdev)
{
    struct rte_flow_action_port_id *port_id = xzalloc(sizeof *port_id);
    int outdev_id;

    outdev_id = netdev_dpdk_get_port_id(outdev);
    if (outdev_id < 0) {
        return -1;
    }
    port_id->id = outdev_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_PORT_ID, port_id);
    return 0;
}

static int
netdev_dpdk_flow_add_output_action(struct flow_actions *actions,
                                   const struct nlattr *nla,
                                   struct offload_info *info)
{
    struct netdev *outdev;
    odp_port_t port;
    int ret = 0;

    port = nl_attr_get_odp_port(nla);
    outdev = netdev_ports_get(port, info->dpif_type_str);
    if (outdev == NULL) {
        VLOG_DBG_RL(&error_rl,
                    "Cannot find netdev for odp port %d", port);
        return -1;
    }
    if (netdev_dpdk_flow_add_port_id_action(actions, outdev)) {
        VLOG_DBG_RL(&error_rl,
                    "Output to %s cannot be offloaded",
                    netdev_get_name(outdev));
        ret = -1;
    }
    netdev_close(outdev);
    return ret;
}

struct set_action_info {
    const uint8_t *value, *mask;
    const uint8_t size;
    uint8_t *spec;
    const int attr;
};

static int
add_set_flow_action(struct flow_actions *actions,
                    struct set_action_info *sa_info_arr,
                    size_t sa_info_arr_size)
{
    int field, i;

    for (field = 0; field < sa_info_arr_size; field++) {
        if (sa_info_arr[field].mask) {
            /* DPDK does not support partially masked set actions. In such
             * case, fail the offload.
             */
            if (sa_info_arr[field].mask[0] != 0x00 &&
                sa_info_arr[field].mask[0] != 0xFF) {
                VLOG_DBG_RL(&error_rl,
                            "Partial mask is not supported");
                return -1;
            }

            for (i = 1; i < sa_info_arr[field].size; i++) {
                if (sa_info_arr[field].mask[i] !=
                    sa_info_arr[field].mask[i - 1]) {
                    VLOG_DBG_RL(&error_rl,
                                "Partial mask is not supported");
                    return -1;
                }
            }

            if (sa_info_arr[field].mask[0] == 0x00) {
                /* mask bytes are all 0 - no rewrite action required */
                continue;
            }
        }

        memcpy(sa_info_arr[field].spec, sa_info_arr[field].value,
               sa_info_arr[field].size);
        add_flow_action(actions, sa_info_arr[field].attr,
                        sa_info_arr[field].spec);
    }

    return 0;
}

/* Mask is at the midpoint of the data. */
#define get_mask(a, type) ((const type *)(const void *)(a + 1) + 1)

#define SA_INFO(_field, _spec, _attr) { \
    .value = (uint8_t *)&key->_field, \
    .mask = (masked) ? (uint8_t *)&mask->_field : NULL, \
    .size = sizeof key->_field, \
    .spec = (uint8_t *)&_spec, \
    .attr = _attr }

static int
netdev_dpdk_flow_add_set_actions(struct flow_actions *actions,
                                 const struct nlattr *set_actions,
                                 const size_t set_actions_len,
                                 bool masked)
{
    const struct nlattr *sa;
    unsigned int sleft;

    NL_ATTR_FOR_EACH_UNSAFE (sa, sleft, set_actions, set_actions_len) {
        if (nl_attr_type(sa) == OVS_KEY_ATTR_ETHERNET) {
            const struct ovs_key_ethernet *key = nl_attr_get(sa);
            const struct ovs_key_ethernet *mask = masked ?
                get_mask(sa, struct ovs_key_ethernet) : NULL;
            struct rte_flow_action_set_mac *src = xzalloc(sizeof *src);
            struct rte_flow_action_set_mac *dst = xzalloc(sizeof *dst);
            struct set_action_info sa_info_arr[] = {
                SA_INFO(eth_src, src->mac_addr[0],
                        RTE_FLOW_ACTION_TYPE_SET_MAC_SRC),
                SA_INFO(eth_dst, dst->mac_addr[0],
                        RTE_FLOW_ACTION_TYPE_SET_MAC_DST),
            };

            if (add_set_flow_action(actions, sa_info_arr,
                                    ARRAY_SIZE(sa_info_arr))) {
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV4) {
            const struct ovs_key_ipv4 *key = nl_attr_get(sa);
            const struct ovs_key_ipv4 *mask = masked ?
                get_mask(sa, struct ovs_key_ipv4) : NULL;
            struct rte_flow_action_set_ipv4 *src = xzalloc(sizeof *src);
            struct rte_flow_action_set_ipv4 *dst = xzalloc(sizeof *dst);
            struct rte_flow_action_set_ttl *ttl = xzalloc(sizeof *ttl);
            struct set_action_info sa_info_arr[] = {
                SA_INFO(ipv4_src, src->ipv4_addr,
                        RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC),
                SA_INFO(ipv4_dst, dst->ipv4_addr,
                        RTE_FLOW_ACTION_TYPE_SET_IPV4_DST),
                SA_INFO(ipv4_ttl, ttl->ttl_value,
                        RTE_FLOW_ACTION_TYPE_SET_TTL),
            };

            if (mask && (mask->ipv4_proto || mask->ipv4_tos ||
                mask->ipv4_frag)) {
                VLOG_DBG_RL(&error_rl, "Unsupported IPv4 set action");
                return -1;
            }

            if (add_set_flow_action(actions, sa_info_arr,
                                    ARRAY_SIZE(sa_info_arr))) {
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_TCP) {
            const struct ovs_key_tcp *key = nl_attr_get(sa);
            const struct ovs_key_tcp *mask = masked ?
                get_mask(sa, struct ovs_key_tcp) : NULL;
            struct rte_flow_action_set_tp *src = xzalloc(sizeof *src);
            struct rte_flow_action_set_tp *dst = xzalloc(sizeof *dst);
            struct set_action_info sa_info_arr[] = {
                SA_INFO(tcp_src, src->port,
                        RTE_FLOW_ACTION_TYPE_SET_TP_SRC),
                SA_INFO(tcp_dst, dst->port,
                        RTE_FLOW_ACTION_TYPE_SET_TP_DST),
            };

            if (add_set_flow_action(actions, sa_info_arr,
                                    ARRAY_SIZE(sa_info_arr))) {
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_UDP) {
            const struct ovs_key_udp *key = nl_attr_get(sa);
            const struct ovs_key_udp *mask = masked ?
                get_mask(sa, struct ovs_key_udp) : NULL;
            struct rte_flow_action_set_tp *src = xzalloc(sizeof *src);
            struct rte_flow_action_set_tp *dst = xzalloc(sizeof *dst);
            struct set_action_info sa_info_arr[] = {
                SA_INFO(udp_src, src->port,
                        RTE_FLOW_ACTION_TYPE_SET_TP_SRC),
                SA_INFO(udp_dst, dst->port,
                        RTE_FLOW_ACTION_TYPE_SET_TP_DST),
            };

            if (add_set_flow_action(actions, sa_info_arr,
                                    ARRAY_SIZE(sa_info_arr))) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&error_rl,
                        "Unsupported set action type=%d", nl_attr_type(sa));
            return -1;
        }
    }

    return 0;
}

static int
netdev_dpdk_flow_add_clone_actions(struct flow_actions *actions,
                                   const struct nlattr *clone_actions,
                                   const size_t clone_actions_len,
                                   struct offload_info *info)
{
    const struct nlattr *ca;
    unsigned int cleft;

    NL_ATTR_FOR_EACH_UNSAFE (ca, cleft, clone_actions, clone_actions_len) {
        int clone_type = nl_attr_type(ca);

        if (clone_type == OVS_ACTION_ATTR_TUNNEL_PUSH) {
            const struct ovs_action_push_tnl *tnl_push = nl_attr_get(ca);
            struct rte_flow_action_raw_encap *raw_encap =
                xzalloc(sizeof *raw_encap);

            raw_encap->data = (uint8_t *)tnl_push->header;
            raw_encap->preserve = NULL;
            raw_encap->size = tnl_push->header_len;

            add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
                            raw_encap);
        } else if (clone_type == OVS_ACTION_ATTR_OUTPUT) {
            if (!(cleft <= NLA_ALIGN(ca->nla_len)) ||
                netdev_dpdk_flow_add_output_action(actions, ca, info)) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&error_rl,
                        "Unsupported clone action. clone_type=%d", clone_type);
            return -1;
        }
    }

    return 0;
}

static void
netdev_dpdk_flow_add_mark_action(struct flow_actions *actions,
                                 uint32_t mark_id)
{
    struct rte_flow_action_mark *mark = xzalloc(sizeof *mark);

    mark->id = mark_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);
}

static void
netdev_dpdk_flow_add_jump_action(struct flow_actions *actions, uint32_t group)
{
    struct rte_flow_action_jump *jump = xzalloc (sizeof *jump);

    jump->group = group;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump);
}

static int
netdev_dpdk_flow_add_tnl_pop_actions(struct flow_actions *actions,
                                     const struct nlattr *nla,
                                     struct flow_action_resources *act_resources)
{
    struct flow_miss_ctx miss_ctx;
    odp_port_t port;

    port = nl_attr_get_odp_port(nla);
    miss_ctx.vport = port;
    if (get_flow_miss_ctx_id(&miss_ctx, &act_resources->flow_miss_ctx_id)) {
        return -1;
    }
    netdev_dpdk_flow_add_mark_action(actions, act_resources->flow_miss_ctx_id);
    if (get_table_id(port, &act_resources->table_id)) {
        return -1;
    }
    netdev_dpdk_flow_add_jump_action(actions, act_resources->table_id);
    return 0;
}

int
netdev_dpdk_flow_actions_add(struct flow_actions *actions,
                             struct nlattr *nl_actions,
                             size_t nl_actions_len,
                             struct offload_info *info,
                             struct flow_action_resources *act_resources)
{
    struct nlattr *nla;
    size_t left;

    netdev_dpdk_flow_add_count_action(actions);
    NL_ATTR_FOR_EACH_UNSAFE (nla, left, nl_actions, nl_actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            if (!(left <= NLA_ALIGN(nla->nla_len)) ||
                netdev_dpdk_flow_add_output_action(actions, nla, info )) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET ||
                   nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED) {
            const struct nlattr *set_actions = nl_attr_get(nla);
            const size_t set_actions_len = nl_attr_get_size(nla);
            bool masked = nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED;

            if (netdev_dpdk_flow_add_set_actions(actions, set_actions,
                                                 set_actions_len, masked)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CLONE) {
            const struct nlattr *clone_actions = nl_attr_get(nla);
            size_t clone_actions_len = nl_attr_get_size(nla);

            if (!(left <= NLA_ALIGN(nla->nla_len)) ||
                netdev_dpdk_flow_add_clone_actions(actions, clone_actions,
                                                   clone_actions_len, info)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_TUNNEL_POP) {
            if (netdev_dpdk_flow_add_tnl_pop_actions(actions, nla,
                                                     act_resources)) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&error_rl,
                        "Unsupported action type %d", nl_attr_type(nla));
            return -1;
        }
    }

    if (nl_actions_len == 0) {
        add_flow_action(actions, RTE_FLOW_ACTION_TYPE_DROP, NULL);
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    return 0;
}

