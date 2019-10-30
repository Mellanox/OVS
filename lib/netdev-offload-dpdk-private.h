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

#ifndef NETDEV_OFFLOAD_DPDK_PRIVATE_H
#define NETDEV_OFFLOAD_DPDK_PRIVATE_H

#include "openvswitch/match.h"

#include <rte_flow.h>

struct netdev;

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

struct flow_pattern_items {
    struct rte_flow_item_eth  eth;
    struct rte_flow_item_vlan vlan;
    struct rte_flow_item_ipv4 ipv4;
    struct rte_flow_item_ipv6 ipv6;
    union {
        struct rte_flow_item_tcp  tcp;
        struct rte_flow_item_udp  udp;
        struct rte_flow_item_sctp sctp;
        struct rte_flow_item_icmp icmp;
    };
};

struct flow_action_items {
    struct rte_flow_action_port_id port_id;
    struct rte_flow_action_count count;
    struct rte_flow_action_mark mark;
    struct action_rss_data {
        struct rte_flow_action_rss conf;
        uint16_t queue[0];
    } rss_data;
};

void
netdev_dpdk_flow_patterns_free(struct flow_patterns *patterns);
int
netdev_dpdk_flow_patterns_add(struct flow_patterns *patterns,
                              struct flow_pattern_items *spec,
                              struct flow_pattern_items *mask,
                              const struct match *match);
void
netdev_dpdk_flow_actions_free(struct flow_actions *actions);
void
netdev_dpdk_flow_actions_add_mark_rss(struct flow_actions *actions,
                                      struct flow_action_items *action_items,
                                      uint32_t mark_id);
int
netdev_dpdk_flow_actions_add_nl(struct flow_actions *actions,
                                struct flow_action_items *action_items,
                                struct nlattr *nl_actions,
                                size_t nl_actions_len,
                                struct offload_info *info);
struct ds *
netdev_dpdk_flow_ds_put_flow(struct ds *s,
                             const struct rte_flow_attr *attr,
                             const struct rte_flow_item *items,
                             const struct rte_flow_action *actions);

#endif /* NETDEV_OFFLOAD_DPDK_PRIVATE_H */
