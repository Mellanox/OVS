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

#ifndef NETDEV_DPDK_FLOW_H
#define NETDEV_DPDK_FLOW_H

#include <config.h>

#include "openvswitch/compiler.h"
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

struct action_rss_data {
    struct rte_flow_action_rss conf;
    uint16_t queue[0];
};

struct flow_action_items {
    struct rte_flow_action_port_id port_id;
    struct rte_flow_action_count count;
    struct {
        struct {
            struct rte_flow_action_set_mac src;
            struct rte_flow_action_set_mac dst;
        } mac;
    } set;
    struct rte_flow_action_raw_encap raw_encap;
};

void
netdev_dpdk_flow_free_patterns(struct flow_patterns *patterns);
void
netdev_dpdk_flow_free_actions(struct flow_actions *actions);
int
netdev_dpdk_flow_add_patterns(struct flow_patterns *patterns,
                              struct flow_pattern_items *spec,
                              struct flow_pattern_items *mask,
                              const struct match *match);
void
netdev_dpdk_flow_add_mark_rss_actions(struct flow_actions *actions,
                                      struct rte_flow_action_mark *mark,
                                      struct action_rss_data *rss_data,
                                      struct netdev *netdev,
                                      uint32_t mark_id);
void
netdev_dpdk_flow_dump_to_str(const struct rte_flow_attr *attr,
                             const struct rte_flow_item *items,
                             const struct rte_flow_action *actions,
                             struct ds *s);
int
netdev_dpdk_flow_add_actions(struct nlattr *nl_actions,
                             size_t nl_actions_len,
                             struct offload_info *info,
                             struct flow_action_items *action_items,
                             struct flow_actions *actions);

#endif /* netdev-dpdk-flow.h */
