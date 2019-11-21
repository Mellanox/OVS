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

struct flow_action_resources {
    uint32_t table_id;
    uint32_t flow_miss_ctx_id;
};

void
netdev_dpdk_flow_patterns_free(struct flow_patterns *patterns);
int
netdev_dpdk_flow_patterns_add(struct flow_patterns *patterns,
                              struct match *match);
void
netdev_dpdk_flow_actions_free(struct flow_actions *actions);
void
netdev_dpdk_flow_actions_add_mark_rss(struct flow_actions *actions,
                                      struct netdev *netdev,
                                      uint32_t mark_id);
int
netdev_dpdk_flow_actions_add(struct flow_actions *actions,
                             struct nlattr *nl_actions,
                             size_t nl_actions_len,
                             struct offload_info *info,
                             struct flow_action_resources *act_resources);
struct ds *
netdev_dpdk_flow_ds_put_flow(struct ds *s,
                             const struct rte_flow_attr *attr,
                             const struct rte_flow_item *items,
                             const struct rte_flow_action *actions);

struct flow_miss_ctx {
    odp_port_t vport;
};

int get_table_id(odp_port_t vport, uint32_t *table_id);
void put_table_id(uint32_t table_id);
int get_flow_miss_ctx_id(struct flow_miss_ctx *flow_ctx_data,
                         uint32_t *miss_ctx_id);
void put_flow_miss_ctx_id(uint32_t flow_miss_ctx_id);
struct flow_miss_ctx *find_flow_miss_ctx(int flow_ctx_id);

#endif /* NETDEV_OFFLOAD_DPDK_PRIVATE_H */
