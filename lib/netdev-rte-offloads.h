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

#ifndef NETDEV_VPORT_OFFLOADS_H
#define NETDEV_VPORT_OFFLOADS_H 1

#include "openvswitch/types.h"
struct netdev;
struct match;
struct nlattr;
struct offload_info;
struct dpif_flow_stats;
struct dp_packet;

#define OFFLOAD_RESERVED_MARK (64)

int netdev_dpdk_flow_put(struct netdev *netdev, struct match *match,
                     struct nlattr *actions, size_t actions_len,
                     const ovs_u128 *ufid, struct offload_info *info,
                     struct dpif_flow_stats *stats OVS_UNUSED);

int netdev_dpdk_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                     struct dpif_flow_stats *stats OVS_UNUSED);

/**
 * should be called by dpif "netdev" when port is added.
 **/
int netdev_rte_offload_add_port(odp_port_t dp_port, 
                                struct netdev * netdev);

int netdev_rte_offload_del_port(odp_port_t dp_port);

/**
 * rte offload might use speial mark to handle exception use case. 
 * packet with special mark require some preprocessing before dpif can
 * continue the processing.
 */
void netdev_rte_offload_preprocess(struct dp_packet *packet, uint32_t mark);

#endif /* netdev-rte-offloads.h */
