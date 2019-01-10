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
#include "netdev-provider.h"

struct dp_packet;

void netdev_rte_offload_preprocess(struct dp_packet *packet, uint32_t mark);

int netdev_vport_flow_put(struct netdev *, struct match *,
                       struct nlattr *actions, size_t actions_len,
                       const ovs_u128 *, struct offload_info *,
                       struct dpif_flow_stats *);
int netdev_vport_flow_del(struct netdev * netdev OVS_UNUSED,
                        const ovs_u128 * ufid OVS_UNUSED,
                        struct dpif_flow_stats * flow_stats OVS_UNUSED);

int netdev_vport_init_flow_api(struct netdev *);

/**
 * should be called on any netdev added to the bridge phy/virt
 * odp_port_t port - the port number allocated by dpif-netdev,
 * matching the offload in_port
 * struct netdev   - point to the netdev
 */
int netdev_rte_offload_add_port(odp_port_t dp_port, struct netdev * netdev);

int netdev_rte_offload_del_port(odp_port_t dp_port);


int netdev_dpdk_flow_put(struct netdev *netdev, struct match *match,
                     struct nlattr *actions, size_t actions_len,
                     const ovs_u128 *ufid, struct offload_info *info,
                     struct dpif_flow_stats *stats OVS_UNUSED);

int netdev_dpdk_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                     struct dpif_flow_stats *stats OVS_UNUSED);

#endif /* netdev-vport-offloads.h */
