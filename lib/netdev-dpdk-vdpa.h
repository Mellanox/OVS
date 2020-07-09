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

#ifndef NETDEV_DPDK_VDPA_H
#define NETDEV_DPDK_VDPA_H 1

#include "netdev.h"

struct netdev_dpdk_vdpa_relay;
struct rte_mempool;

/*
 * Functions that implement the relay forwarding for the netdev dpdkvdpa
 * which is defined and implemented in netdev-dpdk.
 * Each relay is associated with a port representor, which is a regular
 * dpdk netdev. The port representor is the calling context to the relay's
 * rx_recv function. The idle cycles of the port represntor's rx_recv are
 * used to forward packets between vf to vm and vice versa.
 */

#ifdef NETDEV_DPDK_VDPA
void *
netdev_dpdk_vdpa_alloc_relay(void);
int
netdev_dpdk_vdpa_update_relay(struct netdev_dpdk_vdpa_relay *relay,
                              struct rte_mempool *mp,
                              int n_rxq);
int
netdev_dpdk_vdpa_rxq_recv_impl(struct netdev_dpdk_vdpa_relay *relay,
                               int pr_queue);
int
netdev_dpdk_vdpa_config_impl(struct netdev_dpdk_vdpa_relay *relay,
                             uint16_t port_id,
                             const char *vm_socket,
                             const char *vf_pci,
                             int max_queues,
                             bool hw_mode);
void
netdev_dpdk_vdpa_destruct_impl(struct netdev_dpdk_vdpa_relay *relay);
int
netdev_dpdk_vdpa_get_custom_stats_impl(struct netdev_dpdk_vdpa_relay *relay,
                                       struct netdev_custom_stats *cstm_stats);

#else /* stubs */

static void *
netdev_dpdk_vdpa_alloc_relay(void)
{
    return NULL;
}

static int
netdev_dpdk_vdpa_update_relay(struct netdev_dpdk_vdpa_relay *relay OVS_UNUSED,
                              struct rte_mempool *mp OVS_UNUSED,
                              int n_rxq OVS_UNUSED)
{
    return -1;
}

static int
netdev_dpdk_vdpa_rxq_recv_impl(struct netdev_dpdk_vdpa_relay *relay OVS_UNUSED,
                               int pr_queue OVS_UNUSED)
{
    return -1;
}

static int
netdev_dpdk_vdpa_config_impl(struct netdev_dpdk_vdpa_relay *relay OVS_UNUSED,
                             uint16_t port_id OVS_UNUSED,
                             const char *vm_socket OVS_UNUSED,
                             const char *vf_pci OVS_UNUSED,
                             int max_queues OVS_UNUSED,
                             bool hw_mode OVS_UNUSED)
{
    return -1;
}

static void
netdev_dpdk_vdpa_destruct_impl(struct netdev_dpdk_vdpa_relay *relay OVS_UNUSED)
{
}

static int
netdev_dpdk_vdpa_get_custom_stats_impl(struct netdev_dpdk_vdpa_relay *relay OVS_UNUSED,
                                       struct netdev_custom_stats *cstm_stats OVS_UNUSED)
{
    return -1;
}

#endif /* NETDEV_DPDK_VDPA */

#endif /* netdev-dpdk-vdpa.h */
