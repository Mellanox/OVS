/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#include <config.h>

#include "openvswitch/compiler.h"

struct dp_packet;
struct netdev_class;
struct netdev;
#ifdef DPDK_NETDEV

void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);

#define DPDK_VPORT_FLOW_OFFLOAD_API                                \
            NULL,                                                  \
            NULL,                                                  \
            NULL,                                                  \
            NULL,                                                  \
            netdev_vport_flow_put,                                 \
            NULL,                                                  \
            netdev_vport_flow_del,                                 \
            netdev_vport_init_flow_api
#else

static inline void
netdev_dpdk_register(void)
{
    /* Nothing */
}
static inline void
free_dpdk_buf(struct dp_packet *buf OVS_UNUSED)
{
    /* Nothing */
}

#endif

bool netdev_dpdk_is_dpdk_class(const struct netdev_class *class);

int  netdev_dpdk_get_port_id(const struct netdev * netdev);

#endif /* netdev-dpdk.h */
