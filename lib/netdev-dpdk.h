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
#include <errno.h>
#include <stdint.h>

#include "openvswitch/compiler.h"
#include "openvswitch/ofp-meter.h"

struct dp_packet;
struct netdev;

#ifdef DPDK_NETDEV

struct rte_flow;
struct rte_flow_error;
struct rte_flow_attr;
struct rte_flow_item;
struct rte_flow_action;
struct rte_flow_query_count;
struct rte_flow_action_handle;

void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);

bool netdev_dpdk_flow_api_supported(struct netdev *);

int
netdev_dpdk_rte_flow_destroy(struct netdev *netdev,
                             struct rte_flow *rte_flow,
                             struct rte_flow_error *error);
struct rte_flow *
netdev_dpdk_rte_flow_create(struct netdev *netdev,
                            const struct rte_flow_attr *attr,
                            const struct rte_flow_item *items,
                            const struct rte_flow_action *actions,
                            struct rte_flow_error *error);
int
netdev_dpdk_rte_flow_query_count(struct netdev *netdev,
                                 struct rte_flow *rte_flow,
                                 struct rte_flow_query_count *query,
                                 struct rte_flow_error *error);
struct rte_flow_action_handle *
netdev_dpdk_indirect_action_create(struct netdev *,
                                   const struct rte_flow_action *,
                                   struct rte_flow_error *);
int
netdev_dpdk_indirect_action_destroy(struct netdev *,
                                    struct rte_flow_action_handle *,
                                    struct rte_flow_error *);
int
netdev_dpdk_indirect_action_query(struct netdev *,
                                  struct rte_flow_action_handle *,
                                  void *,
                                  struct rte_flow_error *);
int
netdev_dpdk_get_esw_mgr_port_id(struct netdev *netdev);
int
netdev_dpdk_get_port_id(struct netdev *netdev);
bool
netdev_dpdk_is_uplink_port(struct netdev *netdev);
const char *
netdev_dpdk_get_port_devargs(struct netdev *netdev);
struct netdev *
netdev_dpdk_get_netdev_by_devargs(const char *devargs);
uint16_t
netdev_dpdk_get_domain_id_by_netdev(const struct netdev *netdev);
struct netdev *
netdev_dpdk_get_netdev_by_domain_id(uint16_t domain_id);

int
netdev_dpdk_meter_set(ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config);
int
netdev_dpdk_meter_get(ofproto_meter_id meter_id,
                      struct ofputil_meter_stats *stats, uint16_t n_bands);
int
netdev_dpdk_meter_del(ofproto_meter_id meter_id,
                      struct ofputil_meter_stats *stats, uint16_t n_bands);

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

static inline int
netdev_dpdk_meter_set(ofproto_meter_id meter_id OVS_UNUSED,
                      struct ofputil_meter_config *config OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static inline int
netdev_dpdk_meter_get(ofproto_meter_id meter_id OVS_UNUSED,
                      struct ofputil_meter_stats *stats OVS_UNUSED,
                      uint16_t n_bands OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static inline int
netdev_dpdk_meter_del(ofproto_meter_id meter_id OVS_UNUSED,
                      struct ofputil_meter_stats *stats OVS_UNUSED,
                      uint16_t n_bands OVS_UNUSED)
{
    return EOPNOTSUPP;
}

#endif

#endif /* netdev-dpdk.h */
