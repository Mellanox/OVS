/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
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
#include "netdev-rte-offloads.h"
#include "netdev-offload-api.h"
#include "fatal-signal.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/vlog.h"
#include "openvswitch/match.h"
#include "openvswitch/netdev.h"
#include "openvswitch/types.h"
#include "openvswitch/thread.h"
#include "cmap.h"
#include "netdev-dpdk.h"
#include "id-pool.h"
#include "uuid.h"
#include "netdev.h"
#include <rte_flow.h>
#include "dp-packet.h"
#include <rte_ethdev.h>

VLOG_DEFINE_THIS_MODULE(netdev_rte_offload);

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = ETH_MQ_RX_RSS,
        .split_hdr_size = 0,
        .header_split   = 0, /* Header Split disabled */
        .hw_ip_checksum = 0, /* IP checksum offload disabled */
        .hw_vlan_filter = 0, /* VLAN filtering disabled */
        .jumbo_frame    = 0, /* Jumbo Frame Support disabled */
        .hw_strip_crc   = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
    },
};


#define RTE_FLOW_MAX_TABLES (31)
#define HW_OFFLOAD_MAX_PHY (128)
#define INVALID_ODP_PORT (-1)
#define MAX_PHY_RTE_PORTS (128)

struct rte_flow;
struct netdev_rte_port ;


//-------------------------------------------------------


//-------------------------------------

static int netdev_dpdk_validate_flow(const struct match *match);

static struct rte_flow * netdev_dpdk_add_rte_flow_offload(
                                 struct netdev_rte_port * rte_port,
                                 struct netdev *netdev,
                                 const struct match *match,
                                 struct nlattr *nl_actions,
                                 size_t actions_len,
                                 const ovs_u128 *ufid OVS_UNUSED,
                                 struct offload_info *info,
                                 uint64_t * counter_id);


struct netdev_rte_offload_table_ids {
    struct ovs_mutex mutex;
    struct id_pool * table_id_pool;
    struct id_pool * mark_pool;
};

static struct netdev_rte_offload_table_ids netdev_rte_offload_data = {
    .mutex = OVS_MUTEX_INITIALIZER,
    .table_id_pool = NULL,
    .mark_pool = NULL
};

enum rte_port_type {
     RTE_PORT_TYPE_NONE,
     RTE_PORT_TYPE_DPDK,
     RTE_PORT_TYPE_VXLAN
};

/**
 * @brief - struct for holding table represntation of a vport flows.
 */
struct netdev_rte_port {
  struct cmap_node node;      // map by port_no
  odp_port_t  port_no;

  struct cmap_node all_node;  // map by netdev
  struct netdev * netdev;

  struct cmap_node mark_node;
  uint32_t mark;

  enum rte_port_type rte_port_type;
  uint32_t    table_id;
  uint16_t    dpdk_port_id;
  uint16_t    dpdk_num_queues;

  uint32_t    special_mark;
  struct rte_flow * default_rte_flow[RTE_FLOW_MAX_TABLES]; // per odp

  struct cmap ufid_to_rte;   // map of fuid to all the matching rte_flows
};

struct rte_flow_data {
     struct rte_flow * flow;
     uint16_t          port_id;
     uint64_t          counter_id;
};

struct ufid_hw_offload {
    struct cmap_node node;
    int max_flows;
    int curr_idx;
    ovs_u128 ufid;
    struct rte_flow_data rte_flow_data[1];
};

static struct cmap vport_map = CMAP_INITIALIZER;

static struct cmap dpdk_map = CMAP_INITIALIZER;

static struct cmap rte_port_by_netdev = CMAP_INITIALIZER;

static struct cmap mark_to_rte_port = CMAP_INITIALIZER;

//TODO: init it some how.
static struct netdev_rte_port * rte_port_phy_arr[MAX_PHY_RTE_PORTS];
static struct netdev_rte_port * rte_port_vir_arr[MAX_PHY_RTE_PORTS];

struct ufid_to_odp {
    struct cmap_node node;
    ovs_u128 ufid;
    odp_port_t port_no;
};


static struct cmap ufid_to_portid_map = CMAP_INITIALIZER;

struct rte_flow_items {
    struct rte_flow_item_eth eth;
    struct rte_flow_item_vlan vlan;
    struct rte_flow_item_ipv4 ipv4;
    struct rte_flow_item_tcp tcp;
    struct rte_flow_item_udp udp;
    struct rte_flow_item_sctp sctp;
    struct rte_flow_item_icmp icmp;
    struct rte_flow_item_vxlan vxlan;
};

/**
 * @brief - search for ufid mapping
 *
 * @param ufid
 *
 * @return ref to object and not a copy.
 */
static struct ufid_to_odp * ufid_to_portid_get(const ovs_u128 * ufid)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_odp * data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_portid_map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static odp_port_t ufid_to_portid_search(const ovs_u128 * ufid)
{
   struct ufid_to_odp * data = ufid_to_portid_get(ufid);

   return (data != NULL)?data->port_no:INVALID_ODP_PORT;
}


/**
 * @brief - save the fuid->port_no mapping.
 *
 * @param ufid
 * @param port_no
 *
 * @return the port if saved successfully.
 */
static odp_port_t ufid_to_portid_add(const ovs_u128 * ufid, odp_port_t port_no)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_odp * data;

    if (ufid_to_portid_search(ufid) != INVALID_ODP_PORT) {
        return port_no;
    }

    data = xzalloc(sizeof(*data));

    if (data == NULL) {
        VLOG_WARN("failed to add fuid to odp, OOM");
        return INVALID_ODP_PORT;
    }

    data->ufid = *ufid;
    data->port_no = port_no;

    cmap_insert(&ufid_to_portid_map,
                CONST_CAST(struct cmap_node *, &data->node), hash);

    return port_no;
}

/**
 * @brief - remove the mapping if exists.
 *
 * @param ufid
 */
static void ufid_to_portid_remove(const ovs_u128 * ufid)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_to_odp * data = ufid_to_portid_get(ufid);

    if (data != NULL) {
        cmap_remove(&ufid_to_portid_map,
                        CONST_CAST(struct cmap_node *, &data->node),
                        hash);
        free(data);
    }


    return;
}

/**
 * @brief - allocate RTE_FLOW table from id pool.
 *
 * @param id - OUR
 * @return true on success and false on failure.
 */
static bool netdev_rte_reserved_mark_alloc(uint32_t *id)
{
    bool ret;

    // ids can be allocated on different triggers (but few), so  must protect.
    ovs_mutex_lock(&netdev_rte_offload_data.mutex);

    if (netdev_rte_offload_data.mark_pool == NULL) {
        netdev_rte_offload_data.mark_pool = id_pool_create(1,
                                                  OFFLOAD_RESERVED_MARK);
        if (netdev_rte_offload_data.mark_pool == NULL) {
            VLOG_WARN("failed to allocate pool for rte table id");
            ovs_mutex_unlock(&netdev_rte_offload_data.mutex);
            return false;
        }
    }

    ret = id_pool_alloc_id(netdev_rte_offload_data.mark_pool, id);
    ovs_mutex_unlock(&netdev_rte_offload_data.mutex);

    return ret;
}


/**
 * @brief - relase special mark back to the pool
 *
 * @param id
 *
 * @return
 */
static void netdev_rte_reserved_mark_free(uint32_t id)
{
    // ids can be allocated on different triggers (but few), must protect.
    ovs_mutex_lock(&netdev_rte_offload_data.mutex);

    if (netdev_rte_offload_data.mark_pool == NULL) {
        ovs_mutex_unlock(&netdev_rte_offload_data.mutex);
        return;
    }

    id_pool_free_id(netdev_rte_offload_data.mark_pool, id);
    ovs_mutex_unlock(&netdev_rte_offload_data.mutex);

    return;
}

/**
 * @brief - allocate RTE_FLOW table from id pool.
 *
 * @param id - OUR
 * @return true on success and false on failure.
 */
static bool netdev_rte_alloc_table_id(uint32_t *id)
{
    bool ret;

    ovs_mutex_lock(&netdev_rte_offload_data.mutex);

    if (netdev_rte_offload_data.table_id_pool == NULL) {
        netdev_rte_offload_data.table_id_pool = id_pool_create(1
                                          , RTE_FLOW_MAX_TABLES);
        if (netdev_rte_offload_data.table_id_pool == NULL) {
            VLOG_WARN("failed to allocate pool for rte table id");
            ovs_mutex_unlock(&netdev_rte_offload_data.mutex);
            return false;
        }
    }

    ret = id_pool_alloc_id(netdev_rte_offload_data.table_id_pool, id);
    ovs_mutex_unlock(&netdev_rte_offload_data.mutex);

    return ret;
}


static void netdev_rte_free_table_id(uint32_t id)
{

    ovs_mutex_lock(&netdev_rte_offload_data.mutex);
    ovs_assert(netdev_rte_offload_data.table_id_pool != NULL);

    if (netdev_rte_offload_data.table_id_pool != NULL) {
        id_pool_free_id( netdev_rte_offload_data.table_id_pool, id);
    }

    ovs_mutex_unlock(&netdev_rte_offload_data.mutex);

    return;
}

/**
 * @brief - fuid hw offload struct contains array of pointers to RTE FLOWS.
 *  in case of vxlan offload we need rule per phy port. in other cases
 *  we might need only one.
 *
 * @param size  - number of expected max rte for this fuids.
 * @param ufid  - the fuid
 *
 * @return new struct on NULL if OOM
 */
static struct ufid_hw_offload * netdev_rte_port_ufid_hw_offload_alloc(int size,
                                                         const ovs_u128 * ufid)
{
    struct ufid_hw_offload * ret = xzalloc(sizeof(struct  ufid_hw_offload) +
                                           sizeof(struct rte_flow_data)*size);
    if (ret != NULL) {
        ret->max_flows = size;
        ret->curr_idx = 0;
        ret->ufid = *ufid;
    }

    return ret;
}

static int netdev_rte_port_destory_rte_flow(uint16_t port_id,
                                            struct rte_flow * flow)
{
    struct rte_flow_error error;
    int ret = 0;
    ret = rte_flow_destroy(port_id, flow, &error);

    // TODO: think better what we do here.
    if (ret != 0) {
        VLOG_ERR("rte flow destroy error: %u : message : %s\n",
             error.type, error.message);

    }
    return ret;
}

/**
 * @brief - if hw rules were interducedm we make sure we clean them before
 * we free the struct.
 *
 * @param hw_offload
 */
static int netdev_rte_port_ufid_hw_offload_free(
                                           struct ufid_hw_offload * hw_offload)
{
    VLOG_DBG("clean all rte flows for fuid "UUID_FMT" \n",
                                  UUID_ARGS((struct uuid *)&hw_offload->ufid));

    for (int i = 0 ; i < hw_offload->curr_idx ; i++) {
    // TODO: free RTE object
        if (hw_offload->rte_flow_data[i].flow != NULL) {
            netdev_rte_port_destory_rte_flow(
                          hw_offload->rte_flow_data[i].port_id,
                          hw_offload->rte_flow_data[i].flow);

            VLOG_DBG("rte_destory for flow "UUID_FMT" on port %d, was called"
                    ,UUID_ARGS((struct uuid *)&hw_offload->ufid)
                    ,hw_offload->rte_flow_data[i].port_id );
        }

        hw_offload->rte_flow_data[i].flow = NULL;
    }

    free(hw_offload);
    return 0;
}


/**
 * @brief - run all default rules and free if exists.
 *
 * @param rte_port
 */
static void netdev_rte_port_del_default_rules(
                                   struct netdev_rte_port * rte_port)
{
    for (int i = 0 ; i < RTE_FLOW_MAX_TABLES ; i++) {
        if (rte_port->default_rte_flow[i]) {
            netdev_rte_port_destory_rte_flow(rte_port->dpdk_port_id,
                                        rte_port->default_rte_flow[i]);
            rte_port->default_rte_flow[i] = NULL;

        }
    }
}


/**
 * vport conaines a hash with data that also should be cleaned.
 *
 **/
static void netdev_rte_port_clean_all(struct netdev_rte_port * rte_vport)
{
     //TODO: CLEAN ALL INSIDE DATA
    struct cmap_cursor cursor;
    struct ufid_hw_offload * data;

    CMAP_CURSOR_FOR_EACH (data, node, &cursor, &rte_vport->ufid_to_rte) {
        netdev_rte_port_ufid_hw_offload_free(data);
    }

    return;
}

static void netdev_rte_port_del_arr(struct netdev_rte_port * rte_port,
                                    struct netdev_rte_port * arr[],
                                    int arr_len)
{
    for (int i = 0 ; i < arr_len; i++) {
        if (arr[i] == rte_port) {
            arr[i] = arr[arr_len -1]; /* switch with last*/
            return;
        }
    }

}

/**
 * @brief - release the rte_port.
 *   rte_port might contain refrences to offloaded rte_flow's
 *   that should be cleaned
 *
 * @param rte_port
 */
static void netdev_rte_port_free(struct netdev_rte_port * rte_port)
{
    size_t hash     = hash_bytes(&rte_port->port_no, sizeof(odp_port_t), 0);
    size_t hash_all = hash_bytes(&rte_port->netdev, sizeof(struct netdev *),0);
    int count;

    netdev_rte_port_clean_all(rte_port);
    cmap_remove(&rte_port_by_netdev,
                        CONST_CAST(struct cmap_node *, &rte_port->all_node),
                        hash_all);

    switch (rte_port->rte_port_type) {
        case RTE_PORT_TYPE_VXLAN:
            VLOG_DBG("remove vlxan port %d",rte_port->port_no);
            count = (int) cmap_count(&vport_map);
            cmap_remove(&vport_map,
                        CONST_CAST(struct cmap_node *, &rte_port->node), hash);
            netdev_rte_free_table_id(rte_port->table_id);
            netdev_rte_reserved_mark_free(rte_port->special_mark);
            cmap_remove(&mark_to_rte_port,
                        CONST_CAST(struct cmap_node *,
                        &rte_port->mark_node),
                        hash_bytes(&rte_port->special_mark,
                        sizeof(rte_port->special_mark),0));
            netdev_rte_port_del_arr(rte_port, &rte_port_vir_arr[0],count);
            //TODO - release special mark
            break;
        case RTE_PORT_TYPE_DPDK:
            VLOG_DBG("remove dpdk port %d",rte_port->port_no);
            count = (int) cmap_count(&dpdk_map);
            cmap_remove(&dpdk_map,
                        CONST_CAST(struct cmap_node *, &rte_port->node), hash);
            netdev_rte_port_del_default_rules(rte_port);
            netdev_rte_port_del_arr(rte_port, &rte_port_phy_arr[0],count);
            break;
        case RTE_PORT_TYPE_NONE:
            // nothig
            break;
    }

   free(rte_port);
   return;
}

/**
 * @brief - allocate new rte_port.
 *   all rte ports are kept in map by netdev, and are kept per thier type
 *   in another map.
 *
 *   in offload flows we have only the port_id, and flow del
 *   we have only the netdev.
 *
 * @param port_no
 * @param netdev
 * @param map        - specific map by type, dpdk, vport..etc.
 *
 * @return the new allocated port. already initialized for common params.
 */
static struct netdev_rte_port * netdev_rte_port_alloc(odp_port_t port_no,
                                           struct netdev * netdev,
                                           struct cmap * map,
                                           struct netdev_rte_port * port_arr[])
{
    int count = (int) cmap_count(map);
    size_t hash = hash_bytes(&port_no, sizeof(odp_port_t), 0);
    size_t hash_all = hash_bytes(&netdev, sizeof(struct netdev *), 0);
    struct netdev_rte_port *ret_port = xzalloc(sizeof(struct netdev_rte_port));

    if (ret_port == NULL) {
      VLOG_ERR("failed to alloctae ret_port, OOM");
      return NULL;
    }

   memset(ret_port,0,sizeof(*ret_port));
   ret_port->port_no = port_no;
   ret_port->netdev  = netdev;
   cmap_init(&ret_port->ufid_to_rte);

   cmap_insert(map,
                CONST_CAST(struct cmap_node *, &ret_port->node), hash);
   cmap_insert(&rte_port_by_netdev,
                CONST_CAST(struct cmap_node *, &ret_port->all_node), hash_all);
   port_arr[count] = ret_port; // for quick access


   return ret_port;
}


/**
 * search for offloaed voprt by odp port no.
 *
 **/
static struct netdev_rte_port * netdev_rte_port_search(odp_port_t port_no,
                                                       struct cmap * map)
{
    size_t hash = hash_bytes(&port_no, sizeof(odp_port_t), 0);
    struct netdev_rte_port * data;

    VLOG_DBG("search for port %d",port_no);

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (port_no ==  data->port_no) {
            return data;
        }
    }

    return NULL;
}

/**
 * @brief 0 find hw_offload of specific fuid.
 *
 * @param ufid
 * @param map    - map is bounded to interface
 *
 * @return if found on NULL if doesn't exists.
 */
static struct ufid_hw_offload * ufid_hw_offload_find(const ovs_u128 *ufid,
                                                     struct cmap * map)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_hw_offload * data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, map) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}


static struct ufid_hw_offload * ufid_hw_offload_remove(const ovs_u128 *ufid,
                                                       struct cmap * map)
{
    size_t hash = hash_bytes(ufid, sizeof(*ufid), 0);
    struct ufid_hw_offload * data = ufid_hw_offload_find(ufid,map);

    if (data != NULL) {
        cmap_remove(map, CONST_CAST(struct cmap_node *, &data->node),
                        hash);

    }
    return data;
}

static void ufid_hw_offload_add(struct ufid_hw_offload * hw_offload,
                                struct cmap * map)
{
    size_t hash = hash_bytes(&hw_offload->ufid, sizeof(ovs_u128), 0);

    cmap_insert(map,
                CONST_CAST(struct cmap_node *, &hw_offload->node), hash);

    return;
}

static void ufid_hw_offload_add_rte_flow(struct ufid_hw_offload * hw_offload,
                                         struct rte_flow * rte_flow,
                                         int dpdk_port_id,
                                         uint64_t ctr_id)
{
    if (hw_offload->curr_idx < hw_offload->max_flows) {
        hw_offload->rte_flow_data[hw_offload->curr_idx].flow = rte_flow;
        hw_offload->rte_flow_data[hw_offload->curr_idx].port_id = dpdk_port_id;
        hw_offload->rte_flow_data[hw_offload->curr_idx].counter_id = ctr_id;
        hw_offload->curr_idx++;
    } else {
        struct rte_flow_error error;
        int ret = 0;
        ret = rte_flow_destroy(dpdk_port_id, rte_flow, &error);
        if (ret != 0) {
                VLOG_ERR("rte flow destroy error: %u : message : %s\n",
                     error.type, error.message);
        }
        VLOG_WARN("failed to add rte_flow, releasing");
    }
    return;
}

int netdev_vport_flow_del(struct netdev * netdev OVS_UNUSED,
                        const ovs_u128 * ufid ,
                        struct dpif_flow_stats * flow_stats OVS_UNUSED)
{
    struct netdev_rte_port * rte_port;
    odp_port_t port_no = ufid_to_portid_search(ufid);
    struct ufid_hw_offload * ufid_hw_offload;

    if (port_no == INVALID_ODP_PORT) {
        VLOG_ERR("could not find port.");
        return -1;
    }

    rte_port = netdev_rte_port_search(port_no, &vport_map);

    ufid_to_portid_remove(ufid);

    ufid_hw_offload = ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);
    if (ufid_hw_offload) {
        netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload );
    }

    return 0;
}

struct rte_flow *
ufid_to_dpdk_rte_flow(const ovs_u128 *ufid) {
    struct ufid_hw_offload *ufid_hwol = ufid_hw_offload_find(ufid, &dpdk_map);
    if (ufid_hwol) {
        return ufid_hwol->rte_flow_data[0].flow;
    }
    return NULL;
}

int netdev_vport_init_flow_api(struct netdev * netdev OVS_UNUSED)
{
    return 0;
}

/**
 * @brief - called when dpif netdev is added to the DPIF.
 *    we create rte_port for the netdev is hw-offload can be supported.
 *
 * @param dp_port
 * @param netdev
 *
 * @return 0 on success
 */
int netdev_rte_offload_add_port(odp_port_t dp_port, struct netdev * netdev)
{
    const char *type = netdev_get_type(netdev);

    if (netdev_vport_is_vport_class(netdev->netdev_class)) {

         struct netdev_rte_port * rte_vport = netdev_rte_port_search(dp_port,
                                                                 &vport_map);
         if (rte_vport == NULL) {
            uint32_t table_id;
            uint32_t mark;
            enum rte_port_type rte_port_type = RTE_PORT_TYPE_NONE;

            if (!strcmp("vxlan", type)) {
                rte_port_type = RTE_PORT_TYPE_VXLAN;
            } else {
                VLOG_WARN("type %s is not supported currently", type);
                return -1;
            }

            if (!netdev_rte_alloc_table_id(&table_id)) {
                VLOG_WARN("failed to allocate table id for vport %d",dp_port);
                return -1;
            }

            if (!netdev_rte_reserved_mark_alloc(&mark)) {
                VLOG_WARN("failed to allocate mark for vport %d",dp_port);
                return -1;
            }

            rte_vport = netdev_rte_port_alloc(dp_port, netdev, &vport_map,
                                                    &rte_port_phy_arr[0]);
            rte_vport->rte_port_type = rte_port_type;
            rte_vport->table_id      = table_id;
            rte_vport->special_mark  = mark;
            rte_vport->port_no       = dp_port;

            cmap_insert(&mark_to_rte_port,
                CONST_CAST(struct cmap_node *, &rte_vport->mark_node),
                hash_bytes(&mark, sizeof(mark),0));

            VLOG_INFO("rte port for vport %d allocated, table id %d",
                                                  dp_port, table_id);
         }

         return 0;
    }

    if (netdev_dpdk_is_dpdk_class(netdev->netdev_class)) {
        struct netdev_rte_port * rte_vport = netdev_rte_port_search(dp_port,
                                                                  &dpdk_map);
        if (rte_vport == NULL) {
            enum rte_port_type rte_port_type = RTE_PORT_TYPE_NONE;

            if (!strcmp("dpdk", type)) {
                rte_port_type = RTE_PORT_TYPE_DPDK;
            } else {
                VLOG_WARN("type %s offload is not supported currently",type);
                return -1;
            }

            rte_vport = netdev_rte_port_alloc(dp_port, netdev, &dpdk_map,
                                                         &rte_port_vir_arr[0]);
            rte_vport->rte_port_type = rte_port_type;
            rte_vport->dpdk_port_id = netdev_dpdk_get_port_id(netdev);
            rte_vport->dpdk_num_queues = netdev->n_rxq;

            VLOG_INFO("rte_port allocated dpdk port %d, dpdk port id %d",
                                    dp_port, netdev_dpdk_get_port_id(netdev));

         }
        return 0;
    }

    VLOG_INFO("port %s is not supported",type);

    return 0;
}

static struct netdev_rte_port * netdev_rte_port_search_by_port_no(
                                                         odp_port_t port_no)
{
    struct netdev_rte_port * rte_port = NULL;

    rte_port = netdev_rte_port_search(port_no,  &vport_map);
    if (rte_port == NULL) {
        rte_port = netdev_rte_port_search(port_no,  &dpdk_map);
    }

    return rte_port;
}

int netdev_rte_offload_del_port(odp_port_t port_no)
{
      struct netdev_rte_port * rte_port =
                               netdev_rte_port_search_by_port_no(port_no);
      if (rte_port == NULL) {
        VLOG_WARN("port %d has no rte_port",port_no);
        return -1;
      }

      netdev_rte_port_free(rte_port);
      return 0;
}


// RTE_FLOW


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
    if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        VLOG_DBG("rte flow eth pattern:\n");
        if (eth_spec) {
            VLOG_DBG("  Spec: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                     "type=0x%04" PRIx16"\n",
                     ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                     ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                     ntohs(eth_spec->type));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (eth_mask) {
            VLOG_DBG("  Mask: src="ETH_ADDR_FMT", dst="ETH_ADDR_FMT", "
                     "type=0x%04"PRIx16"\n",
                     ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes),
                     ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes),
                     eth_mask->type);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        VLOG_DBG("rte flow vlan pattern:\n");
        if (vlan_spec) {
            VLOG_DBG("  Spec: tpid=0x%"PRIx16", tci=0x%"PRIx16"\n",
                     ntohs(vlan_spec->tpid), ntohs(vlan_spec->tci));
        } else {
            VLOG_DBG("  Spec = null\n");
        }

        if (vlan_mask) {
            VLOG_DBG("  Mask: tpid=0x%"PRIx16", tci=0x%"PRIx16"\n",
                     vlan_mask->tpid, vlan_mask->tci);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        VLOG_DBG("rte flow ipv4 pattern:\n");
        if (ipv4_spec) {
            VLOG_DBG("  Spec: tos=0x%"PRIx8", ttl=%"PRIx8", proto=0x%"PRIx8
                     ", src="IP_FMT", dst="IP_FMT"\n",
                     ipv4_spec->hdr.type_of_service,
                     ipv4_spec->hdr.time_to_live,
                     ipv4_spec->hdr.next_proto_id,
                     IP_ARGS(ipv4_spec->hdr.src_addr),
                     IP_ARGS(ipv4_spec->hdr.dst_addr));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (ipv4_mask) {
            VLOG_DBG("  Mask: tos=0x%"PRIx8", ttl=%"PRIx8", proto=0x%"PRIx8
                     ", src="IP_FMT", dst="IP_FMT"\n",
                     ipv4_mask->hdr.type_of_service,
                     ipv4_mask->hdr.time_to_live,
                     ipv4_mask->hdr.next_proto_id,
                     IP_ARGS(ipv4_mask->hdr.src_addr),
                     IP_ARGS(ipv4_mask->hdr.dst_addr));
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        VLOG_DBG("rte flow udp pattern:\n");
        if (udp_spec) {
            VLOG_DBG("  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                     ntohs(udp_spec->hdr.src_port),
                     ntohs(udp_spec->hdr.dst_port));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (udp_mask) {
            VLOG_DBG("  Mask: src_port=0x%"PRIx16", dst_port=0x%"PRIx16"\n",
                     udp_mask->hdr.src_port,
                     udp_mask->hdr.dst_port);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        VLOG_DBG("rte flow sctp pattern:\n");
        if (sctp_spec) {
            VLOG_DBG("  Spec: src_port=%"PRIu16", dst_port=%"PRIu16"\n",
                     ntohs(sctp_spec->hdr.src_port),
                     ntohs(sctp_spec->hdr.dst_port));
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (sctp_mask) {
            VLOG_DBG("  Mask: src_port=0x%"PRIx16", dst_port=0x%"PRIx16"\n",
                     sctp_mask->hdr.src_port,
                     sctp_mask->hdr.dst_port);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        VLOG_DBG("rte flow icmp pattern:\n");
        if (icmp_spec) {
            VLOG_DBG("  Spec: icmp_type=%"PRIu8", icmp_code=%"PRIu8"\n",
                     icmp_spec->hdr.icmp_type,
                     icmp_spec->hdr.icmp_code);
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (icmp_mask) {
            VLOG_DBG("  Mask: icmp_type=0x%"PRIx8", icmp_code=0x%"PRIx8"\n",
                     icmp_spec->hdr.icmp_type,
                     icmp_spec->hdr.icmp_code);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }

    if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        VLOG_DBG("rte flow tcp pattern:\n");
        if (tcp_spec) {
            VLOG_DBG("  Spec: src_port=%"PRIu16", dst_port=%"PRIu16
                     ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                     ntohs(tcp_spec->hdr.src_port),
                     ntohs(tcp_spec->hdr.dst_port),
                     tcp_spec->hdr.data_off,
                     tcp_spec->hdr.tcp_flags);
        } else {
            VLOG_DBG("  Spec = null\n");
        }
        if (tcp_mask) {
            VLOG_DBG("  Mask: src_port=%"PRIx16", dst_port=%"PRIx16
                     ", data_off=0x%"PRIx8", tcp_flags=0x%"PRIx8"\n",
                     tcp_mask->hdr.src_port,
                     tcp_mask->hdr.dst_port,
                     tcp_mask->hdr.data_off,
                     tcp_mask->hdr.tcp_flags);
        } else {
            VLOG_DBG("  Mask = null\n");
        }
    }
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

static struct rte_flow_action_rss *
add_flow_rss_action(struct flow_actions *actions,
                    struct netdev *netdev) {
    int i;
    struct rte_flow_action_rss *rss;

    if(netdev->n_rxq <= 0){
        VLOG_WARN("failed to add rss, num of queues <= 0");
        return NULL;
    }

    rss = xmalloc(sizeof(*rss) + sizeof(uint16_t) * netdev->n_rxq);
    /*
     * Setting it to NULL will let the driver use the default RSS
     * configuration we have set: &port_conf.rx_adv_conf.rss_conf.
     */
    rss->rss_conf = &port_conf.rx_adv_conf.rss_conf;
    rss->num = netdev->n_rxq;

    for (i = 0; i < rss->num; i++) {
        rss->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, rss);

    return rss;
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

static struct netdev_rte_port *
prepare_and_add_jump_count_flow_action(
        const struct nlattr *nlattr,
        struct rte_flow_action_jump *jump,
        struct rte_flow_action_count *count,
        struct flow_actions *actions)
{
    static uint32_t running_count_ids = 0;
    odp_port_t odp_port;
    struct netdev_rte_port *rte_port;

    odp_port = nl_attr_get_odp_port(nlattr);
    rte_port = netdev_rte_port_search_by_port_no(odp_port);
    if (!rte_port) {
        VLOG_ERR("No rte port was found for odp_port %u",
                odp_to_u32(odp_port));
        return NULL;
    }

    jump->group = rte_port->table_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump);

    count->shared = 0;
    count->id = ++running_count_ids;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, count);
    return rte_port;
}

static int
add_dpdk_flow_patterns(struct flow_patterns *patterns,
                       struct rte_flow_items *specs,
                       struct rte_flow_items *masks,
                       const struct match *match) {
    /* Eth */
    if (!eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        memset(&specs->eth, 0, sizeof(specs->eth));
        memset(&masks->eth, 0, sizeof(masks->eth));
        rte_memcpy(&specs->eth.dst, &match->flow.dl_dst,
                   sizeof(specs->eth.dst));
        rte_memcpy(&specs->eth.src, &match->flow.dl_src,
                   sizeof(specs->eth.src));
        specs->eth.type = match->flow.dl_type;

        rte_memcpy(&masks->eth.dst, &match->wc.masks.dl_dst,
                   sizeof(masks->eth.dst));
        rte_memcpy(&masks->eth.src, &match->wc.masks.dl_src,
                   sizeof(masks->eth.src));
        masks->eth.type = match->wc.masks.dl_type;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH,
                         &specs->eth, &masks->eth);
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
        memset(&specs->vlan, 0, sizeof(specs->vlan));
        memset(&masks->vlan, 0, sizeof(masks->vlan));
        specs->vlan.tci  = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        masks->vlan.tci  = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* match any protocols */
        masks->vlan.tpid = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VLAN,
                         &specs->vlan, &masks->vlan);
    }

    /* IP v4 */
    uint8_t proto = 0;
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        memset(&specs->ipv4, 0, sizeof(specs->ipv4));
        memset(&masks->ipv4, 0, sizeof(masks->ipv4));

        specs->ipv4.hdr.type_of_service = match->flow.nw_tos;
        specs->ipv4.hdr.time_to_live    = match->flow.nw_ttl;
        specs->ipv4.hdr.next_proto_id   = match->flow.nw_proto;
        specs->ipv4.hdr.src_addr        = match->flow.nw_src;
        specs->ipv4.hdr.dst_addr        = match->flow.nw_dst;

        masks->ipv4.hdr.type_of_service = match->wc.masks.nw_tos;
        masks->ipv4.hdr.time_to_live    = match->wc.masks.nw_ttl;
        masks->ipv4.hdr.next_proto_id   = match->wc.masks.nw_proto;
        masks->ipv4.hdr.src_addr        = match->wc.masks.nw_src;
        masks->ipv4.hdr.dst_addr        = match->wc.masks.nw_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &specs->ipv4, &masks->ipv4);

        /* Save proto for L4 protocol setup */
        proto = specs->ipv4.hdr.next_proto_id &
                masks->ipv4.hdr.next_proto_id;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        return -1;
    }

    if ((match->wc.masks.tp_src && (match->wc.masks.tp_src != OVS_BE16_MAX)) ||
        (match->wc.masks.tp_dst && (match->wc.masks.tp_dst != OVS_BE16_MAX))) {
        return -1;
    }

    if (proto == IPPROTO_TCP) {
        memset(&specs->tcp, 0, sizeof(specs->tcp));
        memset(&masks->tcp, 0, sizeof(masks->tcp));
        specs->tcp.hdr.src_port  = match->flow.tp_src;
        specs->tcp.hdr.dst_port  = match->flow.tp_dst;
        specs->tcp.hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        specs->tcp.hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        masks->tcp.hdr.src_port  = match->wc.masks.tp_src;
        masks->tcp.hdr.dst_port  = match->wc.masks.tp_dst;
        masks->tcp.hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        masks->tcp.hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP,
                         &specs->tcp, &masks->tcp);

    } else if (proto == IPPROTO_UDP) {
        memset(&specs->udp, 0, sizeof(specs->udp));
        memset(&masks->udp, 0, sizeof(masks->udp));
        specs->udp.hdr.src_port = match->flow.tp_src;
        specs->udp.hdr.dst_port = match->flow.tp_dst;

        specs->udp.hdr.src_port = match->wc.masks.tp_src;
        specs->udp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &specs->udp, &masks->udp);

    } else if (proto == IPPROTO_SCTP) {
        memset(&specs->sctp, 0, sizeof(specs->sctp));
        memset(&masks->sctp, 0, sizeof(masks->sctp));
        specs->sctp.hdr.src_port = match->flow.tp_src;
        specs->sctp.hdr.dst_port = match->flow.tp_dst;

        specs->sctp.hdr.src_port = match->wc.masks.tp_src;
        specs->sctp.hdr.dst_port = match->wc.masks.tp_dst;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_SCTP,
                         &specs->sctp, &masks->sctp);

    } else if (proto == IPPROTO_ICMP) {
        memset(&specs->icmp, 0, sizeof(specs->icmp));
        memset(&masks->icmp, 0, sizeof(masks->icmp));
        specs->icmp.hdr.icmp_type = (uint8_t)ntohs(match->flow.tp_src);
        specs->icmp.hdr.icmp_code = (uint8_t)ntohs(match->flow.tp_dst);

        masks->icmp.hdr.icmp_type = (uint8_t)ntohs(match->wc.masks.tp_src);
        masks->icmp.hdr.icmp_code = (uint8_t)ntohs(match->wc.masks.tp_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ICMP,
                         &specs->icmp, &masks->icmp);
    }

    return 0;
}

static void
free_flow_patterns(struct flow_patterns *patterns) {
    if (patterns->items) {
        free(patterns->items);
    }
    patterns->items = NULL;
    patterns->cnt = 0;
}

static void
free_flow_actions(struct flow_actions *actions) {
    if (actions->actions) {
        free(actions->actions);
    }
    actions->actions = NULL;
    actions->cnt = 0;
}

static struct rte_flow *
netdev_dpdk_add_rte_flow_offload(struct netdev_rte_port *rte_port,
                                 struct netdev *netdev,
                                 const struct match *match,
                                 struct nlattr *nl_actions,
                                 size_t actions_len,
                                 const ovs_u128 *ufid OVS_UNUSED,
                                 struct offload_info *info,
                                 uint64_t * counter_id) {

    if (!actions_len || !nl_actions) {
        VLOG_DBG("%s: skip flow offload without actions\n",
            netdev_get_name(netdev));
        return NULL;
    }

    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    struct rte_flow_items specs;
    struct rte_flow_items masks;
    int result = -1;
    struct netdev_rte_port * vport = NULL;

    info->is_hwol = false; /* Assume initially no HW offload */
    result = add_dpdk_flow_patterns(&patterns, &specs, &masks, match);
    if (result) {
        flow = NULL;
        goto out;
    }

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    const struct nlattr *a;
    unsigned int left;

    bool is_tunnel_pop_action = false;
    struct rte_flow_action_jump jump;
    struct rte_flow_action_count count;

    NL_ATTR_FOR_EACH_UNSAFE (a, left, nl_actions, actions_len) {
        int type = nl_attr_type(a);
        if ((enum ovs_action_attr) type == OVS_ACTION_ATTR_TUNNEL_POP) {
            vport = prepare_and_add_jump_count_flow_action(a, &jump, &count,
                    &actions);
            if (!vport) {
                break;
            }
            is_tunnel_pop_action = true;
            *counter_id = count.id;
            result = 0;
        } else {
            VLOG_DBG("Unsupported action %d for offload, "
                    "trying to offload mark and rss actions", type);
            result = -1;
            break;
        }
    }

    /* If actions can be offloaded to hw then create an rte_flow */
    if (!result) {
        add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);
        flow = rte_flow_create(rte_port->dpdk_port_id, &flow_attr, patterns.items,
                               actions.actions, &error);

        if (!flow) {
            VLOG_ERR("%s: rte flow create offload error: %u : message : %s\n",
                     netdev_get_name(netdev), error.type, error.message);
            goto out;
        }

        /* If action is tunnel pop, create another table with a default flow.
         * Do it only once, if default rte flow doesn't exist */
        if (is_tunnel_pop_action &&
                          !rte_port->default_rte_flow[vport->table_id]) {
            /* The default flow has the lowest priority, no pattern
             * (match all) and Mark action */
            const struct rte_flow_attr def_flow_attr = {
                .group = vport->table_id,
                .priority = 0, /* lowest priority */
                .ingress = 1,
                .egress = 0,
            };
            struct flow_patterns def_patterns = { .items = NULL, .cnt = 0 };
            struct flow_actions def_actions = { .actions = NULL, .cnt = 0 };
            struct rte_flow *def_flow = NULL;

            add_flow_pattern(&def_patterns, RTE_FLOW_ITEM_TYPE_END, NULL,
                    NULL);

            struct rte_flow_action_mark mark;
            mark.id = vport->special_mark;
            add_flow_action(&def_actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);

            add_flow_action(&def_actions, RTE_FLOW_ACTION_TYPE_END, NULL);

            def_flow = rte_flow_create(rte_port->dpdk_port_id, &def_flow_attr,
                    def_patterns.items, def_actions.actions, &error);


            if (!def_flow) {
                VLOG_ERR("%s: rte flow create for default flow error: %u : "
                        "message : %s\n", netdev_get_name(netdev), error.type,
                        error.message);

                free_flow_patterns(&def_patterns);
                free_flow_actions(&def_actions);
                result = rte_flow_destroy(rte_port->port_no, flow, &error);

                if (result != 0) {
                    VLOG_ERR("rte flow destroy error: %u : message : %s\n",
                         error.type, error.message);
                }
                goto out;
            }

            rte_port->default_rte_flow[vport->table_id] = def_flow;
            info->is_hwol = true;
        }
    } else { /* Previous actions cannot be offloaded to hw,
                try offloading Mark and RSS actions */
        free_flow_actions(&actions);

        struct rte_flow_action_mark mark;
        mark.id = info->flow_mark;
        add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);

        struct rte_flow_action_rss *rss;
        rss = add_flow_rss_action(&actions, netdev);

        add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

        flow = rte_flow_create(rte_port->dpdk_port_id, &flow_attr, patterns.items,
                               actions.actions, &error);
        free(rss);

        if (!flow) {
            VLOG_ERR("%s: rte flow create offload error: %u : message : %s\n",
                     netdev_get_name(netdev), error.type, error.message);
            goto out;
        }
    }

out:
    free_flow_patterns(&patterns);
    free_flow_actions(&actions);

    return flow;
}


/**
 * @brief - offload flow attached to dpdk port.
 *
 *
 * @return
 */
int
netdev_dpdk_flow_put(struct netdev *netdev , struct match *match ,
                 struct nlattr *actions,
                 size_t actions_len,
                 const ovs_u128 *ufid,
                 struct offload_info *info,
                 struct dpif_flow_stats *stats OVS_UNUSED)
{
    struct rte_flow *rte_flow;
    int ret;
    uint64_t counter_id = 0;
    odp_port_t in_port = match->flow.in_port.odp_port;
    struct netdev_rte_port * rte_port = netdev_rte_port_search(in_port,
                                                            &dpdk_map);
    struct ufid_hw_offload * ufid_hw_offload;

    if (rte_port == NULL) {
        VLOG_WARN("failed to find port dpdk no %d",in_port);
        return -1;
    }

    ufid_hw_offload = ufid_hw_offload_find(ufid, &rte_port->ufid_to_rte);

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     */
    if (ufid_hw_offload) {
        VLOG_DBG("got modification. destroy previous rte_flow");
        ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);
        ret = netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload);
       if (ret < 0) {
           return ret;
       }
        return 0;
    }

    // we create fuid_to_rte map for the fuid.
    ufid_hw_offload = netdev_rte_port_ufid_hw_offload_alloc(1, ufid);
    if (ufid_hw_offload == NULL) {
        VLOG_WARN("failed to alloctae ufid_hw_offlaod, OOM");
        return -1;
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte);
    ufid_to_portid_add(ufid, rte_port->port_no);

    // generate HW offload.
    ret = netdev_dpdk_validate_flow(match);
    if (ret < 0) {
        VLOG_ERR("not supported");
        return ret;
    }

    rte_flow = netdev_dpdk_add_rte_flow_offload(rte_port, netdev, match,
                                 actions,actions_len, ufid, info, &counter_id);

    if (rte_flow) {
        ufid_hw_offload_add_rte_flow(ufid_hw_offload, rte_flow,
                                               rte_port->dpdk_port_id,
                                               counter_id);
    }
    return ret;
}

/**
 * @brief - del HW offlaod for ufid if exists.
 *
 * @param OVS_UNUSED
 * @param ufid
 * @param OVS_UNUSED
 */
int
netdev_dpdk_flow_del(struct netdev *netdev OVS_UNUSED, const ovs_u128 *ufid,
                     struct dpif_flow_stats *stats OVS_UNUSED) {

    struct netdev_rte_port * rte_port;
    odp_port_t port_no = ufid_to_portid_search(ufid);
    struct ufid_hw_offload * ufid_hw_offload;

    // no such fuid
    if (port_no == INVALID_ODP_PORT) {
        return -1;
    }

    rte_port = netdev_rte_port_search(port_no, &dpdk_map);

    if (rte_port == NULL) {
        VLOG_ERR("failed to find dpdk port for port %d",port_no);
        return -1;
    }

    ufid_to_portid_remove(ufid);
    ufid_hw_offload = ufid_hw_offload_remove(ufid, &rte_port->ufid_to_rte);

    if (ufid_hw_offload) {
        netdev_rte_port_ufid_hw_offload_free(ufid_hw_offload );
    }

    return -1;
}

static void netdev_rte_port_preprocess(struct netdev_rte_port * rte_port,
                                       struct dp_packet *packet)
{
    switch (rte_port->rte_port_type) {
        case RTE_PORT_TYPE_VXLAN:
            {
                // VXLAN table failed to match on HW. we do however
                // know the port-id so we just pop it here.
                if (rte_port->netdev->netdev_class->pop_header) {
                    rte_port->netdev->netdev_class->pop_header(packet);
                    packet->md.in_port.odp_port = rte_port->port_no;
                    reset_dp_packet_checksum_ol_flags(packet);
                }
            }
            break;
        case RTE_PORT_TYPE_NONE:
        case RTE_PORT_TYPE_DPDK:
            VLOG_WARN("port type %d has no pre-process",
                                            rte_port->rte_port_type);
            break;

    }
    return;
}

/**
 * @brief - we got a packet with special mark, means we need to run
 *  pre-processing on the packet so it could be processed by the OVS SW.
 *  example for such case in vxlan is where we get match on outer
 *  vxlan so we jump to vxlan table, but then we fail on inner match.
 *  In this case we need to make sure SW processing continues from second flow
 *
 *
 * @param packet
 * @param mark
 */
void netdev_rte_offload_preprocess(struct dp_packet *packet, uint32_t mark)
{

    struct netdev_rte_port * rte_port;
    size_t hash = hash_bytes(&mark, sizeof(mark),0);

    CMAP_FOR_EACH_WITH_HASH (rte_port, mark_node, hash, &mark_to_rte_port) {
        if (rte_port->special_mark == mark) {
            netdev_rte_port_preprocess(rte_port, packet);
            return;
        }
    }
    VLOG_WARN("special mark %u with no port", mark);
    return;
}

static int
add_vport_vxlan_flow_patterns(struct flow_patterns *patterns,
                              struct rte_flow_items *specs,
                              struct rte_flow_items *masks,
                              const struct match *match) {
    struct vni { 
        union  {
            uint32_t val;
            uint8_t  vni[4];
        };
    };

    /* IP v4 */
    uint8_t proto = 0;
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        memset(&specs->ipv4, 0, sizeof(specs->ipv4));
        memset(&masks->ipv4, 0, sizeof(masks->ipv4));

        specs->ipv4.hdr.type_of_service = match->flow.tunnel.ip_tos;
        specs->ipv4.hdr.time_to_live    = match->flow.tunnel.ip_ttl;
        specs->ipv4.hdr.next_proto_id   = IPPROTO_UDP;
        specs->ipv4.hdr.src_addr        = match->flow.tunnel.ip_src;
        specs->ipv4.hdr.dst_addr        = match->flow.tunnel.ip_dst;

        masks->ipv4.hdr.type_of_service = match->wc.masks.tunnel.ip_tos;
        masks->ipv4.hdr.time_to_live    = match->wc.masks.tunnel.ip_ttl;
        masks->ipv4.hdr.next_proto_id   = 0xffu;
        masks->ipv4.hdr.src_addr        = match->wc.masks.tunnel.ip_src;
        masks->ipv4.hdr.dst_addr        = match->wc.masks.tunnel.ip_dst;
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4,
                         &specs->ipv4, &masks->ipv4);

        /* Save proto for L4 protocol setup */
        proto = specs->ipv4.hdr.next_proto_id &
                masks->ipv4.hdr.next_proto_id;

    } else {
        return -1;
    }

    if (proto == IPPROTO_UDP) {
        memset(&specs->udp, 0, sizeof(specs->udp));
        memset(&masks->udp, 0, sizeof(masks->udp));
        specs->udp.hdr.src_port = match->flow.tunnel.tp_src;
        specs->udp.hdr.dst_port = match->flow.tunnel.tp_dst;

        masks->udp.hdr.src_port = match->wc.masks.tp_src;
        masks->udp.hdr.dst_port = match->wc.masks.tp_dst;
        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP,
                         &specs->udp, &masks->udp);
    } else {
        VLOG_ERR("flow arrived from vxlan port, but protocol is %d "
                "and not UDP", proto);
        return -1;
    }

    struct vni vni = { .val = (uint32_t) (match->flow.tunnel.tun_id >> 32)};

    /* VXLAN */
    memset(&specs->vxlan, 0, sizeof(specs->vxlan));
    memset(&masks->vxlan, 0, sizeof(masks->vxlan));
    specs->vxlan.flags  = match->flow.tunnel.flags;
    specs->vxlan.vni[0] = vni.vni[1];
    specs->vxlan.vni[1] = vni.vni[2];
    specs->vxlan.vni[2] = vni.vni[3];

    masks->vxlan.vni[0] = 0xFF; //match->wc.masks.tunnel.tun_id & 0xFF;
    masks->vxlan.vni[1] = 0xFF; //(match->wc.masks.tunnel.tun_id >> 8) & 0xFF;
    masks->vxlan.vni[2] = 0xFF; //(match->wc.masks.tunnel.tun_id >> 16) & 0xFF;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VXLAN,
                         &specs->vxlan, &masks->vxlan);

    return 0;
}

static int
netdev_vport_vxlan_add_rte_flow_offload(struct netdev_rte_port * rte_port,
                                        struct netdev * netdev OVS_UNUSED,
                                        struct match * match,
                                        struct nlattr *nl_actions,
                                        size_t actions_len,
                                        const ovs_u128 * ufid ,
                                        struct offload_info * info OVS_UNUSED,
                              struct dpif_flow_stats * flow_stats  OVS_UNUSED)
{
    if (!actions_len || !nl_actions) {
        VLOG_DBG("%s: skip flow offload without actions\n",
            netdev_get_name(netdev));
        return 0;
    }

    int n_phy = (int) cmap_count(&dpdk_map);
    struct ufid_hw_offload * ufid_hw_offload = ufid_hw_offload_find(ufid,
                                                     &rte_port->ufid_to_rte);

    if (ufid_hw_offload != NULL) {
        //TODO: what to do on modification
        VLOG_WARN("got modification. not supported");
        return 0; // return success because we don't remove the flow yet.
    }

    if (n_phy < 1 || n_phy > HW_OFFLOAD_MAX_PHY) {
        VLOG_WARN("offload while no phy ports %d",(int)n_phy);
        return -1;
    }

    ufid_hw_offload = netdev_rte_port_ufid_hw_offload_alloc(n_phy, ufid);
    if (ufid_hw_offload == NULL) {
        VLOG_WARN("failed to allocate ufid_hw_offlaod, OOM");
        return -1;
    }

    ufid_hw_offload_add(ufid_hw_offload, &rte_port->ufid_to_rte);
    ufid_to_portid_add(ufid, rte_port->port_no);

    const struct rte_flow_attr flow_attr = {
        .group = rte_port->table_id,
        .priority = 1,
        .ingress = 1,
        .egress = 0
    };

    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    struct rte_flow_items specs;
    struct rte_flow_items masks;
    struct rte_flow_items specs_inner;
    struct rte_flow_items masks_inner;
    struct rte_flow_action_mark mark;
    struct rte_flow_action_rss *rss = NULL;
    int ret = -1;

    /* Add patterns from outer header */
    ret = add_vport_vxlan_flow_patterns(&patterns, &specs_inner,
                                        &masks_inner, match);
    if (ret) {
        goto out;
    }

    /* Add patterns from inner header */
    ret = add_dpdk_flow_patterns(&patterns, &specs, &masks, match);
    if (ret) {
        goto out;
    }

    add_flow_pattern(&patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);


    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP, NULL);

    mark.id = info->flow_mark;
    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_MARK, &mark);

    rss = add_flow_rss_action(&actions, netdev);

    add_flow_action(&actions, RTE_FLOW_ACTION_TYPE_END, NULL);

    for (int i = 0 ; i < n_phy ; i++) {

        flow = rte_flow_create(rte_port->dpdk_port_id, &flow_attr, patterns.items,
                               actions.actions, &error);



        if (!flow) {
            VLOG_ERR("%s: rte flow create offload error: %u : message : %s\n",
                     netdev_get_name(netdev), error.type, error.message);
            ret = -1;
            goto out;
        }
        info->is_hwol = false;
        ufid_hw_offload_add_rte_flow(ufid_hw_offload, flow,
                                             rte_port_phy_arr[i]->dpdk_port_id,
                                             0);
    }


out:
    free(rss);
    free_flow_patterns(&patterns);
    free_flow_actions(&actions);
    return ret;
}


int netdev_vport_flow_put(struct netdev * netdev , struct match * match,
              struct nlattr *actions OVS_UNUSED, size_t actions_len OVS_UNUSED,
              const ovs_u128 * ufid , struct offload_info * info,
              struct dpif_flow_stats * flow_stats  OVS_UNUSED)
{
    odp_port_t in_port = match->flow.in_port.odp_port;
    struct netdev_rte_port * rte_port = netdev_rte_port_search(in_port,
                                                            &vport_map);
    // TODO: Roni?
    /*if (netdev_dpdk_validate_flow(match)) {
        return -1;
    }*/

    if (rte_port != NULL) {
         switch (rte_port->rte_port_type) {
             case RTE_PORT_TYPE_VXLAN:
                   VLOG_DBG("vxlan offload ufid"UUID_FMT" \n",
                                      UUID_ARGS((struct uuid *)ufid));
                   if (netdev_vport_vxlan_add_rte_flow_offload(rte_port,
                           netdev, match, actions, actions_len, ufid, info,
                           flow_stats)) {
                       return -1;
                   }
                   break;
             case RTE_PORT_TYPE_DPDK:
                   VLOG_WARN("offload of vport could on dpdk port");
                   return -1;
             case RTE_PORT_TYPE_NONE:
             default:
                  VLOG_DBG("unsupported tunnel type");
                  return -1;
         }
    }

    return 0;
}
