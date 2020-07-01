/*
 * Copyright (c) 2015, 2016, 2017, 2019 Nicira, Inc.
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

#ifndef CONNTRACK_H
#define CONNTRACK_H 1

#include <stdbool.h>

#include "cmap.h"
#include "ct-dpif.h"
#include "latch.h"
#include "odp-netlink.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "ovs-atomic.h"
#include "ovs-thread.h"
#include "packets.h"
#include "hindex.h"

/* Userspace connection tracker
 * ============================
 *
 * This is a connection tracking module that keeps all the state in userspace.
 *
 * Usage
 * =====
 *
 *     struct conntrack *ct;
 *
 * Initialization:
 *
 *     ct = conntrack_init();
 *
 * To send a group of packets through the connection tracker:
 *
 *     conntrack_execute(ct, pkt_batch, ...);
 *
 * Thread-safety:
 *
 * conntrack_execute() can be called by multiple threads simultaneoulsy.
 *
 * Shutdown:
 *
 *    1/ Shutdown packet input to the datapath
 *    2/ Destroy PMD threads after quiescence.
 *    3/ conntrack_destroy(ct);
 */

struct dp_packet_batch;

struct conntrack;

union ct_addr {
    ovs_be32 ipv4;
    struct in6_addr ipv6;
};

struct ct_endpoint {
    union ct_addr addr;
    union {
        ovs_be16 port;
        struct {
            ovs_be16 icmp_id;
            uint8_t icmp_type;
            uint8_t icmp_code;
        };
    };
};

/* Verify that there is no padding in struct ct_endpoint, to facilitate
 * hashing in ct_endpoint_hash_add(). */
BUILD_ASSERT_DECL(sizeof(struct ct_endpoint) == sizeof(union ct_addr) + 4);

/* Changes to this structure need to be reflected in conn_key_hash()
 * and conn_key_cmp(). */
struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint16_t zone;
    uint8_t nw_proto;
};

enum nat_action_e {
    NAT_ACTION_SRC = 1 << 0,
    NAT_ACTION_SRC_PORT = 1 << 1,
    NAT_ACTION_DST = 1 << 2,
    NAT_ACTION_DST_PORT = 1 << 3,
};

struct nat_action_info_t {
    union ct_addr min_addr;
    union ct_addr max_addr;
    uint16_t min_port;
    uint16_t max_port;
    uint16_t nat_action;
};

enum ct_direction {
    CT_DIR_INIT,
    CT_DIR_REP,
    CT_DIR_NUM,
};

struct ct_flow_offload_item {
    int  op;
    ovs_u128 ufid;
    void *dp;
    uint32_t ctid;
    uint32_t *ctid_ptr;

    /* matches */
    odp_port_t odp_port;
    struct conn_key key;

    /* actions */
    uint8_t ct_state;
    ovs_u128 label_key;
    ovs_u128 label_mask;
    uint32_t mark_key;
    uint32_t mark_mask;

    struct {
        uint8_t mod_flags;
        struct conn_key  key;
    } nat;

    /* The value of status describes whether the connection is offloaded or
     * not.
     */
    int *status;

    /* refcnt is used to handle a scenario in which a connection issued an
     * offload request and was removed before the offload request is processed.
     */
    struct ovs_refcount *refcnt;
};

/* hw-offload callbacks */
struct conntrack_offload_class {
    void (*conn_get_ufid)(struct ct_flow_offload_item *, ovs_u128 *);
    void (*conn_add)(struct ct_flow_offload_item *);
    void (*conn_del)(struct ct_flow_offload_item *);
    bool (*conn_active)(struct ct_flow_offload_item *, long long now);
};

struct conntrack *conntrack_init(void *dp);
void conntrack_destroy(struct conntrack *);

int conntrack_execute(struct conntrack *ct, struct dp_packet_batch *pkt_batch,
                      ovs_be16 dl_type, bool force, bool commit, uint16_t zone,
                      bool e2e_cache_enabled, const uint32_t *setmark,
                      const struct ovs_key_ct_labels *setlabel,
                      ovs_be16 tp_src, ovs_be16 tp_dst, const char *helper,
                      const struct nat_action_info_t *nat_action_info,
                      long long now, uint32_t tp_id);
void conntrack_clear(struct dp_packet *packet);

struct conntrack_dump {
    struct conntrack *ct;
    unsigned bucket;
    struct cmap_position cm_pos;
    bool filter_zone;
    uint16_t zone;
};

struct conntrack_zone_limit {
    int32_t zone;
    uint32_t limit;
    uint32_t count;
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */
};

struct timeout_policy {
    struct hmap_node node;
    struct ct_dpif_timeout_policy policy;
};

enum {
    INVALID_ZONE = -2,
    DEFAULT_ZONE = -1, /* Default zone for zone limit management. */
    MIN_ZONE = 0,
    MAX_ZONE = 0xFFFF,
};

struct ct_dpif_entry;
struct ct_dpif_tuple;

int conntrack_dump_start(struct conntrack *, struct conntrack_dump *,
                         const uint16_t *pzone, int *);
int conntrack_dump_next(struct conntrack_dump *, struct ct_dpif_entry *);
int conntrack_dump_done(struct conntrack_dump *);

int conntrack_flush(struct conntrack *, const uint16_t *zone);
int conntrack_flush_tuple(struct conntrack *, const struct ct_dpif_tuple *,
                          uint16_t zone);
int conntrack_set_maxconns(struct conntrack *ct, uint32_t maxconns);
int conntrack_get_maxconns(struct conntrack *ct, uint32_t *maxconns);
int conntrack_get_nconns(struct conntrack *ct, uint32_t *nconns);
int conntrack_set_tcp_seq_chk(struct conntrack *ct, bool enabled);
bool conntrack_get_tcp_seq_chk(struct conntrack *ct);
struct ipf *conntrack_ipf_ctx(struct conntrack *ct);
struct conntrack_zone_limit zone_limit_get(struct conntrack *ct,
                                           int32_t zone);
int zone_limit_update(struct conntrack *ct, int32_t zone, uint32_t limit);
int zone_limit_delete(struct conntrack *ct, uint16_t zone);
void conntrack_init_offload_class(struct conntrack *,
                                  struct conntrack_offload_class *);

#endif /* conntrack.h */
