/*
 * Copyright (c) 2015-2019 Nicira, Inc.
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

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "cmap.h"
#include "conntrack.h"
#include "ct-dpif.h"
#include "ipf.h"
#include "openvswitch/hmap.h"
#include "openvswitch/list.h"
#include "openvswitch/types.h"
#include "packets.h"
#include "rculist.h"
#include "unaligned.h"
#include "dp-packet.h"

/* This is used for alg expectations; an expectation is a
 * context created in preparation for establishing a data
 * connection. The expectation is created by the control
 * connection. */
struct alg_exp_node {
    /* Node in alg_expectations. */
    struct hmap_node node;
    /* Node in alg_expectation_refs. */
    struct hindex_node node_ref;
    /* Key of data connection to be created. */
    struct conn_key key;
    /* Corresponding key of the control connection. */
    struct conn_key master_key;
    /* The NAT replacement address to be used by the data connection. */
    union ct_addr alg_nat_repl_addr;
    /* The data connection inherits the master control
     * connection label and mark. */
    ovs_u128 master_label;
    uint32_t master_mark;
    /* True if for NAT application, the alg replaces the dest address;
     * otherwise, the source address is replaced.  */
    bool nat_rpl_dst;
};

enum OVS_PACKED_ENUM ct_conn_type {
    CT_CONN_TYPE_DEFAULT,
    CT_CONN_TYPE_UN_NAT,
};

static inline int
ct_get_packet_dir(bool reply)
{
    return reply ? CT_DIR_REP : CT_DIR_INIT;
}

struct ct_dir_info {
    odp_port_t port;
    ovs_u128 ufid;
    void *dp;
    int status;
    uint8_t pkt_ct_state;
    bool e2e_flow;
    uint8_t e2e_seen_pkts;
};

enum ct_offload_flag {
    CT_OFFLOAD_NONE = 0,
    CT_OFFLOAD_INIT = 0x1 << 0,
    CT_OFFLOAD_REP  = 0x1 << 1,
    CT_OFFLOAD_SKIP = 0x1 << 2,
    CT_OFFLOAD_BOTH = (CT_OFFLOAD_INIT | CT_OFFLOAD_REP),
};

struct ct_offloads {
    uint8_t flags;
    struct ovs_refcount *refcnt;
    struct ct_dir_info dir_info[CT_DIR_NUM];
};

struct conn_exp_node {
    struct rculist node;
    struct conn *up;
};

struct conn {
    /* Immutable data. */
    struct conn_key key;
    struct conn_key rev_key;
    struct conn_key master_key; /* Only used for orig_tuple support. */
    struct conn_exp_node *exp;
    struct cmap_node cm_node;
    struct nat_action_info_t *nat_info;
    char *alg;
    struct conn *nat_conn; /* The NAT 'conn' context, if there is one. */
    struct conn *master_conn; /* The master 'conn' context if this is a NAT
                               * 'conn' */
    atomic_flag reclaimed; /* False during the lifetime of the connection,
                            * True as soon as a thread has started freeing
                            * its memory. */

    /* Mutable data. */
    struct ovs_mutex lock; /* Guards all mutable fields. */
    ovs_u128 label;
    atomic_llong expiration;
    long long prev_query;
    uint32_t mark;
    int seq_skew;

    /* Immutable data. */
    int32_t admit_zone; /* The zone for managing zone limit counts. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */

    /* Mutable data. */
    bool seq_skew_dir; /* TCP sequence skew direction due to NATTing of FTP
                        * control messages; true if reply direction. */
    bool cleaned; /* True if cleaned from expiry lists. */

    /* Immutable data. */
    bool alg_related; /* True if alg data connection. */
    enum ct_conn_type conn_type;

    uint32_t tp_id; /* Timeout policy ID. */
    struct ct_offloads offloads;
};

enum ct_update_res {
    CT_UPDATE_INVALID,
    CT_UPDATE_VALID,
    CT_UPDATE_NEW,
    CT_UPDATE_VALID_NEW,
};

/* Timeouts: all the possible timeout states passed to update_expiration()
 * are listed here. The name will be prefix by CT_TM_ and the value is in
 * milliseconds */
#define CT_TIMEOUTS \
    CT_TIMEOUT(TCP_FIRST_PACKET) \
    CT_TIMEOUT(TCP_OPENING) \
    CT_TIMEOUT(TCP_ESTABLISHED) \
    CT_TIMEOUT(TCP_CLOSING) \
    CT_TIMEOUT(TCP_FIN_WAIT) \
    CT_TIMEOUT(TCP_CLOSED) \
    CT_TIMEOUT(OTHER_FIRST) \
    CT_TIMEOUT(OTHER_MULTIPLE) \
    CT_TIMEOUT(OTHER_BIDIR) \
    CT_TIMEOUT(ICMP_FIRST) \
    CT_TIMEOUT(ICMP_REPLY)

enum ct_timeout {
#define CT_TIMEOUT(NAME) CT_TM_##NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
    N_CT_TM
};

struct conntrack {
    struct ovs_mutex ct_lock; /* Protects 2 following fields. */
    struct cmap conns OVS_GUARDED;
    struct rculist exp_lists[N_CT_TM] OVS_GUARDED;
    struct cmap zone_limits OVS_GUARDED;
    struct cmap timeout_policies OVS_GUARDED;

    uint32_t hash_basis; /* Salt for hashing a connection key. */
    pthread_t clean_thread; /* Periodically cleans up connection tracker. */
    struct latch clean_thread_exit; /* To destroy the 'clean_thread'. */

    /* Counting connections. */
    atomic_count n_conn; /* Number of connections currently tracked. */
    atomic_uint n_conn_limit; /* Max connections tracked. */

    /* Expectations for application level gateways (created by control
     * connections to help create data connections, e.g. for FTP). */
    struct ovs_rwlock resources_lock; /* Protects fields below. */
    struct hmap alg_expectations OVS_GUARDED; /* Holds struct
                                               * alg_exp_nodes. */
    struct hindex alg_expectation_refs OVS_GUARDED; /* For lookup from
                                                     * control context.  */

    struct ipf *ipf; /* Fragmentation handling context. */
    uint32_t zone_limit_seq; /* Used to disambiguate zone limit counts. */
    atomic_bool tcp_seq_chk; /* Check TCP sequence numbers. */
    void *dp; /* DP handler for offloads. */

    /* Holding HW offload callbacks */
    OVSRCU_TYPE(struct conntrack_offload_class *) offload_class;
};

/* Lock acquisition order:
 *    1. 'conn->lock'
 *    2. 'ct_lock'
 *    3. 'resources_lock'
 */

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;
extern struct ct_l4_proto ct_proto_icmp4;
extern struct ct_l4_proto ct_proto_icmp6;

struct ct_l4_proto {
    struct conn *(*new_conn)(struct conntrack *ct, struct dp_packet *pkt,
                             long long now, uint32_t tp_id);
    bool (*valid_new)(struct dp_packet *pkt);
    enum ct_update_res (*conn_update)(struct conntrack *ct, struct conn *conn,
                                      struct dp_packet *pkt, bool reply,
                                      long long now);
    void (*conn_get_protoinfo)(const struct conn *,
                               struct ct_dpif_protoinfo *);
    enum ct_timeout (*get_tm)(struct conn *conn);
};

static inline uint32_t
tcp_payload_length(struct dp_packet *pkt)
{
    const char *tcp_payload = dp_packet_get_tcp_payload(pkt);
    if (tcp_payload) {
        return ((char *) dp_packet_tail(pkt) - dp_packet_l2_pad_size(pkt)
                - tcp_payload);
    } else {
        return 0;
    }
}

#endif /* conntrack-private.h */
