/*
 * Copyright (c) 2009-2014, 2016-2018 Nicira, Inc.
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
#include "dpif-netdev.h"
#include "dpif-netdev-private.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bitmap.h"
#include "cmap.h"
#include "conntrack.h"
#include "conntrack-tp.h"
#include "coverage.h"
#include "ct-dpif.h"
#include "csum.h"
#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-lookup.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "dummy.h"
#include "fat-rwlock.h"
#include "flow.h"
#include "hmapx.h"
#include "id-pool.h"
#include "ipf.h"
#include "netdev.h"
#include "netdev-offload.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "odp-execute.h"
#include "odp-util.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"
#include "ovs-numa.h"
#include "ovs-rcu.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "pvector.h"
#include "random.h"
#include "mpsc-queue.h"
#include "seq.h"
#include "seq-pool.h"
#include "smap.h"
#include "sset.h"
#include "timeval.h"
#include "tnl-neigh-cache.h"
#include "tnl-ports.h"
#include "unixctl.h"
#include "util.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev);

/* Auto Load Balancing Defaults */
#define ALB_IMPROVEMENT_THRESHOLD    25
#define ALB_LOAD_THRESHOLD           95
#define ALB_REBALANCE_INTERVAL       1 /* 1 Min */
#define MIN_TO_MSEC                  60000

#define FLOW_DUMP_MAX_BATCH 50
/* Use per thread recirc_depth to prevent recirculation loop. */
#define MAX_RECIRC_DEPTH 6
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, recirc_depth, 0)

/* Use instant packet send by default. */
#define DEFAULT_TX_FLUSH_INTERVAL 0

/* Configuration parameters. */
enum { MAX_METERS = 65536 };    /* Maximum number of meters. */
enum { MAX_BANDS = 8 };         /* Maximum number of bands / meter. */
enum { N_METER_LOCKS = 64 };    /* Maximum number of meters. */

COVERAGE_DEFINE(datapath_drop_meter);
COVERAGE_DEFINE(datapath_drop_upcall_error);
COVERAGE_DEFINE(datapath_drop_lock_error);
COVERAGE_DEFINE(datapath_drop_userspace_action_error);
COVERAGE_DEFINE(datapath_drop_tunnel_push_error);
COVERAGE_DEFINE(datapath_drop_tunnel_pop_error);
COVERAGE_DEFINE(datapath_drop_recirc_error);
COVERAGE_DEFINE(datapath_drop_invalid_port);
COVERAGE_DEFINE(datapath_drop_invalid_bond);
COVERAGE_DEFINE(datapath_drop_invalid_tnl_port);
COVERAGE_DEFINE(datapath_drop_rx_invalid_packet);

/* Protects against changes to 'dp_netdevs'. */
static struct ovs_mutex dp_netdev_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct dp_netdev's. */
static struct shash dp_netdevs OVS_GUARDED_BY(dp_netdev_mutex)
    = SHASH_INITIALIZER(&dp_netdevs);

static struct vlog_rate_limit upcall_rl = VLOG_RATE_LIMIT_INIT(600, 600);

#define DP_NETDEV_CS_SUPPORTED_MASK (CS_NEW | CS_ESTABLISHED | CS_RELATED \
                                     | CS_INVALID | CS_REPLY_DIR | CS_TRACKED \
                                     | CS_SRC_NAT | CS_DST_NAT)
#define DP_NETDEV_CS_UNSUPPORTED_MASK (~(uint32_t)DP_NETDEV_CS_SUPPORTED_MASK)

static struct odp_support dp_netdev_support = {
    .max_vlan_headers = SIZE_MAX,
    .max_mpls_depth = SIZE_MAX,
    .recirc = true,
    .ct_state = true,
    .ct_zone = true,
    .ct_mark = true,
    .ct_label = true,
    .ct_state_nat = true,
    .ct_orig_tuple = true,
    .ct_orig_tuple6 = true,
};

static bool dp_netdev_e2e_cache_enabled = false;
#ifdef E2E_CACHE_ENABLED
static uint32_t dp_netdev_e2e_cache_size = 0;
#define E2E_CACHE_MAX_TRACE_Q_SIZE   (10000u)
static uint32_t dp_netdev_e2e_cache_trace_q_size = E2E_CACHE_MAX_TRACE_Q_SIZE;
#endif

/* EMC cache and SMC cache compose the datapath flow cache (DFC)
 *
 * Exact match cache for frequently used flows
 *
 * The cache uses a 32-bit hash of the packet (which can be the RSS hash) to
 * search its entries for a miniflow that matches exactly the miniflow of the
 * packet. It stores the 'dpcls_rule' (rule) that matches the miniflow.
 *
 * A cache entry holds a reference to its 'dp_netdev_flow'.
 *
 * A miniflow with a given hash can be in one of EM_FLOW_HASH_SEGS different
 * entries. The 32-bit hash is split into EM_FLOW_HASH_SEGS values (each of
 * them is EM_FLOW_HASH_SHIFT bits wide and the remainder is thrown away). Each
 * value is the index of a cache entry where the miniflow could be.
 *
 *
 * Signature match cache (SMC)
 *
 * This cache stores a 16-bit signature for each flow without storing keys, and
 * stores the corresponding 16-bit flow_table index to the 'dp_netdev_flow'.
 * Each flow thus occupies 32bit which is much more memory efficient than EMC.
 * SMC uses a set-associative design that each bucket contains
 * SMC_ENTRY_PER_BUCKET number of entries.
 * Since 16-bit flow_table index is used, if there are more than 2^16
 * dp_netdev_flow, SMC will miss them that cannot be indexed by a 16-bit value.
 *
 *
 * Thread-safety
 * =============
 *
 * Each pmd_thread has its own private exact match cache.
 * If dp_netdev_input is not called from a pmd thread, a mutex is used.
 */

#define EM_FLOW_HASH_SHIFT 13
#define EM_FLOW_HASH_ENTRIES (1u << EM_FLOW_HASH_SHIFT)
#define EM_FLOW_HASH_MASK (EM_FLOW_HASH_ENTRIES - 1)
#define EM_FLOW_HASH_SEGS 2

/* SMC uses a set-associative design. A bucket contains a set of entries that
 * a flow item can occupy. For now, it uses one hash function rather than two
 * as for the EMC design. */
#define SMC_ENTRY_PER_BUCKET 4
#define SMC_ENTRIES (1u << 20)
#define SMC_BUCKET_CNT (SMC_ENTRIES / SMC_ENTRY_PER_BUCKET)
#define SMC_MASK (SMC_BUCKET_CNT - 1)

/* Default EMC insert probability is 1 / DEFAULT_EM_FLOW_INSERT_INV_PROB */
#define DEFAULT_EM_FLOW_INSERT_INV_PROB 100
#define DEFAULT_EM_FLOW_INSERT_MIN (UINT32_MAX /                     \
                                    DEFAULT_EM_FLOW_INSERT_INV_PROB)

struct emc_entry {
    struct dp_netdev_flow *flow;
    struct netdev_flow_key key;   /* key.hash used for emc hash value. */
};

struct emc_cache {
    struct emc_entry entries[EM_FLOW_HASH_ENTRIES];
    int sweep_idx;                /* For emc_cache_slow_sweep(). */
};

struct smc_bucket {
    uint16_t sig[SMC_ENTRY_PER_BUCKET];
    uint16_t flow_idx[SMC_ENTRY_PER_BUCKET];
};

/* Signature match cache, differentiate from EMC cache */
struct smc_cache {
    struct smc_bucket buckets[SMC_BUCKET_CNT];
};

struct dfc_cache {
    struct emc_cache emc_cache;
    struct smc_cache smc_cache;
};

/* Iterate in the exact match cache through every entry that might contain a
 * miniflow with hash 'HASH'. */
#define EMC_FOR_EACH_POS_WITH_HASH(EMC, CURRENT_ENTRY, HASH)                 \
    for (uint32_t i__ = 0, srch_hash__ = (HASH);                             \
         (CURRENT_ENTRY) = &(EMC)->entries[srch_hash__ & EM_FLOW_HASH_MASK], \
         i__ < EM_FLOW_HASH_SEGS;                                            \
         i__++, srch_hash__ >>= EM_FLOW_HASH_SHIFT)

/* Simple non-wildcarding single-priority classifier. */

/* Time in microseconds between successive optimizations of the dpcls
 * subtable vector */
#define DPCLS_OPTIMIZATION_INTERVAL 1000000LL

/* Time in microseconds of the interval in which rxq processing cycles used
 * in rxq to pmd assignments is measured and stored. */
#define PMD_RXQ_INTERVAL_LEN 10000000LL

/* Number of intervals for which cycles are stored
 * and used during rxq to pmd assignment. */
#define PMD_RXQ_INTERVAL_MAX 6

/* Time in microseconds to try RCU quiescing. */
#define PMD_RCU_QUIESCE_INTERVAL 10000LL

struct dpcls {
    struct cmap_node node;      /* Within dp_netdev_pmd_thread.classifiers */
    odp_port_t in_port;
    struct cmap subtables_map;
    struct pvector subtables;
};

/* Data structure to keep packet order till fastpath processing. */
struct dp_packet_flow_map {
    struct dp_packet *packet;
    struct dp_netdev_flow *flow;
    uint16_t tcp_flags;
};

static void dpcls_init(struct dpcls *);
static void dpcls_destroy(struct dpcls *);
static void dpcls_sort_subtable_vector(struct dpcls *);
static uint32_t dpcls_subtable_lookup_reprobe(struct dpcls *cls);
static void dpcls_insert(struct dpcls *, struct dpcls_rule *,
                         const struct netdev_flow_key *mask);
static void dpcls_remove(struct dpcls *, struct dpcls_rule *);
static bool dpcls_lookup(struct dpcls *cls,
                         const struct netdev_flow_key *keys[],
                         struct dpcls_rule **rules, size_t cnt,
                         int *num_lookups_p);
static void dp_netdev_get_mega_ufid(const struct match *match,
                                    ovs_u128 *mega_ufid);
static void dp_netdev_fill_ct_match(struct match *match,
                                    const struct ct_match *ct_match);

/* Set of supported meter flags */
#define DP_SUPPORTED_METER_FLAGS_MASK \
    (OFPMF13_STATS | OFPMF13_PKTPS | OFPMF13_KBPS | OFPMF13_BURST)

/* Set of supported meter band types */
#define DP_SUPPORTED_METER_BAND_TYPES           \
    ( 1 << OFPMBT13_DROP )

struct dp_meter_band {
    uint32_t rate;
    uint32_t burst_size;
    uint64_t bucket; /* In 1/1000 packets (for PKTPS), or in bits (for KBPS) */
    uint64_t packet_count;
    uint64_t byte_count;
};

struct dp_meter {
    uint16_t flags;
    uint16_t n_bands;
    uint32_t max_delta_t;
    uint64_t used;
    uint64_t packet_count;
    uint64_t byte_count;
    struct dp_meter_band bands[];
};

struct pmd_auto_lb {
    bool auto_lb_requested;     /* Auto load balancing requested by user. */
    bool is_enabled;            /* Current status of Auto load balancing. */
    uint64_t rebalance_intvl;
    uint64_t rebalance_poll_timer;
    uint8_t rebalance_improve_thresh;
    atomic_uint8_t rebalance_load_thresh;
};

/* Datapath based on the network device interface from netdev.h.
 *
 *
 * Thread-safety
 * =============
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 *
 * Acquisition order is, from outermost to innermost:
 *
 *    dp_netdev_mutex (global)
 *    port_mutex
 *    bond_mutex
 *    non_pmd_mutex
 */
struct dp_netdev {
    const struct dpif_class *const class;
    const char *const name;
    struct ovs_refcount ref_cnt;
    atomic_flag destroyed;

    /* Ports.
     *
     * Any lookup into 'ports' or any access to the dp_netdev_ports found
     * through 'ports' requires taking 'port_rwlock'. */
    struct ovs_rwlock port_rwlock;
    struct hmap ports;
    struct seq *port_seq;       /* Incremented whenever a port changes. */

    /* The time that a packet can wait in output batch for sending. */
    atomic_uint32_t tx_flush_interval;

    /* Meters. */
    struct ovs_mutex meter_locks[N_METER_LOCKS];
    struct dp_meter *meters[MAX_METERS]; /* Meter bands. */

    /* Probability of EMC insertions is a factor of 'emc_insert_min'.*/
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) atomic_uint32_t emc_insert_min;
    /* Enable collection of PMD performance metrics. */
    atomic_bool pmd_perf_metrics;
    /* Enable the SMC cache from ovsdb config */
    atomic_bool smc_enable_db;

    /* Protects access to ofproto-dpif-upcall interface during revalidator
     * thread synchronization. */
    struct fat_rwlock upcall_rwlock;
    upcall_callback *upcall_cb;  /* Callback function for executing upcalls. */
    void *upcall_aux;

    /* Callback function for notifying the purging of dp flows (during
     * reseting pmd deletion). */
    dp_purge_callback *dp_purge_cb;
    void *dp_purge_aux;

    /* Stores all 'struct dp_netdev_pmd_thread's. */
    struct cmap poll_threads;
    /* id pool for per thread static_tx_qid. */
    struct id_pool *tx_qid_pool;
    struct ovs_mutex tx_qid_pool_mutex;
    /* Use measured cycles for rxq to pmd assignment. */
    bool pmd_rxq_assign_cyc;

    /* Protects the access of the 'struct dp_netdev_pmd_thread'
     * instance for non-pmd thread. */
    struct ovs_mutex non_pmd_mutex;

    /* Each pmd thread will store its pointer to
     * 'struct dp_netdev_pmd_thread' in 'per_pmd_key'. */
    ovsthread_key_t per_pmd_key;

    struct seq *reconfigure_seq;
    uint64_t last_reconfigure_seq;

    /* Cpu mask for pin of pmd threads. */
    char *pmd_cmask;

    uint64_t last_tnl_conf_seq;

    struct conntrack *conntrack;
    struct pmd_auto_lb pmd_alb;

    /* Bonds. */
    struct ovs_mutex bond_mutex; /* Protects updates of 'tx_bonds'. */
    struct cmap tx_bonds; /* Contains 'struct tx_bond'. */
};

static void meter_lock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_ACQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_lock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}

static void meter_unlock(const struct dp_netdev *dp, uint32_t meter_id)
    OVS_RELEASES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    ovs_mutex_unlock(&dp->meter_locks[meter_id % N_METER_LOCKS]);
}


static struct dp_netdev_port *dp_netdev_lookup_port(const struct dp_netdev *dp,
                                                    odp_port_t)
    OVS_REQ_WRLOCK(dp->port_rwlock);

enum rxq_cycles_counter_type {
    RXQ_CYCLES_PROC_CURR,       /* Cycles spent successfully polling and
                                   processing packets during the current
                                   interval. */
    RXQ_CYCLES_PROC_HIST,       /* Total cycles of all intervals that are used
                                   during rxq to pmd assignment. */
    RXQ_N_CYCLES
};

enum {
    DP_NETDEV_FLOW_OFFLOAD_OP_NONE,
    DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
    DP_NETDEV_FLOW_OFFLOAD_OP_MOD,
    DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
};

enum {
    DP_FLOW_OFFLOAD_ITEM = 1 << 0,
    DP_CT_OFFLOAD_ITEM = 1 << 1,
    DP_FLUSH_OFFLOAD_ITEM = 1 << 2,
};

struct dp_offload_flush_item {
    struct netdev *netdev;
    struct ovs_barrier *barrier;
};

struct dp_flow_offload_item {
    struct dp_netdev_flow *flow;
    int op;
    bool is_e2e_cache_flow;
    struct match match;
    struct nlattr *actions;
    size_t actions_len;
    uintptr_t ct_counter_key;
    struct flows_counter_key flows_counter_key;
};

union dp_offload_thread_data {
    struct dp_flow_offload_item flow_offload;
    struct ct_flow_offload_item ct_offload[CT_DIR_NUM];
    struct dp_offload_flush_item flush;
};

struct dp_offload_thread_item {
    struct mpsc_queue_node node;
    int type;
    struct dp_netdev *dp;
    union dp_offload_thread_data data[0];
};

struct dp_offload_thread {
    PADDED_MEMBERS(CACHE_LINE_SIZE,
        struct mpsc_queue queue;
        atomic_uint64_t enqueued_item;
        atomic_uint64_t ct_uni_dir_connections;
        atomic_uint64_t ct_bi_dir_connections;
        struct cmap megaflow_to_mark;
        struct cmap mark_to_flow;
    );
};

static struct dp_offload_thread *dp_offload_threads;
static void *dp_netdev_flow_offload_main(void *arg);

#define XPS_TIMEOUT 500000LL    /* In microseconds. */

/* Contained by struct dp_netdev_port's 'rxqs' member.  */
struct dp_netdev_rxq {
    struct dp_netdev_port *port;
    struct netdev_rxq *rx;
    unsigned core_id;                  /* Core to which this queue should be
                                          pinned. OVS_CORE_UNSPEC if the
                                          queue doesn't need to be pinned to a
                                          particular core. */
    unsigned intrvl_idx;               /* Write index for 'cycles_intrvl'. */
    struct dp_netdev_pmd_thread *pmd;  /* pmd thread that polls this queue. */
    bool is_vhost;                     /* Is rxq of a vhost port. */

    /* Counters of cycles spent successfully polling and processing pkts. */
    atomic_ullong cycles[RXQ_N_CYCLES];
    /* We store PMD_RXQ_INTERVAL_MAX intervals of data for an rxq and then
       sum them to yield the cycles used for an rxq. */
    atomic_ullong cycles_intrvl[PMD_RXQ_INTERVAL_MAX];
};

/* A port in a netdev-based datapath. */
struct dp_netdev_port {
    odp_port_t port_no;
    bool dynamic_txqs;          /* If true XPS will be used. */
    bool need_reconfigure;      /* True if we should reconfigure netdev. */
    struct netdev *netdev;
    struct hmap_node node;      /* Node in dp_netdev's 'ports'. */
    struct netdev_saved_flags *sf;
    struct dp_netdev_rxq *rxqs;
    unsigned n_rxq;             /* Number of elements in 'rxqs' */
    unsigned *txq_used;         /* Number of threads that use each tx queue. */
    struct ovs_mutex txq_used_mutex;
    bool emc_enabled;           /* If true EMC will be used. */
    char *type;                 /* Port type as requested by user. */
    char *rxq_affinity_list;    /* Requested affinity of rx queues. */
};

/* Contained by struct dp_netdev_flow's 'stats' member.  */
struct dp_netdev_flow_stats {
    atomic_llong used;             /* Last used time, in monotonic msecs. */
    atomic_ullong packet_count;    /* Number of packets matched. */
    atomic_ullong byte_count;      /* Number of bytes matched. */
    atomic_uint16_t tcp_flags;     /* Bitwise-OR of seen tcp_flags values. */
};

/* Contained by struct dp_netdev_flow's 'last_attrs' member.  */
struct dp_netdev_flow_attrs {
    atomic_bool offloaded;         /* True if flow is offloaded to HW. */
    ATOMIC(const char *) dp_layer; /* DP layer the flow is handled in. */
};

/* A flow in 'dp_netdev_pmd_thread's 'flow_table'.
 *
 *
 * Thread-safety
 * =============
 *
 * Except near the beginning or ending of its lifespan, rule 'rule' belongs to
 * its pmd thread's classifier.  The text below calls this classifier 'cls'.
 *
 * Motivation
 * ----------
 *
 * The thread safety rules described here for "struct dp_netdev_flow" are
 * motivated by two goals:
 *
 *    - Prevent threads that read members of "struct dp_netdev_flow" from
 *      reading bad data due to changes by some thread concurrently modifying
 *      those members.
 *
 *    - Prevent two threads making changes to members of a given "struct
 *      dp_netdev_flow" from interfering with each other.
 *
 *
 * Rules
 * -----
 *
 * A flow 'flow' may be accessed without a risk of being freed during an RCU
 * grace period.  Code that needs to hold onto a flow for a while
 * should try incrementing 'flow->ref_cnt' with dp_netdev_flow_ref().
 *
 * 'flow->ref_cnt' protects 'flow' from being freed.  It doesn't protect the
 * flow from being deleted from 'cls' and it doesn't protect members of 'flow'
 * from modification.
 *
 * Some members, marked 'const', are immutable.  Accessing other members
 * requires synchronization, as noted in more detail below.
 */
struct dp_netdev_flow {
    const struct flow flow;      /* Unmasked flow that created this entry. */
    /* Hash table index by unmasked flow. */
    const struct cmap_node node; /* In owning dp_netdev_pmd_thread's */
                                 /* 'flow_table'. */
    const struct cmap_node mark_node; /* In owning flow_mark's mark_to_flow */
    const ovs_u128 ufid;         /* Unique flow identifier. */
    const ovs_u128 mega_ufid;    /* Unique mega flow identifier. */
    const unsigned pmd_id;       /* The 'core_id' of pmd thread owning this */
                                 /* flow. */

    /* Number of references.
     * The classifier owns one reference.
     * Any thread trying to keep a rule from being freed should hold its own
     * reference. */
    struct ovs_refcount ref_cnt;

    bool dead;
    uint32_t mark;               /* Unique flow mark assigned to a flow */

    /* Statistics. */
    struct dp_netdev_flow_stats stats;

    /* Statistics and attributes received from the netdev offload provider. */
    atomic_int netdev_flow_get_result;
    struct dp_netdev_flow_stats last_stats;
    struct dp_netdev_flow_attrs last_attrs;

    /* Actions. */
    OVSRCU_TYPE(struct dp_netdev_actions *) actions;

    /* While processing a group of input packets, the datapath uses the next
     * member to store a pointer to the output batch for the flow.  It is
     * reset after the batch has been sent out (See dp_netdev_queue_batches(),
     * packet_batch_per_flow_init() and packet_batch_per_flow_execute()). */
    struct packet_batch_per_flow *batch;

    /* Packet classification. */
    char *dp_extra_info;         /* String to return in a flow dump/get. */
    struct dpcls_rule cr;        /* In owning dp_netdev's 'cls'. */
    /* 'cr' must be the last member. */
};

static void dp_netdev_flow_unref(struct dp_netdev_flow *);
static bool dp_netdev_flow_ref(struct dp_netdev_flow *);
static int dpif_netdev_flow_from_nlattrs(const struct nlattr *, uint32_t,
                                         struct flow *, bool);

/* A set of datapath actions within a "struct dp_netdev_flow".
 *
 *
 * Thread-safety
 * =============
 *
 * A struct dp_netdev_actions 'actions' is protected with RCU. */
struct dp_netdev_actions {
    /* These members are immutable: they do not change during the struct's
     * lifetime.  */
    unsigned int size;          /* Size of 'actions', in bytes. */
    struct nlattr actions[];    /* Sequence of OVS_ACTION_ATTR_* attributes. */
};

struct dp_netdev_actions *dp_netdev_actions_create(const struct nlattr *,
                                                   size_t);
struct dp_netdev_actions *dp_netdev_flow_get_actions(
    const struct dp_netdev_flow *);
static void dp_netdev_actions_free(struct dp_netdev_actions *);

struct polled_queue {
    struct dp_netdev_rxq *rxq;
    odp_port_t port_no;
    bool emc_enabled;
    bool rxq_enabled;
    uint64_t change_seq;
};

/* Contained by struct dp_netdev_pmd_thread's 'poll_list' member. */
struct rxq_poll {
    struct dp_netdev_rxq *rxq;
    struct hmap_node node;
};

/* Contained by struct dp_netdev_pmd_thread's 'send_port_cache',
 * 'tnl_port_cache' or 'tx_ports'. */
struct tx_port {
    struct dp_netdev_port *port;
    int qid;
    long long last_used;
    struct hmap_node node;
    long long flush_time;
    struct dp_packet_batch output_pkts;
    struct dp_netdev_rxq *output_pkts_rxqs[NETDEV_MAX_BURST];
};

/* Contained by struct tx_bond 'member_buckets'. */
struct member_entry {
    odp_port_t member_id;
    atomic_ullong n_packets;
    atomic_ullong n_bytes;
};

/* Contained by struct dp_netdev_pmd_thread's 'tx_bonds'. */
struct tx_bond {
    struct cmap_node node;
    uint32_t bond_id;
    struct member_entry member_buckets[BOND_BUCKETS];
};

/* A set of properties for the current processing loop that is not directly
 * associated with the pmd thread itself, but with the packets being
 * processed or the short-term system configuration (for example, time).
 * Contained by struct dp_netdev_pmd_thread's 'ctx' member. */
struct dp_netdev_pmd_thread_ctx {
    /* Latest measured time. See 'pmd_thread_ctx_time_update()'. */
    long long now;
    /* RX queue from which last packet was received. */
    struct dp_netdev_rxq *last_rxq;
    /* EMC insertion probability context for the current processing cycle. */
    uint32_t emc_insert_min;
};

/* PMD: Poll modes drivers.  PMD accesses devices via polling to eliminate
 * the performance overhead of interrupt processing.  Therefore netdev can
 * not implement rx-wait for these devices.  dpif-netdev needs to poll
 * these device to check for recv buffer.  pmd-thread does polling for
 * devices assigned to itself.
 *
 * DPDK used PMD for accessing NIC.
 *
 * Note, instance with cpu core id NON_PMD_CORE_ID will be reserved for
 * I/O of all non-pmd threads.  There will be no actual thread created
 * for the instance.
 *
 * Each struct has its own flow cache and classifier per managed ingress port.
 * For packets received on ingress port, a look up is done on corresponding PMD
 * thread's flow cache and in case of a miss, lookup is performed in the
 * corresponding classifier of port.  Packets are executed with the found
 * actions in either case.
 * */
struct dp_netdev_pmd_thread {
    struct dp_netdev *dp;
    struct ovs_refcount ref_cnt;    /* Every reference must be refcount'ed. */
    struct cmap_node node;          /* In 'dp->poll_threads'. */

    /* Per thread exact-match cache.  Note, the instance for cpu core
     * NON_PMD_CORE_ID can be accessed by multiple threads, and thusly
     * need to be protected by 'non_pmd_mutex'.  Every other instance
     * will only be accessed by its own pmd thread. */
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE) struct dfc_cache flow_cache;

    /* Flow-Table and classifiers
     *
     * Writers of 'flow_table' must take the 'flow_mutex'.  Corresponding
     * changes to 'classifiers' must be made while still holding the
     * 'flow_mutex'.
     */
    struct ovs_mutex flow_mutex;
    struct cmap flow_table OVS_GUARDED; /* Flow table. */

    /* One classifier per in_port polled by the pmd */
    struct cmap classifiers;
    /* Periodically sort subtable vectors according to hit frequencies */
    long long int next_optimization;
    /* End of the next time interval for which processing cycles
       are stored for each polled rxq. */
    long long int rxq_next_cycle_store;

    /* Last interval timestamp. */
    uint64_t intrvl_tsc_prev;
    /* Last interval cycles. */
    atomic_ullong intrvl_cycles;

    /* Current context of the PMD thread. */
    struct dp_netdev_pmd_thread_ctx ctx;

    struct seq *reload_seq;
    uint64_t last_reload_seq;

    /* These are atomic variables used as a synchronization and configuration
     * points for thread reload/exit.
     *
     * 'reload' atomic is the main one and it's used as a memory
     * synchronization point for all other knobs and data.
     *
     * For a thread that requests PMD reload:
     *
     *   * All changes that should be visible to the PMD thread must be made
     *     before setting the 'reload'.  These changes could use any memory
     *     ordering model including 'relaxed'.
     *   * Setting the 'reload' atomic should occur in the same thread where
     *     all other PMD configuration options updated.
     *   * Setting the 'reload' atomic should be done with 'release' memory
     *     ordering model or stricter.  This will guarantee that all previous
     *     changes (including non-atomic and 'relaxed') will be visible to
     *     the PMD thread.
     *   * To check that reload is done, thread should poll the 'reload' atomic
     *     to become 'false'.  Polling should be done with 'acquire' memory
     *     ordering model or stricter.  This ensures that PMD thread completed
     *     the reload process.
     *
     * For the PMD thread:
     *
     *   * PMD thread should read 'reload' atomic with 'acquire' memory
     *     ordering model or stricter.  This will guarantee that all changes
     *     made before setting the 'reload' in the requesting thread will be
     *     visible to the PMD thread.
     *   * All other configuration data could be read with any memory
     *     ordering model (including non-atomic and 'relaxed') but *only after*
     *     reading the 'reload' atomic set to 'true'.
     *   * When the PMD reload done, PMD should (optionally) set all the below
     *     knobs except the 'reload' to their default ('false') values and
     *     (mandatory), as the last step, set the 'reload' to 'false' using
     *     'release' memory ordering model or stricter.  This will inform the
     *     requesting thread that PMD has completed a reload cycle.
     */
    atomic_bool reload;             /* Do we need to reload ports? */
    atomic_bool wait_for_reload;    /* Can we busy wait for the next reload? */
    atomic_bool reload_tx_qid;      /* Do we need to reload static_tx_qid? */
    atomic_bool exit;               /* For terminating the pmd thread. */

    pthread_t thread;
    unsigned core_id;               /* CPU core id of this pmd thread. */
    int numa_id;                    /* numa node id of this pmd thread. */
    bool isolated;

    /* Queue id used by this pmd thread to send packets on all netdevs if
     * XPS disabled for this netdev. All static_tx_qid's are unique and less
     * than 'cmap_count(dp->poll_threads)'. */
    uint32_t static_tx_qid;

    /* Number of filled output batches. */
    int n_output_batches;

    struct ovs_mutex port_mutex;    /* Mutex for 'poll_list' and 'tx_ports'. */
    /* List of rx queues to poll. */
    struct hmap poll_list OVS_GUARDED;
    /* Map of 'tx_port's used for transmission.  Written by the main thread,
     * read by the pmd thread. */
    struct hmap tx_ports OVS_GUARDED;

    struct ovs_mutex bond_mutex;    /* Protects updates of 'tx_bonds'. */
    /* Map of 'tx_bond's used for transmission.  Written by the main thread
     * and read by the pmd thread. */
    struct cmap tx_bonds;

    /* These are thread-local copies of 'tx_ports'.  One contains only tunnel
     * ports (that support push_tunnel/pop_tunnel), the other contains ports
     * with at least one txq (that support send).  A port can be in both.
     *
     * There are two separate maps to make sure that we don't try to execute
     * OUTPUT on a device which has 0 txqs or PUSH/POP on a non-tunnel device.
     *
     * The instances for cpu core NON_PMD_CORE_ID can be accessed by multiple
     * threads, and thusly need to be protected by 'non_pmd_mutex'.  Every
     * other instance will only be accessed by its own pmd thread. */
    struct hmap tnl_port_cache;
    struct hmap send_port_cache;

    /* Keep track of detailed PMD performance statistics. */
    struct pmd_perf_stats perf_stats;

    /* Stats from previous iteration used by automatic pmd
     * load balance logic. */
    uint64_t prev_stats[PMD_N_STATS];
    atomic_count pmd_overloaded;

    /* Set to true if the pmd thread needs to be reloaded. */
    bool need_reload;

    /* Next time when PMD should try RCU quiescing. */
    long long next_rcu_quiesce;
};

/* Interface to netdev-based datapath. */
struct dpif_netdev {
    struct dpif dpif;
    struct dp_netdev *dp;
    uint64_t last_port_seq;
};

enum e2e_offload_state {
    E2E_OL_STATE_FLOW,
    E2E_OL_STATE_CT_SW,
    E2E_OL_STATE_CT_HW,
    E2E_OL_STATE_CT_MT_LOCAL,
    E2E_OL_STATE_CT_MT_ASYNC,
    E2E_OL_STATE_CT_ERR,
    E2E_OL_STATE_NUM,
};

static const char * const e2e_offload_state_names[] = {
    [E2E_OL_STATE_FLOW] = "E2E_OL_STATE_FLOW",
    [E2E_OL_STATE_CT_SW] = "E2E_OL_STATE_CT_SW",
    [E2E_OL_STATE_CT_HW] = "E2E_OL_STATE_CT_HW",
    [E2E_OL_STATE_CT_MT_LOCAL] = "E2E_OL_STATE_CT_MT_LOCAL",
    [E2E_OL_STATE_CT_MT_ASYNC] = "E2E_OL_STATE_CT_MT_ASYNC",
    [E2E_OL_STATE_CT_ERR] = "E2E_OL_STATE_CT_ERR",
    [E2E_OL_STATE_NUM] = "Unknown",
};

/*
 * A mapping from ufid to flow for e2e cache.
 */
struct e2e_cache_ovs_flow {
    struct hmap_node node;
    ovs_u128 ufid;
    struct nlattr *actions;
    struct e2e_cache_ovs_flow *ct_peer;
    struct ovs_refcount *mt_refcnt;
    enum e2e_offload_state offload_state;
    uint16_t actions_size;
    struct hmap merged_counters; /* Map of merged flows counters
                                    it is part of. */
    struct ovs_list associated_merged_flows;
    union {
        struct match match[0];
        struct ct_match ct_match[0];
    };
};

/* Helper struct for accessing a struct containing ovs_list array.
 * Containing struct
 *   |- Helper array
 *      [0] Helper item 0
 *          |- ovs_list item 0
 *          |- index (0)
 *      [1] Helper item 1
 *          |- ovs_list item 1
 *          |- index (1)
 * To access the containing struct from one of the ovs_list items:
 * 1. Get the helper item from the ovs_list item using
 *    helper item =
      CONTAINER_OF(ovs_list item, helper struct type, ovs_list field)
 * 2. Get the contining struct from the helper item and its index in the array:
 *    containing struct =
 *    CONTAINER_OF(helper item, containing struct type, helper field[index])
 */
struct flow2flow_item {
    struct ovs_list list;
    struct e2e_cache_ovs_flow *mt_flow;
    uint16_t index;
};

/*
 * Merged flow structure.
 */
struct e2e_cache_merged_flow {
    union {
        struct hmap_node in_hmap;
        struct ovs_list  in_list;
    } node;
    ovs_u128 ufid;
    struct dp_netdev *dp;
    struct nlattr *actions;
    uint16_t actions_size;
    uint16_t associated_flows_len;
    struct ovs_list flow_counter_list; /* Anchor for list of merged flows
                                          using the same flow counter. */
    struct ovs_list ct_counter_list; /* Anchor for list of merged flows
                                        using the same CT counter. */
    uintptr_t ct_counter_key;
    struct flows_counter_key flows_counter_key;
    struct match match;
    struct flow2flow_item associated_flows[0];
};

/* Counter object. */
struct e2e_cache_counter_item {
    struct hmap_node node;
    struct ovs_list merged_flows; /* List of merged flows using this counter. */
    size_t hash;
    bool is_ct;
    struct flows_counter_key key;
};

enum {
    E2E_SET_ETH_SRC = 1 << 0,
    E2E_SET_ETH_DST = 1 << 1,
    E2E_SET_ETH = E2E_SET_ETH_SRC | E2E_SET_ETH_DST,

    E2E_SET_IPV4_SRC = 1 << 2,
    E2E_SET_IPV4_DST = 1 << 3,
    E2E_SET_IPV4_TTL = 1 << 4,
    E2E_SET_IPV4 = E2E_SET_IPV4_SRC | E2E_SET_IPV4_DST | \
                   E2E_SET_IPV4_TTL,

    E2E_SET_IPV6_SRC = 1 << 5,
    E2E_SET_IPV6_DST = 1 << 6,
    E2E_SET_IPV6_HLMT = 1 << 7,
    E2E_SET_IPV6 = E2E_SET_IPV6_SRC | E2E_SET_IPV6_DST | \
                   E2E_SET_IPV6_HLMT,

    E2E_SET_UDP_SRC = 1 << 8,
    E2E_SET_UDP_DST = 1 << 9,
    E2E_SET_UDP = E2E_SET_UDP_SRC | E2E_SET_UDP_DST,

    E2E_SET_TCP_SRC = 1 << 10,
    E2E_SET_TCP_DST = 1 << 11,
    E2E_SET_TCP = E2E_SET_TCP_SRC | E2E_SET_TCP_DST,
};

struct e2e_cache_merged_set {
    struct ovs_key_ethernet eth;
    struct ovs_key_ipv4 ipv4;
    struct ovs_key_ipv6 ipv6;
    struct ovs_key_tcp tcp;
    struct ovs_key_udp udp;
    uint32_t flags;
};

static int get_port_by_number(struct dp_netdev *dp, odp_port_t port_no,
                              struct dp_netdev_port **portp)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static int get_port_by_name(struct dp_netdev *dp, const char *devname,
                            struct dp_netdev_port **portp)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static void dp_netdev_free(struct dp_netdev *)
    OVS_REQUIRES(dp_netdev_mutex);
static int do_add_port(struct dp_netdev *dp, const char *devname,
                       const char *type, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static void do_del_port(struct dp_netdev *dp, struct dp_netdev_port *)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static int dpif_netdev_open(const struct dpif_class *, const char *name,
                            bool create, struct dpif **);
static void dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                                      struct dp_packet_batch *,
                                      bool should_steal,
                                      const struct flow *flow,
                                      const struct nlattr *actions,
                                      size_t actions_len);
static void dp_netdev_input(struct dp_netdev_pmd_thread *,
                            struct dp_packet_batch *, odp_port_t port_no);
static void dp_netdev_recirculate(struct dp_netdev_pmd_thread *,
                                  struct dp_packet_batch *);

static void dp_netdev_disable_upcall(struct dp_netdev *);
static void dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd,
                                    struct dp_netdev *dp, unsigned core_id,
                                    int numa_id);
static void dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock);

static void *pmd_thread_main(void *);
static struct dp_netdev_pmd_thread *dp_netdev_get_pmd(struct dp_netdev *dp,
                                                      unsigned core_id);
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos);
static void dp_netdev_del_pmd(struct dp_netdev *dp,
                              struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd);
static void dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                     struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex);
static void dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                       struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex);
static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force);
static void dp_netdev_add_bond_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                                         struct tx_bond *bond, bool update)
    OVS_EXCLUDED(pmd->bond_mutex);
static void dp_netdev_del_bond_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                                           uint32_t bond_id)
    OVS_EXCLUDED(pmd->bond_mutex);

static void dp_netdev_offload_flush(struct dp_netdev *dp,
                                    struct dp_netdev_port *port);
static void dp_netdev_offload_barrier(struct dp_netdev *dp);

static void reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock);
static bool dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd);
static void dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd);
static void pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex);
static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt);
static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type);
static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                           unsigned long long cycles);
static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx);
static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge);
static int dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                                      struct tx_port *tx);
static inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port);

static inline bool emc_entry_alive(struct emc_entry *ce);
static void emc_clear_entry(struct emc_entry *ce);
static void smc_clear_entry(struct smc_bucket *b, int idx);

static void dp_netdev_request_reconfigure(struct dp_netdev *dp);
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd);
static void queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd,
                                  struct dp_netdev_flow *flow);
static bool
e2e_cache_get_merged_flows_stats(struct netdev *netdev,
                                 struct match *match,
                                 struct nlattr **actions,
                                 const ovs_u128 *mt_ufid,
                                 struct dpif_flow_stats *stats,
                                 struct ofpbuf *buf,
                                 long long now,
                                 long long prev_now);

static void
dp_netdev_offload_init(void)
{
    static struct ovsthread_once offload_thread_start =
                                                    OVSTHREAD_ONCE_INITIALIZER;
    unsigned int i;

    if (ovsthread_once_start(&offload_thread_start)) {
        dp_offload_threads = xcalloc(netdev_offload_thread_nb() +
                                     netdev_is_e2e_cache_enabled(),
                                     sizeof *dp_offload_threads);
        for (i = 0; i < netdev_offload_thread_nb(); i++) {
            mpsc_queue_init(&dp_offload_threads[i].queue);
            cmap_init(&dp_offload_threads[i].megaflow_to_mark);
            cmap_init(&dp_offload_threads[i].mark_to_flow);
            atomic_init(&dp_offload_threads[i].enqueued_item, 0);
            atomic_init(&dp_offload_threads[i].ct_uni_dir_connections, 0);
            atomic_init(&dp_offload_threads[i].ct_bi_dir_connections, 0);
            ovs_thread_create("hw_offload",
                              dp_netdev_flow_offload_main,
                              &dp_offload_threads[i]);
        }
        if (netdev_is_e2e_cache_enabled()) {
            atomic_init(&dp_offload_threads[i].enqueued_item, 0);
            atomic_init(&dp_offload_threads[i].ct_uni_dir_connections, 0);
            atomic_init(&dp_offload_threads[i].ct_bi_dir_connections, 0);
        }
        ovsthread_once_done(&offload_thread_start);
    }
}

static void
dp_netdev_append_ct_offload(struct ct_flow_offload_item *offload)
{
    struct dp_offload_thread_item *offload_item;
    unsigned int i;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    dp_netdev_offload_init();

    offload_item = xzalloc(sizeof *offload_item +
                           sizeof offload_item->data->ct_offload);
    offload_item->type = DP_CT_OFFLOAD_ITEM;
    memcpy(offload_item->data, offload,
           sizeof offload_item->data->ct_offload);
    offload_item->dp = offload->dp;

    /* Use a symmetrical ufid hash for the two CT directions,
     * to force-match thread-id on reverse direction. */
    i = netdev_offload_ufid_to_thread_id(
                                    ovs_u128_xor(offload[CT_DIR_INIT].ufid,
                                                 offload[CT_DIR_REP].ufid));
    mpsc_queue_insert(&dp_offload_threads[i].queue, &offload_item->node);
    atomic_count_inc64(&dp_offload_threads[i].enqueued_item);
}

static void
dp_netdev_ct_offload_get_ufid(struct ct_flow_offload_item *offload,
                              ovs_u128 *ufid)
{
    struct match match;

    dp_netdev_fill_ct_match(&match, &offload->ct_match);
    match.flow.in_port.odp_port = ODPP_NONE;
    dp_netdev_get_mega_ufid(&match, ufid);
}

typedef int
(*dp_netdev_ct_add_cb)(struct ct_flow_offload_item *offload,
                       struct dp_netdev *dp, struct ct_match *match,
                       struct nlattr *actions, int actions_len);
static int
dp_netdev_ct_add(struct ct_flow_offload_item *offload, struct dp_netdev *dp,
                 dp_netdev_ct_add_cb cb);
static int
dp_netdev_ct_e2e_add_cb(struct ct_flow_offload_item *offload,
                        struct dp_netdev *dp OVS_UNUSED,
                        struct ct_match *match,
                        struct nlattr *actions, int actions_len);
static void
dp_netdev_ct_offload_add_item(struct ct_flow_offload_item *offload)
{
    int dir;

    if (dp_netdev_e2e_cache_enabled) {
        for (dir = 0; dir < CT_DIR_NUM; dir++) {
            *offload[dir].status = 0;
        }
        return;
    }
    for (dir = 0; dir < CT_DIR_NUM; dir++) {
        offload[dir].op = DP_NETDEV_FLOW_OFFLOAD_OP_ADD;
        offload[dir].ct_actions_set = false;
    }
    dp_netdev_append_ct_offload(offload);
}

static void
dp_netdev_ct_offload_del_item(struct ct_flow_offload_item *offload)
{
    int dir;

    if (dp_netdev_e2e_cache_enabled) {
        free(offload[CT_DIR_INIT].refcnt);
        return;
    }
    for (dir = 0; dir < CT_DIR_NUM; dir++) {
        offload[dir].op = DP_NETDEV_FLOW_OFFLOAD_OP_DEL;
        offload[dir].ct_actions_set = false;
    }
    dp_netdev_append_ct_offload(offload);
}

static void
dp_netdev_ct_offload_e2e_add(struct ct_flow_offload_item *offload)
{
    dp_netdev_ct_add(offload, NULL, dp_netdev_ct_e2e_add_cb);
}

static int
dpif_netdev_get_flow_offload_status(const struct dp_netdev *dp,
                                    struct dp_netdev_flow *netdev_flow,
                                    struct dpif_flow_stats *stats,
                                    struct dpif_flow_attrs *attrs,
                                    long long now,
                                    long long prev_now);
static int
dp_netdev_ct_offload_active(struct ct_flow_offload_item *offload,
                            long long now, long long prev_now)
{
    struct dp_netdev_flow netdev_flow;
    struct dpif_flow_stats stats;
    struct dpif_flow_attrs attrs;
    int ret;

    /* if a direction is not offloaded do not attempt to query it from HW */
    if (!offload->dp) {
        return EINVAL;
    }
    memset(&netdev_flow, 0, sizeof netdev_flow);
    *CONST_CAST(odp_port_t *, &netdev_flow.flow.in_port.odp_port) =
        offload->ct_match.odp_port;
    *CONST_CAST(ovs_u128 *, &netdev_flow.mega_ufid) = offload->ufid;
    ret = dpif_netdev_get_flow_offload_status(offload->dp, &netdev_flow,
                                              &stats, &attrs, now, prev_now);
    if (ret) {
        return ret;
    }

    return stats.used >= now ? 0 : EINVAL;
}

static int
e2e_cache_flow_del(const ovs_u128 *ufid, struct dp_netdev *dp);
static void
dp_netdev_ct_offload_e2e_del(ovs_u128 *ufid, void *dp)
{
    e2e_cache_flow_del(ufid, dp);
}

static struct conntrack_offload_class dpif_ct_offload_class = {
    .conn_get_ufid = dp_netdev_ct_offload_get_ufid,
    .conn_add = dp_netdev_ct_offload_add_item,
    .conn_del = dp_netdev_ct_offload_del_item,
    .conn_active = dp_netdev_ct_offload_active,
    .conn_e2e_add = dp_netdev_ct_offload_e2e_add,
    .conn_e2e_del = dp_netdev_ct_offload_e2e_del,
};

static void
emc_cache_init(struct emc_cache *flow_cache)
{
    int i;

    flow_cache->sweep_idx = 0;
    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        flow_cache->entries[i].flow = NULL;
        flow_cache->entries[i].key.hash = 0;
        flow_cache->entries[i].key.len = sizeof(struct miniflow);
        flowmap_init(&flow_cache->entries[i].key.mf.map);
    }
}

static void
smc_cache_init(struct smc_cache *smc_cache)
{
    int i, j;
    for (i = 0; i < SMC_BUCKET_CNT; i++) {
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_cache->buckets[i].flow_idx[j] = UINT16_MAX;
        }
    }
}

static void
dfc_cache_init(struct dfc_cache *flow_cache)
{
    emc_cache_init(&flow_cache->emc_cache);
    smc_cache_init(&flow_cache->smc_cache);
}

static void
emc_cache_uninit(struct emc_cache *flow_cache)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(flow_cache->entries); i++) {
        emc_clear_entry(&flow_cache->entries[i]);
    }
}

static void
smc_cache_uninit(struct smc_cache *smc)
{
    int i, j;

    for (i = 0; i < SMC_BUCKET_CNT; i++) {
        for (j = 0; j < SMC_ENTRY_PER_BUCKET; j++) {
            smc_clear_entry(&(smc->buckets[i]), j);
        }
    }
}

static void
dfc_cache_uninit(struct dfc_cache *flow_cache)
{
    smc_cache_uninit(&flow_cache->smc_cache);
    emc_cache_uninit(&flow_cache->emc_cache);
}

/* Check and clear dead flow references slowly (one entry at each
 * invocation).  */
static void
emc_cache_slow_sweep(struct emc_cache *flow_cache)
{
    struct emc_entry *entry = &flow_cache->entries[flow_cache->sweep_idx];

    if (!emc_entry_alive(entry)) {
        emc_clear_entry(entry);
    }
    flow_cache->sweep_idx = (flow_cache->sweep_idx + 1) & EM_FLOW_HASH_MASK;
}

/* Updates the time in PMD threads context and should be called in three cases:
 *
 *     1. PMD structure initialization:
 *         - dp_netdev_configure_pmd()
 *
 *     2. Before processing of the new packet batch:
 *         - dpif_netdev_execute()
 *         - dp_netdev_process_rxq_port()
 *
 *     3. At least once per polling iteration in main polling threads if no
 *        packets received on current iteration:
 *         - dpif_netdev_run()
 *         - pmd_thread_main()
 *
 * 'pmd->ctx.now' should be used without update in all other cases if possible.
 */
static inline void
pmd_thread_ctx_time_update(struct dp_netdev_pmd_thread *pmd)
{
    pmd->ctx.now = time_usec();
}

/* Returns true if 'dpif' is a netdev or dummy dpif, false otherwise. */
bool
dpif_is_netdev(const struct dpif *dpif)
{
    return dpif->dpif_class->open == dpif_netdev_open;
}

static struct dpif_netdev *
dpif_netdev_cast(const struct dpif *dpif)
{
    ovs_assert(dpif_is_netdev(dpif));
    return CONTAINER_OF(dpif, struct dpif_netdev, dpif);
}

static struct dp_netdev *
get_dp_netdev(const struct dpif *dpif)
{
    return dpif_netdev_cast(dpif)->dp;
}

enum pmd_info_type {
    PMD_INFO_SHOW_STATS,  /* Show how cpu cycles are spent. */
    PMD_INFO_CLEAR_STATS, /* Set the cycles count to 0. */
    PMD_INFO_SHOW_RXQ,    /* Show poll lists of pmd threads. */
    PMD_INFO_PERF_SHOW,   /* Show pmd performance details. */
};

static void
format_pmd_thread(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    ds_put_cstr(reply, (pmd->core_id == NON_PMD_CORE_ID)
                        ? "main thread" : "pmd thread");
    if (pmd->numa_id != OVS_NUMA_UNSPEC) {
        ds_put_format(reply, " numa_id %d", pmd->numa_id);
    }
    if (pmd->core_id != OVS_CORE_UNSPEC && pmd->core_id != NON_PMD_CORE_ID) {
        ds_put_format(reply, " core_id %u", pmd->core_id);
    }
    ds_put_cstr(reply, ":\n");
}

static void
pmd_info_show_stats(struct ds *reply,
                    struct dp_netdev_pmd_thread *pmd)
{
    uint64_t stats[PMD_N_STATS];
    uint64_t total_cycles, total_packets;
    double passes_per_pkt = 0;
    double lookups_per_hit = 0;
    double packets_per_batch = 0;

    pmd_perf_read_counters(&pmd->perf_stats, stats);
    total_cycles = stats[PMD_CYCLES_ITER_IDLE]
                         + stats[PMD_CYCLES_ITER_BUSY];
    total_packets = stats[PMD_STAT_RECV];

    format_pmd_thread(reply, pmd);

    if (total_packets > 0) {
        passes_per_pkt = (total_packets + stats[PMD_STAT_RECIRC])
                            / (double) total_packets;
    }
    if (stats[PMD_STAT_MASKED_HIT] > 0) {
        lookups_per_hit = stats[PMD_STAT_MASKED_LOOKUP]
                            / (double) stats[PMD_STAT_MASKED_HIT];
    }
    if (stats[PMD_STAT_SENT_BATCHES] > 0) {
        packets_per_batch = stats[PMD_STAT_SENT_PKTS]
                            / (double) stats[PMD_STAT_SENT_BATCHES];
    }

    ds_put_format(reply,
                  "  packets received: %"PRIu64"\n"
                  "  packet recirculations: %"PRIu64"\n"
                  "  avg. datapath passes per packet: %.02f\n"
                  "  emc hits: %"PRIu64"\n"
                  "  smc hits: %"PRIu64"\n"
                  "  megaflow hits: %"PRIu64"\n"
                  "  avg. subtable lookups per megaflow hit: %.02f\n"
                  "  miss with success upcall: %"PRIu64"\n"
                  "  miss with failed upcall: %"PRIu64"\n"
                  "  avg. packets per output batch: %.02f\n",
                  total_packets, stats[PMD_STAT_RECIRC],
                  passes_per_pkt, stats[PMD_STAT_EXACT_HIT],
                  stats[PMD_STAT_SMC_HIT],
                  stats[PMD_STAT_MASKED_HIT], lookups_per_hit,
                  stats[PMD_STAT_MISS], stats[PMD_STAT_LOST],
                  packets_per_batch);

    if (total_cycles == 0) {
        return;
    }

    ds_put_format(reply,
                  "  idle cycles: %"PRIu64" (%.02f%%)\n"
                  "  processing cycles: %"PRIu64" (%.02f%%)\n",
                  stats[PMD_CYCLES_ITER_IDLE],
                  stats[PMD_CYCLES_ITER_IDLE] / (double) total_cycles * 100,
                  stats[PMD_CYCLES_ITER_BUSY],
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_cycles * 100);

    if (total_packets == 0) {
        return;
    }

    ds_put_format(reply,
                  "  avg cycles per packet: %.02f (%"PRIu64"/%"PRIu64")\n",
                  total_cycles / (double) total_packets,
                  total_cycles, total_packets);

    ds_put_format(reply,
                  "  avg processing cycles per packet: "
                  "%.02f (%"PRIu64"/%"PRIu64")\n",
                  stats[PMD_CYCLES_ITER_BUSY] / (double) total_packets,
                  stats[PMD_CYCLES_ITER_BUSY], total_packets);
}

static void
pmd_info_show_perf(struct ds *reply,
                   struct dp_netdev_pmd_thread *pmd,
                   struct pmd_perf_params *par)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        char *time_str =
                xastrftime_msec("%H:%M:%S.###", time_wall_msec(), true);
        long long now = time_msec();
        double duration = (now - pmd->perf_stats.start_ms) / 1000.0;

        ds_put_cstr(reply, "\n");
        ds_put_format(reply, "Time: %s\n", time_str);
        ds_put_format(reply, "Measurement duration: %.3f s\n", duration);
        ds_put_cstr(reply, "\n");
        format_pmd_thread(reply, pmd);
        ds_put_cstr(reply, "\n");
        pmd_perf_format_overall_stats(reply, &pmd->perf_stats, duration);
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Prevent parallel clearing of perf metrics. */
            ovs_mutex_lock(&pmd->perf_stats.clear_mutex);
            if (par->histograms) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_histograms(reply, &pmd->perf_stats);
            }
            if (par->iter_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_iteration_history(reply, &pmd->perf_stats,
                        par->iter_hist_len);
            }
            if (par->ms_hist_len > 0) {
                ds_put_cstr(reply, "\n");
                pmd_perf_format_ms_history(reply, &pmd->perf_stats,
                        par->ms_hist_len);
            }
            ovs_mutex_unlock(&pmd->perf_stats.clear_mutex);
        }
        free(time_str);
    }
}

static int
compare_poll_list(const void *a_, const void *b_)
{
    const struct rxq_poll *a = a_;
    const struct rxq_poll *b = b_;

    const char *namea = netdev_rxq_get_name(a->rxq->rx);
    const char *nameb = netdev_rxq_get_name(b->rxq->rx);

    int cmp = strcmp(namea, nameb);
    if (!cmp) {
        return netdev_rxq_get_queue_id(a->rxq->rx)
               - netdev_rxq_get_queue_id(b->rxq->rx);
    } else {
        return cmp;
    }
}

static void
sorted_poll_list(struct dp_netdev_pmd_thread *pmd, struct rxq_poll **list,
                 size_t *n)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct rxq_poll *ret, *poll;
    size_t i;

    *n = hmap_count(&pmd->poll_list);
    if (!*n) {
        ret = NULL;
    } else {
        ret = xcalloc(*n, sizeof *ret);
        i = 0;
        HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
            ret[i] = *poll;
            i++;
        }
        ovs_assert(i == *n);
        qsort(ret, *n, sizeof *ret, compare_poll_list);
    }

    *list = ret;
}

static void
pmd_info_show_rxq(struct ds *reply, struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id != NON_PMD_CORE_ID) {
        struct rxq_poll *list;
        size_t n_rxq;
        uint64_t total_cycles = 0;

        ds_put_format(reply,
                      "pmd thread numa_id %d core_id %u:\n  isolated : %s\n",
                      pmd->numa_id, pmd->core_id, (pmd->isolated)
                                                  ? "true" : "false");

        ovs_mutex_lock(&pmd->port_mutex);
        sorted_poll_list(pmd, &list, &n_rxq);

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;

        for (int i = 0; i < n_rxq; i++) {
            struct dp_netdev_rxq *rxq = list[i].rxq;
            const char *name = netdev_rxq_get_name(rxq->rx);
            uint64_t proc_cycles = 0;

            for (int j = 0; j < PMD_RXQ_INTERVAL_MAX; j++) {
                proc_cycles += dp_netdev_rxq_get_intrvl_cycles(rxq, j);
            }
            ds_put_format(reply, "  port: %-16s  queue-id: %2d", name,
                          netdev_rxq_get_queue_id(list[i].rxq->rx));
            ds_put_format(reply, " %s", netdev_rxq_enabled(list[i].rxq->rx)
                                        ? "(enabled) " : "(disabled)");
            ds_put_format(reply, "  pmd usage: ");
            if (total_cycles) {
                ds_put_format(reply, "%2"PRIu64"",
                              proc_cycles * 100 / total_cycles);
                ds_put_cstr(reply, " %");
            } else {
                ds_put_format(reply, "%s", "NOT AVAIL");
            }
            ds_put_cstr(reply, "\n");
        }
        ovs_mutex_unlock(&pmd->port_mutex);
        free(list);
    }
}

static int
compare_poll_thread_list(const void *a_, const void *b_)
{
    const struct dp_netdev_pmd_thread *a, *b;

    a = *(struct dp_netdev_pmd_thread **)a_;
    b = *(struct dp_netdev_pmd_thread **)b_;

    if (a->core_id < b->core_id) {
        return -1;
    }
    if (a->core_id > b->core_id) {
        return 1;
    }
    return 0;
}

/* Create a sorted list of pmd's from the dp->poll_threads cmap. We can use
 * this list, as long as we do not go to quiescent state. */
static void
sorted_poll_thread_list(struct dp_netdev *dp,
                        struct dp_netdev_pmd_thread ***list,
                        size_t *n)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (k >= n_pmds) {
            break;
        }
        pmd_list[k++] = pmd;
    }

    qsort(pmd_list, k, sizeof *pmd_list, compare_poll_thread_list);

    *list = pmd_list;
    *n = k;
}

static void
dpif_netdev_subtable_lookup_get(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[] OVS_UNUSED,
                                void *aux OVS_UNUSED)
{
    /* Get a list of all lookup functions. */
    struct dpcls_subtable_lookup_info_t *lookup_funcs = NULL;
    int32_t count = dpcls_subtable_lookup_info_get(&lookup_funcs);
    if (count < 0) {
        unixctl_command_reply_error(conn, "error getting lookup names");
        return;
    }

    /* Add all lookup functions to reply string. */
    struct ds reply = DS_EMPTY_INITIALIZER;
    ds_put_cstr(&reply, "Available lookup functions (priority : name)\n");
    for (int i = 0; i < count; i++) {
        ds_put_format(&reply, "  %d : %s\n", lookup_funcs[i].prio,
                      lookup_funcs[i].name);
    }
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_subtable_lookup_set(struct unixctl_conn *conn, int argc OVS_UNUSED,
                                const char *argv[], void *aux OVS_UNUSED)
{
    /* This function requires 2 parameters (argv[1] and argv[2]) to execute.
     *   argv[1] is subtable name
     *   argv[2] is priority
     */
    const char *func_name = argv[1];

    errno = 0;
    char *err_char;
    uint32_t new_prio = strtoul(argv[2], &err_char, 10);
    uint32_t lookup_dpcls_changed = 0;
    uint32_t lookup_subtable_changed = 0;
    struct shash_node *node;
    if (errno != 0 || new_prio > UINT8_MAX) {
        unixctl_command_reply_error(conn,
            "error converting priority, use integer in range 0-255\n");
        return;
    }

    int32_t err = dpcls_subtable_set_prio(func_name, new_prio);
    if (err) {
        unixctl_command_reply_error(conn,
            "error, subtable lookup function not found\n");
        return;
    }

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH (node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;

        /* Get PMD threads list, required to get DPCLS instances. */
        size_t n;
        struct dp_netdev_pmd_thread **pmd_list;
        sorted_poll_thread_list(dp, &pmd_list, &n);

        /* take port mutex as HMAP iters over them. */
        ovs_rwlock_rdlock(&dp->port_rwlock);

        for (size_t i = 0; i < n; i++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[i];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            struct dp_netdev_port *port = NULL;
            HMAP_FOR_EACH (port, node, &dp->ports) {
                odp_port_t in_port = port->port_no;
                struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
                if (!cls) {
                    continue;
                }
                uint32_t subtbl_changes = dpcls_subtable_lookup_reprobe(cls);
                if (subtbl_changes) {
                    lookup_dpcls_changed++;
                    lookup_subtable_changed += subtbl_changes;
                }
            }
        }

        /* release port mutex before netdev mutex. */
        ovs_rwlock_unlock(&dp->port_rwlock);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    struct ds reply = DS_EMPTY_INITIALIZER;
    ds_put_format(&reply,
        "Lookup priority change affected %d dpcls ports and %d subtables.\n",
        lookup_dpcls_changed, lookup_subtable_changed);
    const char *reply_str = ds_cstr(&reply);
    unixctl_command_reply(conn, reply_str);
    VLOG_INFO("%s", reply_str);
    ds_destroy(&reply);
}

static void
dpif_netdev_pmd_rebalance(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

    ovs_mutex_lock(&dp_netdev_mutex);

    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath */
        dp = shash_first(&dp_netdevs)->data;
    }

    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    dp_netdev_request_reconfigure(dp);
    ovs_mutex_unlock(&dp_netdev_mutex);
    ds_put_cstr(&reply, "pmd rxq rebalance requested.\n");
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
dpif_netdev_pmd_info(struct unixctl_conn *conn, int argc, const char *argv[],
                     void *aux)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev_pmd_thread **pmd_list;
    struct dp_netdev *dp = NULL;
    enum pmd_info_type type = *(enum pmd_info_type *) aux;
    unsigned int core_id;
    bool filter_on_pmd = false;
    size_t n;

    ovs_mutex_lock(&dp_netdev_mutex);

    while (argc > 1) {
        if (!strcmp(argv[1], "-pmd") && argc > 2) {
            if (str_to_uint(argv[2], 10, &core_id)) {
                filter_on_pmd = true;
            }
            argc -= 2;
            argv += 2;
        } else {
            dp = shash_find_data(&dp_netdevs, argv[1]);
            argc -= 1;
            argv += 1;
        }
    }

    if (!dp) {
        if (shash_count(&dp_netdevs) == 1) {
            /* There's only one datapath */
            dp = shash_first(&dp_netdevs)->data;
        } else {
            ovs_mutex_unlock(&dp_netdev_mutex);
            unixctl_command_reply_error(conn,
                                        "please specify an existing datapath");
            return;
        }
    }

    sorted_poll_thread_list(dp, &pmd_list, &n);
    for (size_t i = 0; i < n; i++) {
        struct dp_netdev_pmd_thread *pmd = pmd_list[i];
        if (!pmd) {
            break;
        }
        if (filter_on_pmd && pmd->core_id != core_id) {
            continue;
        }
        if (type == PMD_INFO_SHOW_RXQ) {
            pmd_info_show_rxq(&reply, pmd);
        } else if (type == PMD_INFO_CLEAR_STATS) {
            pmd_perf_stats_clear(&pmd->perf_stats);
        } else if (type == PMD_INFO_SHOW_STATS) {
            pmd_info_show_stats(&reply, pmd);
        } else if (type == PMD_INFO_PERF_SHOW) {
            pmd_info_show_perf(&reply, pmd, (struct pmd_perf_params *)aux);
        }
    }
    free(pmd_list);

    ovs_mutex_unlock(&dp_netdev_mutex);

    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}

static void
pmd_perf_show_cmd(struct unixctl_conn *conn, int argc,
                          const char *argv[],
                          void *aux OVS_UNUSED)
{
    struct pmd_perf_params par;
    long int it_hist = 0, ms_hist = 0;
    par.histograms = true;

    while (argc > 1) {
        if (!strcmp(argv[1], "-nh")) {
            par.histograms = false;
            argc -= 1;
            argv += 1;
        } else if (!strcmp(argv[1], "-it") && argc > 2) {
            it_hist = strtol(argv[2], NULL, 10);
            if (it_hist < 0) {
                it_hist = 0;
            } else if (it_hist > HISTORY_LEN) {
                it_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else if (!strcmp(argv[1], "-ms") && argc > 2) {
            ms_hist = strtol(argv[2], NULL, 10);
            if (ms_hist < 0) {
                ms_hist = 0;
            } else if (ms_hist > HISTORY_LEN) {
                ms_hist = HISTORY_LEN;
            }
            argc -= 2;
            argv += 2;
        } else {
            break;
        }
    }
    par.iter_hist_len = it_hist;
    par.ms_hist_len = ms_hist;
    par.command_type = PMD_INFO_PERF_SHOW;
    dpif_netdev_pmd_info(conn, argc, argv, &par);
}

static void
dpif_netdev_bond_show(struct unixctl_conn *conn, int argc,
                      const char *argv[], void *aux OVS_UNUSED)
{
    struct ds reply = DS_EMPTY_INITIALIZER;
    struct dp_netdev *dp = NULL;

    ovs_mutex_lock(&dp_netdev_mutex);
    if (argc == 2) {
        dp = shash_find_data(&dp_netdevs, argv[1]);
    } else if (shash_count(&dp_netdevs) == 1) {
        /* There's only one datapath. */
        dp = shash_first(&dp_netdevs)->data;
    }
    if (!dp) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn,
                                    "please specify an existing datapath");
        return;
    }

    if (cmap_count(&dp->tx_bonds) > 0) {
        struct tx_bond *dp_bond_entry;

        ds_put_cstr(&reply, "Bonds:\n");
        CMAP_FOR_EACH (dp_bond_entry, node, &dp->tx_bonds) {
            ds_put_format(&reply, "  bond-id %"PRIu32":\n",
                          dp_bond_entry->bond_id);
            for (int bucket = 0; bucket < BOND_BUCKETS; bucket++) {
                uint32_t member_id = odp_to_u32(
                    dp_bond_entry->member_buckets[bucket].member_id);
                ds_put_format(&reply,
                              "    bucket %d - member %"PRIu32"\n",
                              bucket, member_id);
            }
        }
    }
    ovs_mutex_unlock(&dp_netdev_mutex);
    unixctl_command_reply(conn, ds_cstr(&reply));
    ds_destroy(&reply);
}


static int
dpif_netdev_init(void)
{
    static enum pmd_info_type show_aux = PMD_INFO_SHOW_STATS,
                              clear_aux = PMD_INFO_CLEAR_STATS,
                              poll_aux = PMD_INFO_SHOW_RXQ;

    unixctl_command_register("dpif-netdev/pmd-stats-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&show_aux);
    unixctl_command_register("dpif-netdev/pmd-stats-clear", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&clear_aux);
    unixctl_command_register("dpif-netdev/pmd-rxq-show", "[-pmd core] [dp]",
                             0, 3, dpif_netdev_pmd_info,
                             (void *)&poll_aux);
    unixctl_command_register("dpif-netdev/pmd-perf-show",
                             "[-nh] [-it iter-history-len]"
                             " [-ms ms-history-len]"
                             " [-pmd core] [dp]",
                             0, 8, pmd_perf_show_cmd,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-rxq-rebalance", "[dp]",
                             0, 1, dpif_netdev_pmd_rebalance,
                             NULL);
    unixctl_command_register("dpif-netdev/pmd-perf-log-set",
                             "on|off [-b before] [-a after] [-e|-ne] "
                             "[-us usec] [-q qlen]",
                             0, 10, pmd_perf_log_set_cmd,
                             NULL);
    unixctl_command_register("dpif-netdev/bond-show", "[dp]",
                             0, 1, dpif_netdev_bond_show,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-prio-set",
                             "[lookup_func] [prio]",
                             2, 2, dpif_netdev_subtable_lookup_set,
                             NULL);
    unixctl_command_register("dpif-netdev/subtable-lookup-prio-get", "",
                             0, 0, dpif_netdev_subtable_lookup_get,
                             NULL);
    return 0;
}

static int
dpif_netdev_enumerate(struct sset *all_dps,
                      const struct dpif_class *dpif_class)
{
    struct shash_node *node;

    ovs_mutex_lock(&dp_netdev_mutex);
    SHASH_FOR_EACH(node, &dp_netdevs) {
        struct dp_netdev *dp = node->data;
        if (dpif_class != dp->class) {
            /* 'dp_netdevs' contains both "netdev" and "dummy" dpifs.
             * If the class doesn't match, skip this dpif. */
             continue;
        }
        sset_add(all_dps, node->name);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return 0;
}

static bool
dpif_netdev_class_is_dummy(const struct dpif_class *class)
{
    return class != &dpif_netdev_class;
}

static const char *
dpif_netdev_port_open_type(const struct dpif_class *class, const char *type)
{
    return strcmp(type, "internal") ? type
                  : dpif_netdev_class_is_dummy(class) ? "dummy-internal"
                  : "tap";
}

static struct dpif *
create_dpif_netdev(struct dp_netdev *dp)
{
    uint16_t netflow_id = hash_string(dp->name, 0);
    struct dpif_netdev *dpif;

    ovs_refcount_ref(&dp->ref_cnt);

    dpif = xmalloc(sizeof *dpif);
    dpif_init(&dpif->dpif, dp->class, dp->name, netflow_id >> 8, netflow_id);
    dpif->dp = dp;
    dpif->last_port_seq = seq_read(dp->port_seq);

    return &dpif->dpif;
}

/* Choose an unused, non-zero port number and return it on success.
 * Return ODPP_NONE on failure. */
static odp_port_t
choose_port(struct dp_netdev *dp, const char *name)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    uint32_t port_no;

    if (dp->class != &dpif_netdev_class) {
        const char *p;
        int start_no = 0;

        /* If the port name begins with "br", start the number search at
         * 100 to make writing tests easier. */
        if (!strncmp(name, "br", 2)) {
            start_no = 100;
        }

        /* If the port name contains a number, try to assign that port number.
         * This can make writing unit tests easier because port numbers are
         * predictable. */
        for (p = name; *p != '\0'; p++) {
            if (isdigit((unsigned char) *p)) {
                port_no = start_no + strtol(p, NULL, 10);
                if (port_no > 0 && port_no != odp_to_u32(ODPP_NONE)
                    && !dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
                    return u32_to_odp(port_no);
                }
                break;
            }
        }
    }

    for (port_no = 1; port_no <= UINT16_MAX; port_no++) {
        if (!dp_netdev_lookup_port(dp, u32_to_odp(port_no))) {
            return u32_to_odp(port_no);
        }
    }

    return ODPP_NONE;
}

static int
create_dp_netdev(const char *name, const struct dpif_class *class,
                 struct dp_netdev **dpp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    static struct ovsthread_once tsc_freq_check = OVSTHREAD_ONCE_INITIALIZER;
    struct dp_netdev *dp;
    int error;

    /* Avoid estimating TSC frequency for dummy datapath to not slow down
     * unit tests. */
    if (!dpif_netdev_class_is_dummy(class)
        && ovsthread_once_start(&tsc_freq_check)) {
        pmd_perf_estimate_tsc_frequency();
        ovsthread_once_done(&tsc_freq_check);
    }

    dp = xzalloc(sizeof *dp);
    shash_add(&dp_netdevs, name, dp);

    *CONST_CAST(const struct dpif_class **, &dp->class) = class;
    *CONST_CAST(const char **, &dp->name) = xstrdup(name);
    ovs_refcount_init(&dp->ref_cnt);
    atomic_flag_clear(&dp->destroyed);

    ovs_rwlock_init(&dp->port_rwlock);
    hmap_init(&dp->ports);
    dp->port_seq = seq_create();
    ovs_mutex_init(&dp->bond_mutex);
    cmap_init(&dp->tx_bonds);

    fat_rwlock_init(&dp->upcall_rwlock);

    dp->reconfigure_seq = seq_create();
    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    for (int i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_init_adaptive(&dp->meter_locks[i]);
    }

    /* Disable upcalls by default. */
    dp_netdev_disable_upcall(dp);
    dp->upcall_aux = NULL;
    dp->upcall_cb = NULL;

    dp->conntrack = conntrack_init(dp);
    conntrack_init_offload_class(dp->conntrack, &dpif_ct_offload_class);

    atomic_init(&dp->emc_insert_min, DEFAULT_EM_FLOW_INSERT_MIN);
    atomic_init(&dp->tx_flush_interval, DEFAULT_TX_FLUSH_INTERVAL);

    cmap_init(&dp->poll_threads);
    dp->pmd_rxq_assign_cyc = true;

    ovs_mutex_init(&dp->tx_qid_pool_mutex);
    /* We need 1 Tx queue for each possible core + 1 for non-PMD threads. */
    dp->tx_qid_pool = id_pool_create(0, ovs_numa_get_n_cores() + 1);

    ovs_mutex_init_recursive(&dp->non_pmd_mutex);
    ovsthread_key_create(&dp->per_pmd_key, NULL);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    /* non-PMD will be created before all other threads and will
     * allocate static_tx_qid = 0. */
    dp_netdev_set_nonpmd(dp);

    error = do_add_port(dp, name, dpif_netdev_port_open_type(dp->class,
                                                             "internal"),
                        ODPP_LOCAL);
    ovs_rwlock_unlock(&dp->port_rwlock);
    if (error) {
        dp_netdev_free(dp);
        return error;
    }

    dp->last_tnl_conf_seq = seq_read(tnl_conf_seq);
    *dpp = dp;
    return 0;
}

static void
dp_netdev_request_reconfigure(struct dp_netdev *dp)
{
    seq_change(dp->reconfigure_seq);
}

static bool
dp_netdev_is_reconf_required(struct dp_netdev *dp)
{
    return seq_read(dp->reconfigure_seq) != dp->last_reconfigure_seq;
}

static int
dpif_netdev_open(const struct dpif_class *class, const char *name,
                 bool create, struct dpif **dpifp)
{
    struct dp_netdev *dp;
    int error;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, name);
    if (!dp) {
        error = create ? create_dp_netdev(name, class, &dp) : ENODEV;
    } else {
        error = (dp->class != class ? EINVAL
                 : create ? EEXIST
                 : 0);
    }
    if (!error) {
        *dpifp = create_dpif_netdev(dp);
    }
    ovs_mutex_unlock(&dp_netdev_mutex);

    return error;
}

static void
dp_netdev_destroy_upcall_lock(struct dp_netdev *dp)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    /* Check that upcalls are disabled, i.e. that the rwlock is taken */
    ovs_assert(fat_rwlock_tryrdlock(&dp->upcall_rwlock));

    /* Before freeing a lock we should release it */
    fat_rwlock_unlock(&dp->upcall_rwlock);
    fat_rwlock_destroy(&dp->upcall_rwlock);
}

static void
dp_delete_meter(struct dp_netdev *dp, uint32_t meter_id)
    OVS_REQUIRES(dp->meter_locks[meter_id % N_METER_LOCKS])
{
    if (dp->meters[meter_id]) {
        free(dp->meters[meter_id]);
        dp->meters[meter_id] = NULL;
    }
}

static uint32_t
hash_bond_id(uint32_t bond_id)
{
    return hash_int(bond_id, 0);
}

/* Requires dp_netdev_mutex so that we can't get a new reference to 'dp'
 * through the 'dp_netdevs' shash while freeing 'dp'. */
static void
dp_netdev_free(struct dp_netdev *dp)
    OVS_REQUIRES(dp_netdev_mutex)
{
    struct dp_netdev_port *port, *next;
    struct tx_bond *bond;

    shash_find_and_delete(&dp_netdevs, dp->name);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    HMAP_FOR_EACH_SAFE (port, next, node, &dp->ports) {
        do_del_port(dp, port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    ovs_mutex_lock(&dp->bond_mutex);
    CMAP_FOR_EACH (bond, node, &dp->tx_bonds) {
        cmap_remove(&dp->tx_bonds, &bond->node, hash_bond_id(bond->bond_id));
        ovsrcu_postpone(free, bond);
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    dp_netdev_destroy_all_pmds(dp, true);
    cmap_destroy(&dp->poll_threads);

    ovs_mutex_destroy(&dp->tx_qid_pool_mutex);
    id_pool_destroy(dp->tx_qid_pool);

    ovs_mutex_destroy(&dp->non_pmd_mutex);
    ovsthread_key_delete(dp->per_pmd_key);

    conntrack_destroy(dp->conntrack);
    /* Wait for all CT offload del to resolve before continuing
     * to destroy the datapath. */
    dp_netdev_offload_barrier(dp);

    seq_destroy(dp->reconfigure_seq);

    seq_destroy(dp->port_seq);
    hmap_destroy(&dp->ports);
    ovs_rwlock_destroy(&dp->port_rwlock);

    cmap_destroy(&dp->tx_bonds);
    ovs_mutex_destroy(&dp->bond_mutex);

    /* Upcalls must be disabled at this point */
    dp_netdev_destroy_upcall_lock(dp);

    int i;

    for (i = 0; i < MAX_METERS; ++i) {
        meter_lock(dp, i);
        dp_delete_meter(dp, i);
        meter_unlock(dp, i);
    }
    for (i = 0; i < N_METER_LOCKS; ++i) {
        ovs_mutex_destroy(&dp->meter_locks[i]);
    }

    free(dp->pmd_cmask);
    free(CONST_CAST(char *, dp->name));
    free(dp);
}

static void
dp_netdev_unref(struct dp_netdev *dp)
{
    if (dp) {
        /* Take dp_netdev_mutex so that, if dp->ref_cnt falls to zero, we can't
         * get a new reference to 'dp' through the 'dp_netdevs' shash. */
        ovs_mutex_lock(&dp_netdev_mutex);
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            dp_netdev_free(dp);
        }
        ovs_mutex_unlock(&dp_netdev_mutex);
    }
}

static void
dpif_netdev_close(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    dp_netdev_unref(dp);
    free(dpif);
}

static int
dpif_netdev_destroy(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (!atomic_flag_test_and_set(&dp->destroyed)) {
        if (ovs_refcount_unref_relaxed(&dp->ref_cnt) == 1) {
            /* Can't happen: 'dpif' still owns a reference to 'dp'. */
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

/* Add 'n' to the atomic variable 'var' non-atomically and using relaxed
 * load/store semantics.  While the increment is not atomic, the load and
 * store operations are, making it impossible to read inconsistent values.
 *
 * This is used to update thread local stats counters. */
static void
non_atomic_ullong_add(atomic_ullong *var, unsigned long long n)
{
    unsigned long long tmp;

    atomic_read_relaxed(var, &tmp);
    tmp += n;
    atomic_store_relaxed(var, tmp);
}

static int
dpif_netdev_get_stats(const struct dpif *dpif, struct dpif_dp_stats *stats)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    uint64_t pmd_stats[PMD_N_STATS];

    stats->n_flows = stats->n_hit = stats->n_missed = stats->n_lost = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        stats->n_flows += cmap_count(&pmd->flow_table);
        pmd_perf_read_counters(&pmd->perf_stats, pmd_stats);
        stats->n_hit += pmd_stats[PMD_STAT_EXACT_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_SMC_HIT];
        stats->n_hit += pmd_stats[PMD_STAT_MASKED_HIT];
        stats->n_missed += pmd_stats[PMD_STAT_MISS];
        stats->n_lost += pmd_stats[PMD_STAT_LOST];
    }
    stats->n_masks = UINT32_MAX;
    stats->n_mask_hit = UINT64_MAX;

    return 0;
}

static void
dp_netdev_reload_pmd__(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&pmd->dp->non_pmd_mutex);
        ovs_mutex_lock(&pmd->port_mutex);
        pmd_load_cached_ports(pmd);
        ovs_mutex_unlock(&pmd->port_mutex);
        ovs_mutex_unlock(&pmd->dp->non_pmd_mutex);
        return;
    }

    seq_change(pmd->reload_seq);
    atomic_store_explicit(&pmd->reload, true, memory_order_release);
}

static uint32_t
hash_port_no(odp_port_t port_no)
{
    return hash_int(odp_to_u32(port_no), 0);
}

static int
port_create(const char *devname, const char *type,
            odp_port_t port_no, struct dp_netdev_port **portp)
{
    struct dp_netdev_port *port;
    enum netdev_flags flags;
    struct netdev *netdev;
    int error;

    *portp = NULL;

    /* Open and validate network device. */
    error = netdev_open(devname, type, &netdev);
    if (error) {
        return error;
    }
    /* XXX reject non-Ethernet devices */

    netdev_get_flags(netdev, &flags);
    if (flags & NETDEV_LOOPBACK) {
        VLOG_ERR("%s: cannot add a loopback device", devname);
        error = EINVAL;
        goto out;
    }

    port = xzalloc(sizeof *port);
    port->port_no = port_no;
    port->netdev = netdev;
    port->type = xstrdup(type);
    port->sf = NULL;
    port->emc_enabled = true;
    port->need_reconfigure = true;
    ovs_mutex_init(&port->txq_used_mutex);

    *portp = port;

    return 0;

out:
    netdev_close(netdev);
    return error;
}

static int
do_add_port(struct dp_netdev *dp, const char *devname, const char *type,
            odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct netdev_saved_flags *sf;
    struct dp_netdev_port *port;
    int error;

    /* Reject devices already in 'dp'. */
    if (!get_port_by_name(dp, devname, &port)) {
        return EEXIST;
    }

    error = port_create(devname, type, port_no, &port);
    if (error) {
        return error;
    }

    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

    /* Check that port was successfully configured. */
    if (!dp_netdev_lookup_port(dp, port_no)) {
        return EINVAL;
    }

    /* Updating device flags triggers an if_notifier, which triggers a bridge
     * reconfiguration and another attempt to add this port, leading to an
     * infinite loop if the device is configured incorrectly and cannot be
     * added.  Setting the promisc mode after a successful reconfiguration,
     * since we already know that the device is somehow properly configured. */
    error = netdev_turn_flags_on(port->netdev, NETDEV_PROMISC, &sf);
    if (error) {
        VLOG_ERR("%s: cannot set promisc flag", devname);
        do_del_port(dp, port);
        return error;
    }
    port->sf = sf;

    return 0;
}

static int
dpif_netdev_port_add(struct dpif *dpif, struct netdev *netdev,
                     odp_port_t *port_nop)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    char namebuf[NETDEV_VPORT_NAME_BUFSIZE];
    const char *dpif_port;
    odp_port_t port_no;
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    dpif_port = netdev_vport_get_dpif_port(netdev, namebuf, sizeof namebuf);
    if (*port_nop != ODPP_NONE) {
        port_no = *port_nop;
        error = dp_netdev_lookup_port(dp, *port_nop) ? EBUSY : 0;
    } else {
        port_no = choose_port(dp, dpif_port);
        error = port_no == ODPP_NONE ? EFBIG : 0;
    }
    if (!error) {
        *port_nop = port_no;
        error = do_add_port(dp, dpif_port, netdev_get_type(netdev), port_no);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static int
dpif_netdev_port_del(struct dpif *dpif, odp_port_t port_no)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    if (port_no == ODPP_LOCAL) {
        error = EINVAL;
    } else {
        struct dp_netdev_port *port;

        error = get_port_by_number(dp, port_no, &port);
        if (!error) {
            do_del_port(dp, port);
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static bool
is_valid_port_number(odp_port_t port_no)
{
    return port_no != ODPP_NONE;
}

static struct dp_netdev_port *
dp_netdev_lookup_port(const struct dp_netdev *dp, odp_port_t port_no)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, node, hash_port_no(port_no), &dp->ports) {
        if (port->port_no == port_no) {
            return port;
        }
    }
    return NULL;
}

static int
get_port_by_number(struct dp_netdev *dp,
                   odp_port_t port_no, struct dp_netdev_port **portp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    if (!is_valid_port_number(port_no)) {
        *portp = NULL;
        return EINVAL;
    } else {
        *portp = dp_netdev_lookup_port(dp, port_no);
        return *portp ? 0 : ENODEV;
    }
}

static void
port_destroy(struct dp_netdev_port *port)
{
    if (!port) {
        return;
    }

    netdev_close(port->netdev);
    netdev_restore_flags(port->sf);

    for (unsigned i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
    }
    ovs_mutex_destroy(&port->txq_used_mutex);
    free(port->rxq_affinity_list);
    free(port->txq_used);
    free(port->rxqs);
    free(port->type);
    free(port);
}

static int
get_port_by_name(struct dp_netdev *dp,
                 const char *devname, struct dp_netdev_port **portp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!strcmp(netdev_get_name(port->netdev), devname)) {
            *portp = port;
            return 0;
        }
    }

    /* Callers of dpif_netdev_port_query_by_name() expect ENODEV for a non
     * existing port. */
    return ENODEV;
}

/* Returns 'true' if there is a port with pmd netdev. */
static bool
has_pmd_port(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_pmd(port->netdev)) {
            return true;
        }
    }

    return false;
}

static void
do_del_port(struct dp_netdev *dp, struct dp_netdev_port *port)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    /* Blocking call, will finish only once all flow offload have
     * been removed from the port. The port cannot be destroyed before
     * its hardware has been cleaned.
     */
    ovs_rwlock_unlock(&dp->port_rwlock);
    dp_netdev_offload_flush(dp, port);
    ovs_rwlock_wrlock(&dp->port_rwlock);
    netdev_uninit_flow_api(port->netdev);

    hmap_remove(&dp->ports, &port->node);
    seq_change(dp->port_seq);

    reconfigure_datapath(dp);

    port_destroy(port);
}

static void
answer_port_query(const struct dp_netdev_port *port,
                  struct dpif_port *dpif_port)
{
    dpif_port->name = xstrdup(netdev_get_name(port->netdev));
    dpif_port->type = xstrdup(port->type);
    dpif_port->port_no = port->port_no;
}

static int
dpif_netdev_port_query_by_number(const struct dpif *dpif, odp_port_t port_no,
                                 struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = get_port_by_number(dp, port_no, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static int
dpif_netdev_port_query_by_name(const struct dpif *dpif, const char *devname,
                               struct dpif_port *dpif_port)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = get_port_by_name(dp, devname, &port);
    if (!error && dpif_port) {
        answer_port_query(port, dpif_port);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return error;
}

static void
dp_netdev_flow_free(struct dp_netdev_flow *flow)
{
    struct dp_netdev_actions *actions = dp_netdev_flow_get_actions(flow);

    if (actions) {
        dp_netdev_actions_free(actions);
    }
    if (flow->dp_extra_info) {
        free(flow->dp_extra_info);
    }
    free(flow);
}

static void dp_netdev_flow_unref(struct dp_netdev_flow *flow)
{
    if (ovs_refcount_unref_relaxed(&flow->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_flow_free, flow);
    }
}

static uint32_t
dp_netdev_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

static inline struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port)
{
    struct dpcls *cls;
    uint32_t hash = hash_port_no(in_port);
    CMAP_FOR_EACH_WITH_HASH (cls, node, hash, &pmd->classifiers) {
        if (cls->in_port == in_port) {
            /* Port classifier exists already */
            return cls;
        }
    }
    return NULL;
}

static inline struct dpcls *
dp_netdev_pmd_find_dpcls(struct dp_netdev_pmd_thread *pmd,
                         odp_port_t in_port)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct dpcls *cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    uint32_t hash = hash_port_no(in_port);

    if (!cls) {
        /* Create new classifier for in_port */
        cls = xmalloc(sizeof(*cls));
        dpcls_init(cls);
        cls->in_port = in_port;
        cmap_insert(&pmd->classifiers, &cls->node, hash);
        VLOG_DBG("Creating dpcls %p for in_port %d", cls, in_port);
    }
    return cls;
}

struct megaflow_to_mark_data {
    const struct cmap_node node;
    ovs_u128 mega_ufid;
    uint32_t mark;
};

/* associate megaflow with a mark, which is a 1:1 mapping */
static void
megaflow_to_mark_associate(const ovs_u128 *mega_ufid, uint32_t mark)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data = xzalloc(sizeof(*data));
    unsigned int tid = netdev_offload_thread_id();

    data->mega_ufid = *mega_ufid;
    data->mark = mark;

    cmap_insert(&dp_offload_threads[tid].megaflow_to_mark,
                CONST_CAST(struct cmap_node *, &data->node), hash);
}

/* disassociate meagaflow with a mark */
static void
megaflow_to_mark_disassociate(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = netdev_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &dp_offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            cmap_remove(&dp_offload_threads[tid].megaflow_to_mark,
                        CONST_CAST(struct cmap_node *, &data->node), hash);
            ovsrcu_postpone(free, data);
            return;
        }
    }

    VLOG_WARN("Masked ufid "UUID_FMT" is not associated with a mark?\n",
              UUID_ARGS((struct uuid *)mega_ufid));
}

static inline uint32_t
megaflow_to_mark_find(const ovs_u128 *mega_ufid)
{
    size_t hash = dp_netdev_flow_hash(mega_ufid);
    struct megaflow_to_mark_data *data;
    unsigned int tid = netdev_offload_thread_id();

    CMAP_FOR_EACH_WITH_HASH (data, node, hash,
                             &dp_offload_threads[tid].megaflow_to_mark) {
        if (ovs_u128_equals(*mega_ufid, data->mega_ufid)) {
            return data->mark;
        }
    }

    VLOG_DBG("Mark id for ufid "UUID_FMT" was not found\n",
             UUID_ARGS((struct uuid *)mega_ufid));
    return INVALID_FLOW_MARK;
}

/* associate mark with a flow, which is 1:N mapping */
static void
mark_to_flow_associate(const uint32_t mark, struct dp_netdev_flow *flow)
{
    unsigned int tid = netdev_offload_thread_id();

    dp_netdev_flow_ref(flow);

    cmap_insert(&dp_offload_threads[tid].mark_to_flow,
                CONST_CAST(struct cmap_node *, &flow->mark_node),
                hash_int(mark, 0));
    flow->mark = mark;

    VLOG_DBG("Associated dp_netdev flow %p with mark %u mega_ufid "UUID_FMT,
             flow, mark, UUID_ARGS((struct uuid *) &flow->mega_ufid));
}

static bool
flow_mark_has_no_ref(uint32_t mark)
{
    unsigned int tid = netdev_offload_thread_id();
    struct dp_netdev_flow *flow;

    CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash_int(mark, 0),
                             &dp_offload_threads[tid].mark_to_flow) {
        if (flow->mark == mark) {
            return false;
        }
    }

    return true;
}

static int
mark_to_flow_disassociate(struct dp_offload_thread_item *offload_item)
{
    bool is_e2e_cache_flow = offload_item->data->flow_offload.is_e2e_cache_flow;
    struct dp_netdev_flow *flow = offload_item->data->flow_offload.flow;
    unsigned int tid = netdev_offload_thread_id();
    uint32_t mark = flow->mark;
    int ret = 0;

    if (!is_e2e_cache_flow) {
        struct cmap_node *mark_node;

        /* INVALID_FLOW_MARK may mean that the flow has been disassociated
         * or never associated.
         */
        if (OVS_UNLIKELY(mark == INVALID_FLOW_MARK)) {
            return EINVAL;
        }

        mark_node = CONST_CAST(struct cmap_node *, &flow->mark_node);
        cmap_remove(&dp_offload_threads[tid].mark_to_flow, mark_node,
                    hash_int(mark, 0));
    }
    flow->mark = INVALID_FLOW_MARK;

    /*
     * no flow is referencing the mark any more? If so, let's
     * remove the flow from hardware and free the mark. Always remove from
     * hardware in case of E2E cache flow.
     */
    if (is_e2e_cache_flow || flow_mark_has_no_ref(mark)) {
        const char *dpif_type_str =
            dpif_normalize_type(offload_item->dp->class->type);
        odp_port_t in_port = flow->flow.in_port.odp_port;
        struct netdev *port;

        port = netdev_ports_get(in_port, dpif_type_str);
        if (port) {
            /* Taking a global 'port_rwlock' to fulfill thread safety
             * restrictions regarding netdev port mapping. */
            ovs_rwlock_rdlock(&offload_item->dp->port_rwlock);
            ret = netdev_flow_del(port, &flow->mega_ufid, NULL);
            ovs_rwlock_unlock(&offload_item->dp->port_rwlock);
            netdev_close(port);
        }

        if (!is_e2e_cache_flow) {
            netdev_offload_flow_mark_free(mark);
            VLOG_DBG("Freed flow mark %u\n", mark);

            megaflow_to_mark_disassociate(&flow->mega_ufid);
        }
    }
    if (!is_e2e_cache_flow) {
        dp_netdev_flow_unref(flow);
    }

    return ret;
}

static void
flow_mark_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *flow;
    size_t i;

    dp_netdev_offload_init();

    for (i = 0; i < netdev_offload_thread_nb(); i++) {
        struct dp_offload_thread *ofl_thread = &dp_offload_threads[i];

        CMAP_FOR_EACH (flow, mark_node, &ofl_thread->mark_to_flow) {
            if (flow->pmd_id == pmd->core_id) {
                queue_netdev_flow_del(pmd, flow);
            }
        }
    }
}

static struct dp_netdev_flow *
mark_to_flow_find(const struct dp_netdev_pmd_thread *pmd,
                  const uint32_t mark)
{
    struct dp_netdev_flow *flow;
    size_t hash;
    size_t i;

    dp_netdev_offload_init();

    hash = hash_int(mark, 0);
    for (i = 0; i < netdev_offload_thread_nb(); i++) {
        struct dp_offload_thread *ofl_thread = &dp_offload_threads[i];

        CMAP_FOR_EACH_WITH_HASH (flow, mark_node, hash,
                                 &ofl_thread->mark_to_flow) {
            if (flow->mark == mark && flow->pmd_id == pmd->core_id &&
                flow->dead == false) {
                return flow;
            }
        }
    }

    return NULL;
}

static struct dp_flow_offload_item *
dp_netdev_alloc_flow_offload(struct dp_netdev_pmd_thread *pmd,
                             struct dp_netdev_flow *flow,
                             int op)
{
    struct dp_offload_thread_item *offload_item;
    struct dp_flow_offload_item *offload;

    offload_item = xzalloc(sizeof *offload_item +
                           sizeof offload_item->data->flow_offload);
    offload_item->dp = pmd->dp;
    offload_item->type = DP_FLOW_OFFLOAD_ITEM;

    offload = &offload_item->data->flow_offload;
    offload->flow = flow;
    offload->op = op;
    offload->is_e2e_cache_flow = false;

    dp_netdev_flow_ref(flow);

    return offload;
}

static void
dp_netdev_flow_offload_free(struct dp_offload_thread_item *offload_item)
{
    struct dp_flow_offload_item *flow_offload =
                                            &offload_item->data->flow_offload;

    free(flow_offload->actions);
    free(offload_item);
}

static void
dp_netdev_ct_offload_free(struct dp_offload_thread_item *offload_item)
{
    struct ct_flow_offload_item *ct_offload = offload_item->data->ct_offload;

    if (ct_offload[CT_DIR_INIT].ct_actions_set) {
        free(ct_offload[CT_DIR_INIT].actions);
    }
    if (ct_offload[CT_DIR_REP].ct_actions_set) {
        free(ct_offload[CT_DIR_REP].actions);
    }

    free(offload_item);
}

static void
dp_netdev_offload_item_unref(struct dp_offload_thread_item *offload_item)
{
    switch (offload_item->type) {
    case DP_FLOW_OFFLOAD_ITEM:
        dp_netdev_flow_unref(offload_item->data->flow_offload.flow);
        ovsrcu_postpone(dp_netdev_flow_offload_free, offload_item);
        break;
    case DP_CT_OFFLOAD_ITEM:
        ovsrcu_postpone(dp_netdev_ct_offload_free, offload_item);
        break;
    case DP_FLUSH_OFFLOAD_ITEM:
        free(offload_item);
        break;
    default:
        OVS_NOT_REACHED();
    }
}

static void
dp_netdev_append_flow_offload(struct dp_flow_offload_item *offload)
{
    struct dp_offload_thread_item *offload_item = CONTAINER_OF(offload,
            struct dp_offload_thread_item, data);
    unsigned int i;

    dp_netdev_offload_init();
    i = netdev_offload_ufid_to_thread_id(offload->flow->mega_ufid);
    mpsc_queue_insert(&dp_offload_threads[i].queue, &offload_item->node);
    atomic_count_inc64(&dp_offload_threads[i].enqueued_item);
}

static int
dp_netdev_flow_offload_del(struct dp_offload_thread_item *offload_item)
{
    return mark_to_flow_disassociate(offload_item);
}

/*
 * There are two flow offload operations here: addition and modification.
 *
 * For flow addition, this function does:
 * - allocate a new flow mark id
 * - perform hardware flow offload
 * - associate the flow mark with flow and mega flow
 *
 * For flow modification, both flow mark and the associations are still
 * valid, thus only item 2 needed.
 */
static int
dp_netdev_flow_offload_put(struct dp_offload_thread_item *offload_item)
{
    struct dp_flow_offload_item *offload = &offload_item->data->flow_offload;
    struct dp_netdev_flow *flow = offload->flow;
    odp_port_t in_port = flow->flow.in_port.odp_port;
    const char *dpif_type_str = dpif_normalize_type(offload_item->dp->class->type);
    bool modification = offload->op == DP_NETDEV_FLOW_OFFLOAD_OP_MOD
                        && flow->mark != INVALID_FLOW_MARK;
    bool is_e2e_cache_flow = offload->is_e2e_cache_flow;
    struct offload_info info;
    struct netdev *port;
    uint32_t mark;
    int ret;

    if (flow->dead) {
        return -1;
    }

    if (is_e2e_cache_flow) {
        mark = INVALID_FLOW_MARK;
    } else {
        if (modification) {
            mark = flow->mark;
        } else {
            /*
             * If a mega flow has already been offloaded (from other PMD
             * instances), do not offload it again.
             */
            mark = megaflow_to_mark_find(&flow->mega_ufid);
            if (mark != INVALID_FLOW_MARK) {
                VLOG_DBG("Flow has already been offloaded with mark %u\n",
                         mark);
                if (flow->mark != INVALID_FLOW_MARK) {
                    ovs_assert(flow->mark == mark);
                } else {
                    mark_to_flow_associate(mark, flow);
                }
                return 0;
            }

            mark = netdev_offload_flow_mark_alloc();
            if (mark == INVALID_FLOW_MARK) {
                VLOG_ERR("Failed to allocate flow mark!\n");
                return -1;
            }
        }
    }

    info.flow_mark = mark;
    info.is_e2e_cache_flow = is_e2e_cache_flow;
    info.ct_counter_key = offload->ct_counter_key;
    memcpy(&info.flows_counter_key, &offload->flows_counter_key,
           sizeof offload->flows_counter_key);

    port = netdev_ports_get(in_port, dpif_type_str);
    if (!port) {
        goto err_free;
    }
    /* Taking a global 'port_rwlock' to fulfill thread safety
     * restrictions regarding the netdev port mapping. */
    ovs_rwlock_rdlock(&offload_item->dp->port_rwlock);
    ret = netdev_flow_put(port, &offload->match,
                          CONST_CAST(struct nlattr *, offload->actions),
                          offload->actions_len, &flow->mega_ufid, &info,
                          NULL);
    ovs_rwlock_unlock(&offload_item->dp->port_rwlock);
    netdev_close(port);

    if (ret) {
        goto err_free;
    }

    if (!modification) {
        if (!is_e2e_cache_flow) {
            megaflow_to_mark_associate(&flow->mega_ufid, mark);
            mark_to_flow_associate(mark, flow);
        } else {
            flow->mark = INVALID_FLOW_MARK;
        }
    }
    return 0;

err_free:
    if (!is_e2e_cache_flow) {
        if (!modification) {
            netdev_offload_flow_mark_free(mark);
        } else {
            mark_to_flow_disassociate(offload_item);
        }
    }
    return -1;
}

static void
dp_netdev_fill_ct_match(struct match *match, const struct ct_match *ct_match)
{
    memset(match, 0, sizeof *match);
    if (ct_match->key.dl_type == htons(ETH_TYPE_IP)) {
        /* Fill in ipv4 5-tuples */
        match->flow.nw_src = ct_match->key.src.addr.ipv4;
        match->flow.nw_dst = ct_match->key.dst.addr.ipv4;
        match->wc.masks.nw_src = OVS_BE32_MAX;
        match->wc.masks.nw_dst = OVS_BE32_MAX;
    } else {
        /* Fill in ipv6 5-tuples */
        memcpy(&match->flow.ipv6_src,
               &ct_match->key.src.addr.ipv6,
               sizeof match->flow.ipv6_src);
        memcpy(&match->flow.ipv6_dst,
               &ct_match->key.dst.addr.ipv6,
               sizeof match->flow.ipv6_dst);
        memset(&match->wc.masks.ipv6_src, 0xFF,
                sizeof match->wc.masks.ipv6_src);
        memset(&match->wc.masks.ipv6_dst, 0xFF,
                sizeof match->wc.masks.ipv6_dst);
    }
    match->flow.dl_type = ct_match->key.dl_type;
    match->flow.nw_proto = ct_match->key.nw_proto;
    match->wc.masks.dl_type = OVS_BE16_MAX;
    match->wc.masks.nw_proto = UINT8_MAX;
    if (match->flow.nw_proto == IPPROTO_TCP) {
        match->wc.masks.tcp_flags = htons(TCP_RST | TCP_FIN);
    }
    if (match->flow.nw_proto == IPPROTO_TCP ||
        match->flow.nw_proto == IPPROTO_UDP) {
        match->flow.tp_src = ct_match->key.src.port;
        match->flow.tp_dst = ct_match->key.dst.port;
        match->wc.masks.tp_src = OVS_BE16_MAX;
        match->wc.masks.tp_dst = OVS_BE16_MAX;
    }
    match->flow.ct_zone = ct_match->key.zone;
    match->wc.masks.ct_zone = UINT16_MAX;
    match->flow.in_port.odp_port = ct_match->odp_port;
    match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
}

static void
dp_netdev_create_ct_actions(struct ofpbuf *buf,
                            struct ct_flow_offload_item *offload)
{
    size_t offset;
    char helper[] = "offl,st(0x  ),id_key(0x                )";
    char s[17];
    char *end;

    if (offload->nat.mod_flags) {
        offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_SET_MASKED);
        if (offload->ct_match.key.dl_type == htons(ETH_TYPE_IP)) {
            struct ovs_key_ipv4 *ipv4_key = NULL, *ipv4_mask = NULL;

            if (offload->nat.mod_flags & NAT_ACTION_SRC ||
                offload->nat.mod_flags & NAT_ACTION_DST) {
                ipv4_key = nl_msg_put_unspec_zero(buf, OVS_KEY_ATTR_IPV4,
                                                  2 * sizeof *ipv4_key);
                ipv4_mask = ipv4_key + 1;
            }
            if (offload->nat.mod_flags & NAT_ACTION_SRC) {
                ipv4_key->ipv4_src = offload->nat.key.src.addr.ipv4;
                ipv4_mask->ipv4_src = OVS_BE32_MAX;
            }
            if (offload->nat.mod_flags & NAT_ACTION_DST) {
                ipv4_key->ipv4_dst = offload->nat.key.dst.addr.ipv4;
                ipv4_mask->ipv4_dst = OVS_BE32_MAX;
            }
        } else {
            struct ovs_key_ipv6 *ipv6_key = NULL, *ipv6_mask = NULL;

            if (offload->nat.mod_flags & NAT_ACTION_SRC ||
                offload->nat.mod_flags & NAT_ACTION_DST) {
                ipv6_key = nl_msg_put_unspec_zero(buf, OVS_KEY_ATTR_IPV6,
                                                  2 * sizeof *ipv6_key);
                ipv6_mask = ipv6_key + 1;
            }
            if (offload->nat.mod_flags & NAT_ACTION_SRC) {
                ipv6_key->ipv6_src = offload->nat.key.src.addr.ipv6;
                memset(&ipv6_mask->ipv6_src, 0xFF, sizeof ipv6_mask->ipv6_src);
            }
            if (offload->nat.mod_flags & NAT_ACTION_DST) {
                ipv6_key->ipv6_dst = offload->nat.key.dst.addr.ipv6;
                memset(&ipv6_mask->ipv6_dst, 0xFF, sizeof ipv6_mask->ipv6_dst);
            }
        }
        if (offload->nat.mod_flags & NAT_ACTION_SRC_PORT ||
            offload->nat.mod_flags & NAT_ACTION_DST_PORT) {
            if (offload->ct_match.key.nw_proto == IPPROTO_TCP) {
                struct ovs_key_tcp *tcp_key, *tcp_mask;

                tcp_key = nl_msg_put_unspec_zero(buf, OVS_KEY_ATTR_TCP,
                                                 2 * sizeof *tcp_key);
                tcp_mask = tcp_key + 1;
                if (offload->nat.mod_flags & NAT_ACTION_SRC_PORT) {
                    tcp_key->tcp_src = offload->nat.key.src.port;
                    tcp_mask->tcp_src = OVS_BE16_MAX;
                }
                if (offload->nat.mod_flags & NAT_ACTION_DST_PORT) {
                    tcp_key->tcp_dst = offload->nat.key.dst.port;
                    tcp_mask->tcp_dst = OVS_BE16_MAX;
                }
            }
            if (offload->ct_match.key.nw_proto == IPPROTO_UDP) {
                struct ovs_key_udp *udp_key, *udp_mask;

                udp_key = nl_msg_put_unspec_zero(buf, OVS_KEY_ATTR_UDP,
                                                 2 * sizeof *udp_key);
                udp_mask = udp_key + 1;
                if (offload->nat.mod_flags & NAT_ACTION_SRC_PORT) {
                    udp_key->udp_src = offload->nat.key.src.port;
                    udp_mask->udp_src = OVS_BE16_MAX;
                }
                if (offload->nat.mod_flags & NAT_ACTION_DST_PORT) {
                    udp_key->udp_dst = offload->nat.key.dst.port;
                    udp_mask->udp_dst = OVS_BE16_MAX;
                }
            }
        }
        nl_msg_end_nested(buf, offset);
    }
    offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_CT);
    if (offload->mark_mask) {
        uint32_t *mark_key, *mark_mask;

        mark_key = nl_msg_put_unspec_zero(buf, OVS_CT_ATTR_MARK,
                                          2 * sizeof *mark_key);
        mark_mask = mark_key + 1;
        *mark_key = offload->mark_key;
        *mark_mask = offload->mark_mask;
    }
    if (!is_all_zeros(&offload->label_mask, sizeof offload->label_mask)) {
        ovs_u128 *labels_key, *labels_mask;

        labels_key = nl_msg_put_unspec_zero(buf, OVS_CT_ATTR_LABELS,
                                            2 * sizeof *labels_key);
        labels_mask = labels_key + 1;
        *labels_key = offload->label_key;
        *labels_mask = offload->label_mask;
    }
    nl_msg_put_u16(buf, OVS_CT_ATTR_ZONE, offload->ct_match.key.zone);

    end = helper;
    ovs_strcat(helper, sizeof helper, &end, "offl,st(0x");
    ovs_strcat(helper, sizeof helper, &end, u32_to_hex(s, offload->ct_state));
    ovs_strcat(helper, sizeof helper, &end, "),id_key(0x");
    ovs_strcat(helper, sizeof helper, &end, uintptr_to_hex(s,
                                                           offload->ctid_key));
    ovs_strcat(helper, sizeof helper, &end, ")");

    nl_msg_put_string(buf, OVS_CT_ATTR_HELPER, helper);
    nl_msg_end_nested(buf, offset);
}

static int
dp_netdev_ct_offload_add_cb(struct ct_flow_offload_item *offload,
                            struct dp_netdev *dp, struct ct_match *ct_match,
                            struct nlattr *actions, int actions_len)
{
    const char *dpif_type_str = dpif_normalize_type(dp->class->type);
    struct offload_info info = { .flow_mark = INVALID_FLOW_MARK, };
    struct netdev *port;
    struct match match;
    int ret;

    port = netdev_ports_get(ct_match->odp_port, dpif_type_str);
    if (OVS_UNLIKELY(!port)) {
        return ENODEV;
    }

    dp_netdev_fill_ct_match(&match, ct_match);

    ovs_rwlock_rdlock(&dp->port_rwlock);
    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&upcall_rl)))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        struct ofpbuf key_buf, mask_buf;
        struct odp_flow_key_parms odp_parms = {
            .flow = &match.flow,
            .mask = &match.wc.masks,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key_buf, 0);
        ofpbuf_init(&mask_buf, 0);

        odp_flow_key_from_flow(&odp_parms, &key_buf);
        odp_parms.key_buf = &key_buf;
        odp_flow_key_from_mask(&odp_parms, &mask_buf);

        ds_put_cstr(&ds, "ct_add: ");
        odp_format_ufid(&offload->ufid, &ds);
        ds_put_cstr(&ds, " ");
        odp_flow_format(key_buf.data, key_buf.size,
                        mask_buf.data, mask_buf.size,
                        NULL, &ds, false);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len, NULL);

        VLOG_DBG("%s", ds_cstr(&ds));

        ofpbuf_uninit(&key_buf);
        ofpbuf_uninit(&mask_buf);

        ds_destroy(&ds);
    }
    ret = netdev_flow_put(port, &match, actions, actions_len, &offload->ufid,
                          &info, NULL);
    if (offload->status) {
        *(offload->status) = !ret;
    }
    ovs_rwlock_unlock(&dp->port_rwlock);
    netdev_close(port);

    return ret;
}

static int
dp_netdev_ct_add(struct ct_flow_offload_item *offload, struct dp_netdev *dp,
                 dp_netdev_ct_add_cb cb)
{
    struct nlattr *actions;
    size_t actions_size;
    struct ofpbuf buf;
    int ret;

    /* Bypass actions building if the work is already done.
     *
     * When e2e is enabled, the datapath will create the ct_actions and
     * send them ready to the e2e thread. There, if the e2e-cache is not
     * yet full, they will be consumed directly. Otherwise, an offload
     * request will be emitted to the regular offload threads.
     *
     * In this case, those OFL-threads will call again this function,
     * but the actions will already have been created.
     */

    if (!offload->ct_actions_set) {
        ofpbuf_init(&buf, 0);
        dp_netdev_create_ct_actions(&buf, offload);
        actions = ofpbuf_at_assert(&buf, 0, sizeof(struct nlattr));
        actions_size = buf.size;
    } else {
        actions = offload->actions;
        actions_size = offload->actions_size;
    }

    ret = cb(offload, dp, &offload->ct_match, actions, actions_size);

    if (!offload->ct_actions_set) {
        ofpbuf_uninit(&buf);
    }

    return ret;
}

static int
dp_netdev_ct_offload_del(struct dp_offload_thread_item *offload_item, int dir)
{
    const char *dpif_type_str = dpif_normalize_type(offload_item->dp->class->type);
    struct ct_flow_offload_item *offload =
                                &offload_item->data->ct_offload[dir];
    struct netdev *port;
    int ret;

    port = netdev_ports_get(offload->ct_match.odp_port, dpif_type_str);
    if (!port) {
        return ENODEV;
    }

    ovs_rwlock_rdlock(&offload_item->dp->port_rwlock);
    ret = netdev_flow_del(port, &offload->ufid, NULL);
    ovs_rwlock_unlock(&offload_item->dp->port_rwlock);
    netdev_close(port);

    return ret;
}

static void
dp_netdev_ct_offload_handle(struct dp_offload_thread_item *offload_item)
{
    struct ct_flow_offload_item *ct_offload = offload_item->data->ct_offload;
    struct dp_offload_thread *ofl_thread;
    int ret[CT_DIR_NUM];
    const char *op;
    int dir;

    ofl_thread = &dp_offload_threads[netdev_offload_thread_id()];

    if (ct_offload[CT_DIR_INIT].op == DP_NETDEV_FLOW_OFFLOAD_OP_ADD &&
        ovs_refcount_unref(ct_offload[CT_DIR_INIT].refcnt) == 1) {
        free(ct_offload[CT_DIR_INIT].refcnt);
        return;
    }
    if (ct_offload[CT_DIR_INIT].op == DP_NETDEV_FLOW_OFFLOAD_OP_DEL) {
        free(ct_offload[CT_DIR_INIT].refcnt);
    }

    for (dir = 0; dir < CT_DIR_NUM; dir++) {
        switch (ct_offload[dir].op) {
        case DP_NETDEV_FLOW_OFFLOAD_OP_ADD:
            op = "add";
            ret[dir] = dp_netdev_ct_add(&ct_offload[dir], ct_offload->dp,
                                        dp_netdev_ct_offload_add_cb);

            break;
        case DP_NETDEV_FLOW_OFFLOAD_OP_DEL:
            op = "delete";
            ret[dir] = dp_netdev_ct_offload_del(offload_item, dir);
            if (ret[dir] == ENODEV) {
                /* If the port was previously deleted, its offloads
                 * have been flushed. Count as deletion. */
                ret[dir] = 0;
            }
            break;
        default:
            OVS_NOT_REACHED();
        }
        VLOG_DBG("%s to %s ct(%s) flow "UUID_FMT,
                 ret[dir] == 0 ? "succeed" : "failed", op,
                 dir == CT_DIR_INIT ? "init" : "reply",
                 UUID_ARGS((struct uuid *)&ct_offload[dir].ufid));
    }
    if (!ret[CT_DIR_INIT] && !ret[CT_DIR_REP]) {
        if (ct_offload[CT_DIR_INIT].op ==
            DP_NETDEV_FLOW_OFFLOAD_OP_ADD) {
            atomic_count_inc64(&ofl_thread->ct_bi_dir_connections);
        } else {
            atomic_count_dec64(&ofl_thread->ct_bi_dir_connections);
        }
    }
}

/* This offload operation is blocking.
 * Caller thread will wait on each offload thread to finish.
 */
static void
dp_netdev_offload_flush_handle(struct dp_offload_thread_item *item)
{
    struct dp_offload_flush_item *flush = &item->data->flush;

    /* per-thread cmaps will be updated by revalidators
     * deleting flows. */
    if (flush->netdev != NULL) {
        ovs_rwlock_rdlock(&item->dp->port_rwlock);
        netdev_flow_flush(flush->netdev);
        ovs_rwlock_unlock(&item->dp->port_rwlock);
    }

    ovs_barrier_block(flush->barrier);
}

#define DP_NETDEV_OFFLOAD_BACKOFF_MIN 1
#define DP_NETDEV_OFFLOAD_BACKOFF_MAX 64
#define DP_NETDEV_OFFLOAD_QUIESCE_INTERVAL_MS 10

static void *
dp_netdev_flow_offload_main(void *arg)
{
    struct dp_offload_thread_item *offload_item;
    struct dp_offload_thread *ofl_thread = arg;
    enum mpsc_queue_poll_result poll_result;
    long long int next_rcu_quiesce;
    struct mpsc_queue *queue;
    uint64_t backoff;
    const char *op;
    int ret;

    queue = &ofl_thread->queue;
    if (!mpsc_queue_acquire(queue)) {
        VLOG_ERR("failed to register as consumer of the offload queue.\n");
        return NULL;
    }

    backoff = DP_NETDEV_OFFLOAD_BACKOFF_MIN;
    for (;;) {
        struct mpsc_queue_node *node;

        while ((poll_result = mpsc_queue_poll(queue, &node)) ==
               MPSC_QUEUE_EMPTY) {
            xnanosleep(backoff * 1E6);
            if (backoff < DP_NETDEV_OFFLOAD_BACKOFF_MAX) {
                backoff <<= 1;
            }
        }

        backoff = DP_NETDEV_OFFLOAD_BACKOFF_MIN;
        next_rcu_quiesce = time_msec() + DP_NETDEV_OFFLOAD_QUIESCE_INTERVAL_MS;
        do {
            if (poll_result == MPSC_QUEUE_RETRY) {
                continue;
            }

            offload_item = CONTAINER_OF(node, struct dp_offload_thread_item,
                                        node);
            atomic_count_dec64(&ofl_thread->enqueued_item);

            if (offload_item->type == DP_FLOW_OFFLOAD_ITEM) {
                struct dp_flow_offload_item *dp_offload =
                        &offload_item->data->flow_offload;

                switch (dp_offload->op) {
                case DP_NETDEV_FLOW_OFFLOAD_OP_ADD:
                    op = "add";
                    ret = dp_netdev_flow_offload_put(offload_item);
                    break;
                case DP_NETDEV_FLOW_OFFLOAD_OP_MOD:
                    op = "modify";
                    ret = dp_netdev_flow_offload_put(offload_item);
                    break;
                case DP_NETDEV_FLOW_OFFLOAD_OP_DEL:
                    op = "delete";
                    ret = dp_netdev_flow_offload_del(offload_item);
                    break;
                default:
                    OVS_NOT_REACHED();
                }
                VLOG_DBG("%s to %s netdev flow "UUID_FMT,
                         ret == 0 ? "succeed" : "failed", op,
                         UUID_ARGS(
                             (struct uuid *)&dp_offload->flow->mega_ufid));
            } else if (offload_item->type == DP_CT_OFFLOAD_ITEM) {
                dp_netdev_ct_offload_handle(offload_item);
            } else if (offload_item->type == DP_FLUSH_OFFLOAD_ITEM) {
                dp_netdev_offload_flush_handle(offload_item);
            } else {
                OVS_NOT_REACHED();
            }

            dp_netdev_offload_item_unref(offload_item);

            /* Do RCU synchronization at fixed interval. */
            if (time_msec() > next_rcu_quiesce) {
                if (!ovsrcu_try_quiesce()) {
                    next_rcu_quiesce += DP_NETDEV_OFFLOAD_QUIESCE_INTERVAL_MS;
                }
            }
        } while ((poll_result = mpsc_queue_poll(queue, &node)) !=
                 MPSC_QUEUE_EMPTY);
    }

    return NULL;
}

static void
queue_netdev_flow_del(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow)
{
    struct dp_flow_offload_item *offload;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    if (dp_netdev_e2e_cache_enabled) {
        e2e_cache_flow_del(&flow->mega_ufid, pmd->dp);
    }

    offload = dp_netdev_alloc_flow_offload(pmd, flow,
                                           DP_NETDEV_FLOW_OFFLOAD_OP_DEL);
    dp_netdev_append_flow_offload(offload);
}

static int
e2e_cache_flow_put(bool is_ct, const ovs_u128 *ufid, const void *match,
                   const struct nlattr *actions, size_t actions_len);
static void
queue_netdev_flow_put(struct dp_netdev_pmd_thread *pmd,
                      struct dp_netdev_flow *flow, struct match *match,
                      const struct nlattr *actions, size_t actions_len,
                      bool modify)
{
    struct dp_flow_offload_item *offload;
    int op;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    if (dp_netdev_e2e_cache_enabled) {
        e2e_cache_flow_put(false, &flow->mega_ufid, match,
                           actions, actions_len);
    }

    op = modify ? DP_NETDEV_FLOW_OFFLOAD_OP_MOD : DP_NETDEV_FLOW_OFFLOAD_OP_ADD;
    offload = dp_netdev_alloc_flow_offload(pmd, flow, op);
    offload->match = *match;
    offload->actions = xmalloc(actions_len);
    memcpy(offload->actions, actions, actions_len);
    offload->actions_len = actions_len;

    dp_netdev_append_flow_offload(offload);
}

static void
dp_netdev_pmd_remove_flow(struct dp_netdev_pmd_thread *pmd,
                          struct dp_netdev_flow *flow)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct cmap_node *node = CONST_CAST(struct cmap_node *, &flow->node);
    struct dpcls *cls;
    odp_port_t in_port = flow->flow.in_port.odp_port;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    ovs_assert(cls != NULL);
    dpcls_remove(cls, &flow->cr);
    cmap_remove(&pmd->flow_table, node, dp_netdev_flow_hash(&flow->ufid));
    if (flow->mark != INVALID_FLOW_MARK) {
        queue_netdev_flow_del(pmd, flow);
    }
    flow->dead = true;

    dp_netdev_flow_unref(flow);
}

static void
dp_netdev_offload_flush_enqueue(struct dp_netdev *dp,
                                struct netdev *netdev,
                                struct ovs_barrier *barrier)
{
    unsigned int tid;

    for (tid = 0; tid < netdev_offload_thread_nb(); tid++) {
        struct dp_offload_thread_item *item;
        struct dp_offload_flush_item *flush;

        item = xmalloc(sizeof *item + sizeof *flush);
        item->type = DP_FLUSH_OFFLOAD_ITEM;
        item->dp = dp;

        flush = &item->data->flush;
        flush->netdev = netdev;
        flush->barrier = barrier;

        mpsc_queue_insert(&dp_offload_threads[tid].queue, &item->node);
        atomic_count_inc64(&dp_offload_threads[tid].enqueued_item);
    }
}

static int
e2e_cache_flow_flush(struct netdev *netdev, struct ovs_barrier *barrier,
                     struct dp_netdev *dp);

/* Blocking call that will wait on offload threads to finish
 * their work. As the flush order will only be enqueued after
 * existing offload requests, those previous offload requests
 * need to be processed, which requires being able to
 * rdlock the 'port_rwlock' in the offload threads.
 *
 * If we keep the wrlock on it now, it will deadlock waiting
 * on those other offload threads to resume while blocking on
 * the flush.
 */
static void
dp_netdev_offload_flush_(struct dp_netdev *dp,
                         struct dp_netdev_port *port)
    OVS_EXCLUDED(dp->port_rwlock)
{
    static struct ovs_mutex flush_mutex = OVS_MUTEX_INITIALIZER;
    struct ovs_barrier barrier;
    struct netdev *netdev;

    if (!netdev_is_flow_api_enabled()) {
        return;
    }

    dp_netdev_offload_init();

    /* Do not interleave flush barriers. Only one flush
     * order can be 'live' at any single time. It must be unique
     * within each offload thread queue and resolved before
     * another flush order can be issued.
     */
    ovs_mutex_lock(&flush_mutex);

    netdev = port ? netdev_ref(port->netdev) : NULL;

    /* Wait on each offload thread, plus this one. */
    ovs_barrier_init(&barrier,
                     netdev_offload_thread_nb() + 1 +
                     dp_netdev_e2e_cache_enabled);

    if (dp_netdev_e2e_cache_enabled) {
        /* If e2e is enabled, it must send the flush requests
         * after it has processed its own queue. This means that this
         * thread should not send the flush requests, only e2e can do so.
         * cf. e2e_cache_flow_db_flush().
         */
        e2e_cache_flow_flush(netdev, &barrier, dp);
    } else {
        dp_netdev_offload_flush_enqueue(dp, netdev, &barrier);
    }

    ovs_barrier_block(&barrier);
    ovs_barrier_destroy(&barrier);

    netdev_close(netdev);

    ovs_mutex_unlock(&flush_mutex);
}

static void
dp_netdev_offload_flush(struct dp_netdev *dp,
                        struct dp_netdev_port *port)
{
    dp_netdev_offload_flush_(dp, port);
}

static void
dp_netdev_offload_barrier(struct dp_netdev *dp)
{
    /* 'Dummy' flush call, that is only used to sync all offload threads.
     * The 'port_rwlock' is not necessary as no offloads will change.
     */
    dp_netdev_offload_flush_(dp, NULL);
}

static void
dp_netdev_pmd_flow_flush(struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_flow *netdev_flow;

    ovs_mutex_lock(&pmd->flow_mutex);
    CMAP_FOR_EACH (netdev_flow, node, &pmd->flow_table) {
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
}

static int
dpif_netdev_flow_flush(struct dpif *dpif)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_pmd_flow_flush(pmd);
    }

    return 0;
}

struct dp_netdev_port_state {
    struct hmap_position position;
    char *name;
};

static int
dpif_netdev_port_dump_start(const struct dpif *dpif OVS_UNUSED, void **statep)
{
    *statep = xzalloc(sizeof(struct dp_netdev_port_state));
    return 0;
}

static int
dpif_netdev_port_dump_next(const struct dpif *dpif, void *state_,
                           struct dpif_port *dpif_port)
{
    struct dp_netdev_port_state *state = state_;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct hmap_node *node;
    int retval;

    ovs_rwlock_rdlock(&dp->port_rwlock);
    node = hmap_at_position(&dp->ports, &state->position);
    if (node) {
        struct dp_netdev_port *port;

        port = CONTAINER_OF(node, struct dp_netdev_port, node);

        free(state->name);
        state->name = xstrdup(netdev_get_name(port->netdev));
        dpif_port->name = state->name;
        dpif_port->type = port->type;
        dpif_port->port_no = port->port_no;

        retval = 0;
    } else {
        retval = EOF;
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    return retval;
}

static int
dpif_netdev_port_dump_done(const struct dpif *dpif OVS_UNUSED, void *state_)
{
    struct dp_netdev_port_state *state = state_;
    free(state->name);
    free(state);
    return 0;
}

static int
dpif_netdev_port_poll(const struct dpif *dpif_, char **devnamep OVS_UNUSED)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);
    uint64_t new_port_seq;
    int error;

    new_port_seq = seq_read(dpif->dp->port_seq);
    if (dpif->last_port_seq != new_port_seq) {
        dpif->last_port_seq = new_port_seq;
        error = ENOBUFS;
    } else {
        error = EAGAIN;
    }

    return error;
}

static void
dpif_netdev_port_poll_wait(const struct dpif *dpif_)
{
    struct dpif_netdev *dpif = dpif_netdev_cast(dpif_);

    seq_wait(dpif->dp->port_seq, dpif->last_port_seq);
}

static struct dp_netdev_flow *
dp_netdev_flow_cast(const struct dpcls_rule *cr)
{
    return cr ? CONTAINER_OF(cr, struct dp_netdev_flow, cr) : NULL;
}

static bool dp_netdev_flow_ref(struct dp_netdev_flow *flow)
{
    return ovs_refcount_try_ref_rcu(&flow->ref_cnt);
}

/* netdev_flow_key utilities.
 *
 * netdev_flow_key is basically a miniflow.  We use these functions
 * (netdev_flow_key_clone, netdev_flow_key_equal, ...) instead of the miniflow
 * functions (miniflow_clone_inline, miniflow_equal, ...), because:
 *
 * - Since we are dealing exclusively with miniflows created by
 *   miniflow_extract(), if the map is different the miniflow is different.
 *   Therefore we can be faster by comparing the map and the miniflow in a
 *   single memcmp().
 * - These functions can be inlined by the compiler. */

/* Given the number of bits set in miniflow's maps, returns the size of the
 * 'netdev_flow_key.mf' */
static inline size_t
netdev_flow_key_size(size_t flow_u64s)
{
    return sizeof(struct miniflow) + MINIFLOW_VALUES_SIZE(flow_u64s);
}

static inline bool
netdev_flow_key_equal(const struct netdev_flow_key *a,
                      const struct netdev_flow_key *b)
{
    /* 'b->len' may be not set yet. */
    return a->hash == b->hash && !memcmp(&a->mf, &b->mf, a->len);
}

/* Used to compare 'netdev_flow_key' in the exact match cache to a miniflow.
 * The maps are compared bitwise, so both 'key->mf' and 'mf' must have been
 * generated by miniflow_extract. */
static inline bool
netdev_flow_key_equal_mf(const struct netdev_flow_key *key,
                         const struct miniflow *mf)
{
    return !memcmp(&key->mf, mf, key->len);
}

static inline void
netdev_flow_key_clone(struct netdev_flow_key *dst,
                      const struct netdev_flow_key *src)
{
    memcpy(dst, src,
           offsetof(struct netdev_flow_key, mf) + src->len);
}

/* Initialize a netdev_flow_key 'mask' from 'match'. */
static inline void
netdev_flow_mask_init(struct netdev_flow_key *mask,
                      const struct match *match)
{
    uint64_t *dst = miniflow_values(&mask->mf);
    struct flowmap fmap;
    uint32_t hash = 0;
    size_t idx;

    /* Only check masks that make sense for the flow. */
    flow_wc_map(&match->flow, &fmap);
    flowmap_init(&mask->mf.map);

    FLOWMAP_FOR_EACH_INDEX(idx, fmap) {
        uint64_t mask_u64 = flow_u64_value(&match->wc.masks, idx);

        if (mask_u64) {
            flowmap_set(&mask->mf.map, idx, 1);
            *dst++ = mask_u64;
            hash = hash_add64(hash, mask_u64);
        }
    }

    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, mask->mf.map) {
        hash = hash_add64(hash, map);
    }

    size_t n = dst - miniflow_get_values(&mask->mf);

    mask->hash = hash_finish(hash, n * 8);
    mask->len = netdev_flow_key_size(n);
}

/* Initializes 'dst' as a copy of 'flow' masked with 'mask'. */
static inline void
netdev_flow_key_init_masked(struct netdev_flow_key *dst,
                            const struct flow *flow,
                            const struct netdev_flow_key *mask)
{
    uint64_t *dst_u64 = miniflow_values(&dst->mf);
    const uint64_t *mask_u64 = miniflow_get_values(&mask->mf);
    uint32_t hash = 0;
    uint64_t value;

    dst->len = mask->len;
    dst->mf = mask->mf;   /* Copy maps. */

    FLOW_FOR_EACH_IN_MAPS(value, flow, mask->mf.map) {
        *dst_u64 = value & *mask_u64++;
        hash = hash_add64(hash, *dst_u64++);
    }
    dst->hash = hash_finish(hash,
                            (dst_u64 - miniflow_get_values(&dst->mf)) * 8);
}

static inline bool
emc_entry_alive(struct emc_entry *ce)
{
    return ce->flow && !ce->flow->dead;
}

static void
emc_clear_entry(struct emc_entry *ce)
{
    if (ce->flow) {
        dp_netdev_flow_unref(ce->flow);
        ce->flow = NULL;
    }
}

static inline void
emc_change_entry(struct emc_entry *ce, struct dp_netdev_flow *flow,
                 const struct netdev_flow_key *key)
{
    if (ce->flow != flow) {
        if (ce->flow) {
            dp_netdev_flow_unref(ce->flow);
        }

        if (dp_netdev_flow_ref(flow)) {
            ce->flow = flow;
        } else {
            ce->flow = NULL;
        }
    }
    if (key) {
        netdev_flow_key_clone(&ce->key, key);
    }
}

static inline void
emc_insert(struct emc_cache *cache, const struct netdev_flow_key *key,
           struct dp_netdev_flow *flow)
{
    struct emc_entry *to_be_replaced = NULL;
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (netdev_flow_key_equal(&current_entry->key, key)) {
            /* We found the entry with the 'mf' miniflow */
            emc_change_entry(current_entry, flow, NULL);
            return;
        }

        /* Replacement policy: put the flow in an empty (not alive) entry, or
         * in the first entry where it can be */
        if (!to_be_replaced
            || (emc_entry_alive(to_be_replaced)
                && !emc_entry_alive(current_entry))
            || current_entry->key.hash < to_be_replaced->key.hash) {
            to_be_replaced = current_entry;
        }
    }
    /* We didn't find the miniflow in the cache.
     * The 'to_be_replaced' entry is where the new flow will be stored */

    emc_change_entry(to_be_replaced, flow, key);
}

static inline void
emc_probabilistic_insert(struct dp_netdev_pmd_thread *pmd,
                         const struct netdev_flow_key *key,
                         struct dp_netdev_flow *flow)
{
    /* Insert an entry into the EMC based on probability value 'min'. By
     * default the value is UINT32_MAX / 100 which yields an insertion
     * probability of 1/100 ie. 1% */

    uint32_t min = pmd->ctx.emc_insert_min;

    if (min && random_uint32() <= min) {
        emc_insert(&(pmd->flow_cache).emc_cache, key, flow);
    }
}

static inline struct dp_netdev_flow *
emc_lookup(struct emc_cache *cache, const struct netdev_flow_key *key)
{
    struct emc_entry *current_entry;

    EMC_FOR_EACH_POS_WITH_HASH(cache, current_entry, key->hash) {
        if (current_entry->key.hash == key->hash
            && emc_entry_alive(current_entry)
            && netdev_flow_key_equal_mf(&current_entry->key, &key->mf)) {

            /* We found the entry with the 'key->mf' miniflow */
            return current_entry->flow;
        }
    }

    return NULL;
}

static inline const struct cmap_node *
smc_entry_get(struct dp_netdev_pmd_thread *pmd, const uint32_t hash)
{
    struct smc_cache *cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &cache->buckets[hash & SMC_MASK];
    uint16_t sig = hash >> 16;
    uint16_t index = UINT16_MAX;

    for (int i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            index = bucket->flow_idx[i];
            break;
        }
    }
    if (index != UINT16_MAX) {
        return cmap_find_by_index(&pmd->flow_table, index);
    }
    return NULL;
}

static void
smc_clear_entry(struct smc_bucket *b, int idx)
{
    b->flow_idx[idx] = UINT16_MAX;
}

/* Insert the flow_table index into SMC. Insertion may fail when 1) SMC is
 * turned off, 2) the flow_table index is larger than uint16_t can handle.
 * If there is already an SMC entry having same signature, the index will be
 * updated. If there is no existing entry, but an empty entry is available,
 * the empty entry will be taken. If no empty entry or existing same signature,
 * a random entry from the hashed bucket will be picked. */
static inline void
smc_insert(struct dp_netdev_pmd_thread *pmd,
           const struct netdev_flow_key *key,
           uint32_t hash)
{
    struct smc_cache *smc_cache = &(pmd->flow_cache).smc_cache;
    struct smc_bucket *bucket = &smc_cache->buckets[key->hash & SMC_MASK];
    uint16_t index;
    uint32_t cmap_index;
    bool smc_enable_db;
    int i;

    atomic_read_relaxed(&pmd->dp->smc_enable_db, &smc_enable_db);
    if (!smc_enable_db) {
        return;
    }

    cmap_index = cmap_find_index(&pmd->flow_table, hash);
    index = (cmap_index >= UINT16_MAX) ? UINT16_MAX : (uint16_t)cmap_index;

    /* If the index is larger than SMC can handle (uint16_t), we don't
     * insert */
    if (index == UINT16_MAX) {
        return;
    }

    /* If an entry with same signature already exists, update the index */
    uint16_t sig = key->hash >> 16;
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->sig[i] == sig) {
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* If there is an empty entry, occupy it. */
    for (i = 0; i < SMC_ENTRY_PER_BUCKET; i++) {
        if (bucket->flow_idx[i] == UINT16_MAX) {
            bucket->sig[i] = sig;
            bucket->flow_idx[i] = index;
            return;
        }
    }
    /* Otherwise, pick a random entry. */
    i = random_uint32() % SMC_ENTRY_PER_BUCKET;
    bucket->sig[i] = sig;
    bucket->flow_idx[i] = index;
}

static struct dp_netdev_flow *
dp_netdev_pmd_lookup_flow(struct dp_netdev_pmd_thread *pmd,
                          const struct netdev_flow_key *key,
                          int *lookup_num_p)
{
    struct dpcls *cls;
    struct dpcls_rule *rule;
    odp_port_t in_port = u32_to_odp(MINIFLOW_GET_U32(&key->mf,
                                                     in_port.odp_port));
    struct dp_netdev_flow *netdev_flow = NULL;

    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        dpcls_lookup(cls, &key, &rule, 1, lookup_num_p);
        netdev_flow = dp_netdev_flow_cast(rule);
    }
    return netdev_flow;
}

static struct dp_netdev_flow *
dp_netdev_pmd_find_flow(const struct dp_netdev_pmd_thread *pmd,
                        const ovs_u128 *ufidp, const struct nlattr *key,
                        size_t key_len)
{
    struct dp_netdev_flow *netdev_flow;
    struct flow flow;
    ovs_u128 ufid;

    /* If a UFID is not provided, determine one based on the key. */
    if (!ufidp && key && key_len
        && !dpif_netdev_flow_from_nlattrs(key, key_len, &flow, false)) {
        odp_flow_key_hash(&flow, sizeof flow, &ufid);
        ufidp = &ufid;
    }

    if (ufidp) {
        CMAP_FOR_EACH_WITH_HASH (netdev_flow, node, dp_netdev_flow_hash(ufidp),
                                 &pmd->flow_table) {
            if (ovs_u128_equals(netdev_flow->ufid, *ufidp)) {
                return netdev_flow;
            }
        }
    }

    return NULL;
}

static void
dp_netdev_flow_set_last_stats_attrs(struct dp_netdev_flow *netdev_flow,
                                    const struct dpif_flow_stats *stats,
                                    const struct dpif_flow_attrs *attrs,
                                    int result)
{
    struct dp_netdev_flow_stats *last_stats = &netdev_flow->last_stats;
    struct dp_netdev_flow_attrs *last_attrs = &netdev_flow->last_attrs;

    atomic_store_relaxed(&netdev_flow->netdev_flow_get_result, result);
    if (result) {
        return;
    }

    atomic_store_relaxed(&last_stats->used,         stats->used);
    atomic_store_relaxed(&last_stats->packet_count, stats->n_packets);
    atomic_store_relaxed(&last_stats->byte_count,   stats->n_bytes);
    atomic_store_relaxed(&last_stats->tcp_flags,    stats->tcp_flags);

    atomic_store_relaxed(&last_attrs->offloaded,    attrs->offloaded);
    atomic_store_relaxed(&last_attrs->dp_layer,     attrs->dp_layer);

}

static void
dp_netdev_flow_get_last_stats_attrs(struct dp_netdev_flow *netdev_flow,
                                    struct dpif_flow_stats *stats,
                                    struct dpif_flow_attrs *attrs,
                                    int *result)
{
    struct dp_netdev_flow_stats *last_stats = &netdev_flow->last_stats;
    struct dp_netdev_flow_attrs *last_attrs = &netdev_flow->last_attrs;

    atomic_read_relaxed(&netdev_flow->netdev_flow_get_result, result);
    if (*result) {
        return;
    }

    atomic_read_relaxed(&last_stats->used,         &stats->used);
    atomic_read_relaxed(&last_stats->packet_count, &stats->n_packets);
    atomic_read_relaxed(&last_stats->byte_count,   &stats->n_bytes);
    atomic_read_relaxed(&last_stats->tcp_flags,    &stats->tcp_flags);

    atomic_read_relaxed(&last_attrs->offloaded,    &attrs->offloaded);
    atomic_read_relaxed(&last_attrs->dp_layer,     &attrs->dp_layer);
}

static int
dpif_netdev_get_flow_offload_status(const struct dp_netdev *dp,
                                    struct dp_netdev_flow *netdev_flow,
                                    struct dpif_flow_stats *stats,
                                    struct dpif_flow_attrs *attrs,
                                    long long now,
                                    long long prev_now)
{
    uint64_t act_buf[1024 / 8];
    bool merged_ret = false;
    struct nlattr *actions;
    struct netdev *netdev;
    struct match match;
    struct ofpbuf buf;
    int ret = 0;

    if (!netdev_is_flow_api_enabled()) {
        return EINVAL;
    }

    netdev = netdev_ports_get(netdev_flow->flow.in_port.odp_port,
                              dpif_normalize_type(dp->class->type));
    if (!netdev) {
        return EINVAL;
    }
    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);
    /* Taking a global 'port_mutex' to fulfill thread safety
     * restrictions regarding netdev port mapping.
     *
     * XXX: Main thread will try to pause/stop all revalidators during datapath
     *      reconfiguration via datapath purge callback (dp_purge_cb) while
     *      holding 'dp->port_mutex'.  So we're not waiting for mutex here.
     *      Otherwise, deadlock is possible, bcause revalidators might sleep
     *      waiting for the main thread to release the lock and main thread
     *      will wait for them to stop processing.
     *      This workaround might make statistics less accurate. Especially
     *      for flow deletion case, since there will be no other attempt.  */
    if (!ovs_rwlock_tryrdlock(&dp->port_rwlock)) {
        ret = netdev_flow_get(netdev, &match, &actions,
                              &netdev_flow->mega_ufid, stats, attrs, &buf);
        /* Storing statistics and attributes from the last request for
         * later use on mutex contention. */
        dp_netdev_flow_set_last_stats_attrs(netdev_flow, stats, attrs, ret);
        /* Get merged flow stats and update it to mt flow stats. As CT connections
         * are offloaded either to MT or e2e (but not both), even if we fail to
         * get stats for MT CT, we still need to query the e2e.
         */
        if (dp_netdev_e2e_cache_enabled) {
            merged_ret =
                e2e_cache_get_merged_flows_stats(netdev, &match, &actions,
                                                 &netdev_flow->mega_ufid,
                                                 stats, &buf, now, prev_now);
        }
        ovs_rwlock_unlock(&dp->port_rwlock);
    } else {
        dp_netdev_flow_get_last_stats_attrs(netdev_flow, stats, attrs, &ret);
        if (!ret && !attrs->dp_layer) {
            /* Flow was never reported as 'offloaded' so it's harmless
             * to continue to think so. */
            ret = EAGAIN;
        }
    }
    netdev_close(netdev);
    if (ret) {
        return merged_ret ? 0 : ret;
    }

    return 0;
}

static void
get_dpif_flow_status(const struct dp_netdev *dp,
                     const struct dp_netdev_flow *netdev_flow_,
                     struct dpif_flow_stats *stats,
                     struct dpif_flow_attrs *attrs)
{
    struct dpif_flow_stats offload_stats;
    struct dpif_flow_attrs offload_attrs;
    struct dp_netdev_flow *netdev_flow;
    unsigned long long n;
    long long used;
    uint16_t flags;

    netdev_flow = CONST_CAST(struct dp_netdev_flow *, netdev_flow_);

    atomic_read_relaxed(&netdev_flow->stats.packet_count, &n);
    stats->n_packets = n;
    atomic_read_relaxed(&netdev_flow->stats.byte_count, &n);
    stats->n_bytes = n;
    atomic_read_relaxed(&netdev_flow->stats.used, &used);
    stats->used = used;
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    stats->tcp_flags = flags;

    if (!dpif_netdev_get_flow_offload_status(dp, netdev_flow,
                                             &offload_stats, &offload_attrs, 0,
                                             0)) {
        stats->n_packets += offload_stats.n_packets;
        stats->n_bytes += offload_stats.n_bytes;
        stats->used = MAX(stats->used, offload_stats.used);
        stats->tcp_flags |= offload_stats.tcp_flags;
        if (attrs) {
            attrs->offloaded = offload_attrs.offloaded;
            attrs->dp_layer = offload_attrs.dp_layer;
        }
    } else if (attrs) {
        attrs->offloaded = false;
        attrs->dp_layer = "ovs";
    }
}

/* Converts to the dpif_flow format, using 'key_buf' and 'mask_buf' for
 * storing the netlink-formatted key/mask. 'key_buf' may be the same as
 * 'mask_buf'. Actions will be returned without copying, by relying on RCU to
 * protect them. */
static void
dp_netdev_flow_to_dpif_flow(const struct dp_netdev *dp,
                            const struct dp_netdev_flow *netdev_flow,
                            struct ofpbuf *key_buf, struct ofpbuf *mask_buf,
                            struct dpif_flow *flow, bool terse)
{
    if (terse) {
        memset(flow, 0, sizeof *flow);
    } else {
        struct flow_wildcards wc;
        struct dp_netdev_actions *actions;
        size_t offset;
        struct odp_flow_key_parms odp_parms = {
            .flow = &netdev_flow->flow,
            .mask = &wc.masks,
            .support = dp_netdev_support,
        };

        miniflow_expand(&netdev_flow->cr.mask->mf, &wc.masks);
        /* in_port is exact matched, but we have left it out from the mask for
         * optimnization reasons. Add in_port back to the mask. */
        wc.masks.in_port.odp_port = ODPP_NONE;

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_parms.key_buf = key_buf;
        odp_flow_key_from_mask(&odp_parms, mask_buf);
        flow->mask_len = mask_buf->size - offset;

        /* Actions */
        actions = dp_netdev_flow_get_actions(netdev_flow);
        flow->actions = actions->actions;
        flow->actions_len = actions->size;
    }

    flow->ufid = netdev_flow->ufid;
    flow->ufid_present = true;
    flow->pmd_id = netdev_flow->pmd_id;

    get_dpif_flow_status(dp, netdev_flow, &flow->stats, &flow->attrs);
    flow->attrs.dp_extra_info = netdev_flow->dp_extra_info;
}

static int
dpif_netdev_mask_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              const struct nlattr *mask_key,
                              uint32_t mask_key_len, const struct flow *flow,
                              struct flow_wildcards *wc, bool probe)
{
    enum odp_key_fitness fitness;

    fitness = odp_flow_key_to_mask(mask_key, mask_key_len, wc, flow, NULL);
    if (fitness) {
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_mask() and odp_flow_key_to_mask()
             * disagree on the acceptable form of a mask.  Log the problem
             * as an error, with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, mask_key, mask_key_len, NULL, &s,
                                true);
                VLOG_ERR("internal error parsing flow mask %s (%s)",
                ds_cstr(&s), odp_key_fitness_to_string(fitness));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    return 0;
}

static int
dpif_netdev_flow_from_nlattrs(const struct nlattr *key, uint32_t key_len,
                              struct flow *flow, bool probe)
{
    if (odp_flow_key_to_flow(key, key_len, flow, NULL)) {
        if (!probe) {
            /* This should not happen: it indicates that
             * odp_flow_key_from_flow() and odp_flow_key_to_flow() disagree on
             * the acceptable form of a flow.  Log the problem as an error,
             * with enough details to enable debugging. */
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            if (!VLOG_DROP_ERR(&rl)) {
                struct ds s;

                ds_init(&s);
                odp_flow_format(key, key_len, NULL, 0, NULL, &s, true);
                VLOG_ERR("internal error parsing flow key %s", ds_cstr(&s));
                ds_destroy(&s);
            }
        }

        return EINVAL;
    }

    if (flow->ct_state & DP_NETDEV_CS_UNSUPPORTED_MASK) {
        return EINVAL;
    }

    return 0;
}

static int
dpif_netdev_flow_get(const struct dpif *dpif, const struct dpif_flow_get *get)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_flow *netdev_flow;
    struct dp_netdev_pmd_thread *pmd;
    struct hmapx to_find = HMAPX_INITIALIZER(&to_find);
    struct hmapx_node *node;
    int error = EINVAL;

    if (get->pmd_id == PMD_ID_NULL) {
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dp_netdev_pmd_try_ref(pmd) && !hmapx_add(&to_find, pmd)) {
                dp_netdev_pmd_unref(pmd);
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, get->pmd_id);
        if (!pmd) {
            goto out;
        }
        hmapx_add(&to_find, pmd);
    }

    if (!hmapx_count(&to_find)) {
        goto out;
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        netdev_flow = dp_netdev_pmd_find_flow(pmd, get->ufid, get->key,
                                              get->key_len);
        if (netdev_flow) {
            dp_netdev_flow_to_dpif_flow(dp, netdev_flow, get->buffer,
                                        get->buffer, get->flow, false);
            error = 0;
            break;
        } else {
            error = ENOENT;
        }
    }

    HMAPX_FOR_EACH (node, &to_find) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        dp_netdev_pmd_unref(pmd);
    }
out:
    hmapx_destroy(&to_find);
    return error;
}

static void
dp_netdev_get_mega_ufid(const struct match *match, ovs_u128 *mega_ufid)
{
    struct flow masked_flow;
    size_t i;

    for (i = 0; i < sizeof(struct flow); i++) {
        ((uint8_t *)&masked_flow)[i] = ((uint8_t *)&match->flow)[i] &
                                       ((uint8_t *)&match->wc)[i];
    }
    odp_flow_key_hash(&masked_flow, sizeof masked_flow, mega_ufid);
}

static struct dp_netdev_flow *
dp_netdev_flow_add(struct dp_netdev_pmd_thread *pmd,
                   struct match *match, const ovs_u128 *ufid,
                   const struct nlattr *actions, size_t actions_len)
    OVS_REQUIRES(pmd->flow_mutex)
{
    struct ds extra_info = DS_EMPTY_INITIALIZER;
    struct dp_netdev_flow *flow;
    struct netdev_flow_key mask;
    struct dpcls *cls;
    size_t unit;

    /* Make sure in_port is exact matched before we read it. */
    ovs_assert(match->wc.masks.in_port.odp_port == ODPP_NONE);
    odp_port_t in_port = match->flow.in_port.odp_port;

    /* As we select the dpcls based on the port number, each netdev flow
     * belonging to the same dpcls will have the same odp_port value.
     * For performance reasons we wildcard odp_port here in the mask.  In the
     * typical case dp_hash is also wildcarded, and the resulting 8-byte
     * chunk {dp_hash, in_port} will be ignored by netdev_flow_mask_init() and
     * will not be part of the subtable mask.
     * This will speed up the hash computation during dpcls_lookup() because
     * there is one less call to hash_add64() in this case. */
    match->wc.masks.in_port.odp_port = 0;
    netdev_flow_mask_init(&mask, match);
    match->wc.masks.in_port.odp_port = ODPP_NONE;

    /* Make sure wc does not have metadata. */
    ovs_assert(!FLOWMAP_HAS_FIELD(&mask.mf.map, metadata)
               && !FLOWMAP_HAS_FIELD(&mask.mf.map, regs));

    /* Do not allocate extra space. */
    flow = xmalloc(sizeof *flow - sizeof flow->cr.flow.mf + mask.len);
    memset(&flow->stats, 0, sizeof flow->stats);
    atomic_init(&flow->netdev_flow_get_result, 0);
    memset(&flow->last_stats, 0, sizeof flow->last_stats);
    memset(&flow->last_attrs, 0, sizeof flow->last_attrs);
    flow->dead = false;
    flow->batch = NULL;
    flow->mark = INVALID_FLOW_MARK;
    *CONST_CAST(unsigned *, &flow->pmd_id) = pmd->core_id;
    *CONST_CAST(struct flow *, &flow->flow) = match->flow;
    *CONST_CAST(ovs_u128 *, &flow->ufid) = *ufid;
    ovs_refcount_init(&flow->ref_cnt);
    ovsrcu_set(&flow->actions, dp_netdev_actions_create(actions, actions_len));

    dp_netdev_get_mega_ufid(match, CONST_CAST(ovs_u128 *, &flow->mega_ufid));
    netdev_flow_key_init_masked(&flow->cr.flow, &match->flow, &mask);

    /* Select dpcls for in_port. Relies on in_port to be exact match. */
    cls = dp_netdev_pmd_find_dpcls(pmd, in_port);
    dpcls_insert(cls, &flow->cr, &mask);

    ds_put_cstr(&extra_info, "miniflow_bits(");
    FLOWMAP_FOR_EACH_UNIT (unit) {
        if (unit) {
            ds_put_char(&extra_info, ',');
        }
        ds_put_format(&extra_info, "%d",
                      count_1bits(flow->cr.mask->mf.map.bits[unit]));
    }
    ds_put_char(&extra_info, ')');
    flow->dp_extra_info = ds_steal_cstr(&extra_info);
    ds_destroy(&extra_info);

    cmap_insert(&pmd->flow_table, CONST_CAST(struct cmap_node *, &flow->node),
                dp_netdev_flow_hash(&flow->ufid));

    queue_netdev_flow_put(pmd, flow, match, actions, actions_len, false);

    if (OVS_UNLIKELY(!VLOG_DROP_DBG((&upcall_rl)))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        struct ofpbuf key_buf, mask_buf;
        struct odp_flow_key_parms odp_parms = {
            .flow = &match->flow,
            .mask = &match->wc.masks,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key_buf, 0);
        ofpbuf_init(&mask_buf, 0);

        odp_flow_key_from_flow(&odp_parms, &key_buf);
        odp_parms.key_buf = &key_buf;
        odp_flow_key_from_mask(&odp_parms, &mask_buf);

        ds_put_cstr(&ds, "flow_add: ");
        odp_format_ufid(ufid, &ds);
        ds_put_cstr(&ds, " mega_");
        odp_format_ufid(&flow->mega_ufid, &ds);
        ds_put_cstr(&ds, " ");
        odp_flow_format(key_buf.data, key_buf.size,
                        mask_buf.data, mask_buf.size,
                        NULL, &ds, false);
        ds_put_cstr(&ds, ", actions:");
        format_odp_actions(&ds, actions, actions_len, NULL);

        VLOG_DBG("%s", ds_cstr(&ds));

        ofpbuf_uninit(&key_buf);
        ofpbuf_uninit(&mask_buf);

        /* Add a printout of the actual match installed. */
        struct match m;
        ds_clear(&ds);
        ds_put_cstr(&ds, "flow match: ");
        miniflow_expand(&flow->cr.flow.mf, &m.flow);
        miniflow_expand(&flow->cr.mask->mf, &m.wc.masks);
        memset(&m.tun_md, 0, sizeof m.tun_md);
        match_format(&m, NULL, &ds, OFP_DEFAULT_PRIORITY);

        VLOG_DBG("%s", ds_cstr(&ds));

        ds_destroy(&ds);
    }

    return flow;
}

static int
flow_put_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct netdev_flow_key *key,
                struct match *match,
                ovs_u128 *ufid,
                const struct dpif_flow_put *put,
                struct dpif_flow_stats *stats)
{
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
    if (!netdev_flow) {
        if (put->flags & DPIF_FP_CREATE) {
            dp_netdev_flow_add(pmd, match, ufid, put->actions,
                               put->actions_len);
        } else {
            error = ENOENT;
        }
    } else {
        if (put->flags & DPIF_FP_MODIFY) {
            struct dp_netdev_actions *new_actions;
            struct dp_netdev_actions *old_actions;

            new_actions = dp_netdev_actions_create(put->actions,
                                                   put->actions_len);

            old_actions = dp_netdev_flow_get_actions(netdev_flow);
            ovsrcu_set(&netdev_flow->actions, new_actions);

            queue_netdev_flow_put(pmd, netdev_flow, match,
                                  put->actions, put->actions_len, true);

            if (stats) {
                get_dpif_flow_status(pmd->dp, netdev_flow, stats, NULL);
            }
            if (put->flags & DPIF_FP_ZERO_STATS) {
                /* XXX: The userspace datapath uses thread local statistics
                 * (for flows), which should be updated only by the owning
                 * thread.  Since we cannot write on stats memory here,
                 * we choose not to support this flag.  Please note:
                 * - This feature is currently used only by dpctl commands with
                 *   option --clear.
                 * - Should the need arise, this operation can be implemented
                 *   by keeping a base value (to be update here) for each
                 *   counter, and subtracting it before outputting the stats */
                error = EOPNOTSUPP;
            }

            ovsrcu_postpone(dp_netdev_actions_free, old_actions);
        } else if (put->flags & DPIF_FP_CREATE) {
            error = EEXIST;
        } else {
            /* Overlapping flow. */
            error = EINVAL;
        }
    }
    ovs_mutex_unlock(&pmd->flow_mutex);
    return error;
}

static int
dpif_netdev_flow_put(struct dpif *dpif, const struct dpif_flow_put *put)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct netdev_flow_key key, mask;
    struct dp_netdev_pmd_thread *pmd;
    struct match match;
    ovs_u128 ufid;
    int error;
    bool probe = put->flags & DPIF_FP_PROBE;

    if (put->stats) {
        memset(put->stats, 0, sizeof *put->stats);
    }
    error = dpif_netdev_flow_from_nlattrs(put->key, put->key_len, &match.flow,
                                          probe);
    if (error) {
        return error;
    }
    error = dpif_netdev_mask_from_nlattrs(put->key, put->key_len,
                                          put->mask, put->mask_len,
                                          &match.flow, &match.wc, probe);
    if (error) {
        return error;
    }

    if (match.wc.masks.in_port.odp_port != ODPP_NONE) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_ERR_RL(&rl, "failed to put%s flow: in_port is not an exact match",
                    (put->flags & DPIF_FP_CREATE) ? "[create]"
                    : (put->flags & DPIF_FP_MODIFY) ? "[modify]" : "[zero]");
        return EINVAL;
    }

    if (put->ufid) {
        ufid = *put->ufid;
    } else {
        odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in handle_packet_upcall(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    /* Must produce a netdev_flow_key for lookup.
     * Use the same method as employed to create the key when adding
     * the flow to the dplcs to make sure they match. */
    netdev_flow_mask_init(&mask, &match);
    netdev_flow_key_init_masked(&key, &match.flow, &mask);

    if (put->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_put_on_pmd(pmd, &key, &match, &ufid, put,
                                        &pmd_stats);
            if (pmd_error) {
                error = pmd_error;
            } else if (put->stats) {
                put->stats->n_packets += pmd_stats.n_packets;
                put->stats->n_bytes += pmd_stats.n_bytes;
                put->stats->used = MAX(put->stats->used, pmd_stats.used);
                put->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, put->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_put_on_pmd(pmd, &key, &match, &ufid, put, put->stats);
        dp_netdev_pmd_unref(pmd);
    }

    return error;
}

static int
flow_del_on_pmd(struct dp_netdev_pmd_thread *pmd,
                struct dpif_flow_stats *stats,
                const struct dpif_flow_del *del)
{
    struct dp_netdev_flow *netdev_flow;
    int error = 0;

    ovs_mutex_lock(&pmd->flow_mutex);
    netdev_flow = dp_netdev_pmd_find_flow(pmd, del->ufid, del->key,
                                          del->key_len);
    if (netdev_flow) {
        if (stats) {
            get_dpif_flow_status(pmd->dp, netdev_flow, stats, NULL);
        }
        dp_netdev_pmd_remove_flow(pmd, netdev_flow);
    } else {
        error = ENOENT;
    }
    ovs_mutex_unlock(&pmd->flow_mutex);

    return error;
}

static int
dpif_netdev_flow_del(struct dpif *dpif, const struct dpif_flow_del *del)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    int error = 0;

    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

    if (del->pmd_id == PMD_ID_NULL) {
        if (cmap_count(&dp->poll_threads) == 0) {
            return EINVAL;
        }
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            struct dpif_flow_stats pmd_stats;
            int pmd_error;

            pmd_error = flow_del_on_pmd(pmd, &pmd_stats, del);
            if (pmd_error) {
                error = pmd_error;
            } else if (del->stats) {
                del->stats->n_packets += pmd_stats.n_packets;
                del->stats->n_bytes += pmd_stats.n_bytes;
                del->stats->used = MAX(del->stats->used, pmd_stats.used);
                del->stats->tcp_flags |= pmd_stats.tcp_flags;
            }
        }
    } else {
        pmd = dp_netdev_get_pmd(dp, del->pmd_id);
        if (!pmd) {
            return EINVAL;
        }
        error = flow_del_on_pmd(pmd, del->stats, del);
        dp_netdev_pmd_unref(pmd);
    }


    return error;
}

struct dpif_netdev_flow_dump {
    struct dpif_flow_dump up;
    struct cmap_position poll_thread_pos;
    struct cmap_position flow_pos;
    struct dp_netdev_pmd_thread *cur_pmd;
    int status;
    struct ovs_mutex mutex;
};

static struct dpif_netdev_flow_dump *
dpif_netdev_flow_dump_cast(struct dpif_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct dpif_netdev_flow_dump, up);
}

static struct dpif_flow_dump *
dpif_netdev_flow_dump_create(const struct dpif *dpif_, bool terse,
                             struct dpif_flow_dump_types *types OVS_UNUSED)
{
    struct dpif_netdev_flow_dump *dump;

    dump = xzalloc(sizeof *dump);
    dpif_flow_dump_init(&dump->up, dpif_);
    dump->up.terse = terse;
    ovs_mutex_init(&dump->mutex);

    return &dump->up;
}

static int
dpif_netdev_flow_dump_destroy(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);

    ovs_mutex_destroy(&dump->mutex);
    free(dump);
    return 0;
}

struct dpif_netdev_flow_dump_thread {
    struct dpif_flow_dump_thread up;
    struct dpif_netdev_flow_dump *dump;
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
};

static struct dpif_netdev_flow_dump_thread *
dpif_netdev_flow_dump_thread_cast(struct dpif_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct dpif_netdev_flow_dump_thread, up);
}

static struct dpif_flow_dump_thread *
dpif_netdev_flow_dump_thread_create(struct dpif_flow_dump *dump_)
{
    struct dpif_netdev_flow_dump *dump = dpif_netdev_flow_dump_cast(dump_);
    struct dpif_netdev_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_flow_dump_thread_init(&thread->up, &dump->up);
    thread->dump = dump;
    return &thread->up;
}

static void
dpif_netdev_flow_dump_thread_destroy(struct dpif_flow_dump_thread *thread_)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);

    free(thread);
}

static int
dpif_netdev_flow_dump_next(struct dpif_flow_dump_thread *thread_,
                           struct dpif_flow *flows, int max_flows)
{
    struct dpif_netdev_flow_dump_thread *thread
        = dpif_netdev_flow_dump_thread_cast(thread_);
    struct dpif_netdev_flow_dump *dump = thread->dump;
    struct dp_netdev_flow *netdev_flows[FLOW_DUMP_MAX_BATCH];
    struct dpif_netdev *dpif = dpif_netdev_cast(thread->up.dpif);
    struct dp_netdev *dp = get_dp_netdev(&dpif->dpif);
    int n_flows = 0;
    int i;

    ovs_mutex_lock(&dump->mutex);
    if (!dump->status) {
        struct dp_netdev_pmd_thread *pmd = dump->cur_pmd;
        int flow_limit = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

        /* First call to dump_next(), extracts the first pmd thread.
         * If there is no pmd thread, returns immediately. */
        if (!pmd) {
            pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
            if (!pmd) {
                ovs_mutex_unlock(&dump->mutex);
                return n_flows;

            }
        }

        do {
            for (n_flows = 0; n_flows < flow_limit; n_flows++) {
                struct cmap_node *node;

                node = cmap_next_position(&pmd->flow_table, &dump->flow_pos);
                if (!node) {
                    break;
                }
                netdev_flows[n_flows] = CONTAINER_OF(node,
                                                     struct dp_netdev_flow,
                                                     node);
            }
            /* When finishing dumping the current pmd thread, moves to
             * the next. */
            if (n_flows < flow_limit) {
                memset(&dump->flow_pos, 0, sizeof dump->flow_pos);
                dp_netdev_pmd_unref(pmd);
                pmd = dp_netdev_pmd_get_next(dp, &dump->poll_thread_pos);
                if (!pmd) {
                    dump->status = EOF;
                    break;
                }
            }
            /* Keeps the reference to next caller. */
            dump->cur_pmd = pmd;

            /* If the current dump is empty, do not exit the loop, since the
             * remaining pmds could have flows to be dumped.  Just dumps again
             * on the new 'pmd'. */
        } while (!n_flows);
    }
    ovs_mutex_unlock(&dump->mutex);

    for (i = 0; i < n_flows; i++) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[i];
        struct odputil_keybuf *keybuf = &thread->keybuf[i];
        struct dp_netdev_flow *netdev_flow = netdev_flows[i];
        struct dpif_flow *f = &flows[i];
        struct ofpbuf key, mask;

        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        dp_netdev_flow_to_dpif_flow(dp, netdev_flow, &key, &mask, f,
                                    dump->up.terse);
    }

    return n_flows;
}

static int
dpif_netdev_execute(struct dpif *dpif, struct dpif_execute *execute)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    struct dp_packet_batch pp;

    if (dp_packet_size(execute->packet) < ETH_HEADER_LEN ||
        dp_packet_size(execute->packet) > UINT16_MAX) {
        return EINVAL;
    }

    /* Tries finding the 'pmd'.  If NULL is returned, that means
     * the current thread is a non-pmd thread and should use
     * dp_netdev_get_pmd(dp, NON_PMD_CORE_ID). */
    pmd = ovsthread_getspecific(dp->per_pmd_key);
    if (!pmd) {
        pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
        if (!pmd) {
            return EBUSY;
        }
    }

    if (execute->probe) {
        /* If this is part of a probe, Drop the packet, since executing
         * the action may actually cause spurious packets be sent into
         * the network. */
        if (pmd->core_id == NON_PMD_CORE_ID) {
            dp_netdev_pmd_unref(pmd);
        }
        return 0;
    }

    /* If the current thread is non-pmd thread, acquires
     * the 'non_pmd_mutex'. */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
    }

    /* Update current time in PMD context. We don't care about EMC insertion
     * probability, because we are on a slow path. */
    pmd_thread_ctx_time_update(pmd);

    /* The action processing expects the RSS hash to be valid, because
     * it's always initialized at the beginning of datapath processing.
     * In this case, though, 'execute->packet' may not have gone through
     * the datapath at all, it may have been generated by the upper layer
     * (OpenFlow packet-out, BFD frame, ...). */
    if (!dp_packet_rss_valid(execute->packet)) {
        dp_packet_set_rss_hash(execute->packet,
                               flow_hash_5tuple(execute->flow, 0));
    }

    dp_packet_batch_init_packet(&pp, execute->packet);
    dp_netdev_execute_actions(pmd, &pp, false, execute->flow,
                              execute->actions, execute->actions_len);
    dp_netdev_pmd_flush_output_packets(pmd, true);

    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_unlock(&dp->non_pmd_mutex);
        dp_netdev_pmd_unref(pmd);
    }

    return 0;
}

static void
dpif_netdev_operate(struct dpif *dpif, struct dpif_op **ops, size_t n_ops,
                    enum dpif_offload_type offload_type OVS_UNUSED)
{
    size_t i;

    for (i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];

        switch (op->type) {
        case DPIF_OP_FLOW_PUT:
            op->error = dpif_netdev_flow_put(dpif, &op->flow_put);
            break;

        case DPIF_OP_FLOW_DEL:
            op->error = dpif_netdev_flow_del(dpif, &op->flow_del);
            break;

        case DPIF_OP_EXECUTE:
            op->error = dpif_netdev_execute(dpif, &op->execute);
            break;

        case DPIF_OP_FLOW_GET:
            op->error = dpif_netdev_flow_get(dpif, &op->flow_get);
            break;
        }
    }
}

static int
dpif_netdev_offload_stats_get(struct dpif *dpif,
                              struct netdev_custom_stats *stats)
{
    enum {
        DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED,
        DP_NETDEV_HW_OFFLOADS_STATS_INSERTED,
        DP_NETDEV_HW_OFFLOADS_STATS_CT_UNI_DIR_CONNS,
        DP_NETDEV_HW_OFFLOADS_STATS_CT_BI_DIR_CONNS,
    };
    struct {
        const char *name;
        uint64_t total;
    } hwol_stats[] = {
        [DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED] =
            { "     Enqueued offloads", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] =
            { "     Inserted offloads", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_CT_UNI_DIR_CONNS] =
            { "CT uni-dir Connections", 0 },
        [DP_NETDEV_HW_OFFLOADS_STATS_CT_BI_DIR_CONNS] =
            { " CT bi-dir Connections", 0 },
    };
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    unsigned int nb_thread;
    uint64_t *port_nb_offloads;
    uint64_t *nb_offloads;
    unsigned int tid;
    size_t i;

    if (!netdev_is_flow_api_enabled()) {
        return EINVAL;
    }

    nb_thread = netdev_offload_thread_nb() + netdev_is_e2e_cache_enabled();
    stats->size = ARRAY_SIZE(hwol_stats) * (nb_thread + 1);
    stats->counters = xcalloc(stats->size, sizeof *stats->counters);

    nb_offloads = xcalloc(nb_thread, sizeof *nb_offloads);
    port_nb_offloads = xcalloc(nb_thread, sizeof *port_nb_offloads);

    ovs_rwlock_rdlock(&dp->port_rwlock);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        memset(port_nb_offloads, 0, nb_thread * sizeof *port_nb_offloads);
        /* Do not abort on read error from a port, just report 0. */
        if (!netdev_hw_offload_stats_get(port->netdev, port_nb_offloads)) {
            for (i = 0; i < nb_thread; i++) {
                nb_offloads[i] += port_nb_offloads[i];
            }
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    free(port_nb_offloads);

    for (tid = 0; tid < nb_thread; tid++) {
        uint64_t counts[ARRAY_SIZE(hwol_stats)];
        size_t idx = ((tid + 1) * ARRAY_SIZE(hwol_stats));

        memset(counts, 0, sizeof(counts));
        counts[DP_NETDEV_HW_OFFLOADS_STATS_INSERTED] = nb_offloads[tid];
        if (dp_offload_threads != NULL) {
            atomic_read_relaxed(&dp_offload_threads[tid].enqueued_item,
                                &counts[DP_NETDEV_HW_OFFLOADS_STATS_ENQUEUED]);
            atomic_read_relaxed(&dp_offload_threads[tid].ct_uni_dir_connections,
                                &counts[DP_NETDEV_HW_OFFLOADS_STATS_CT_UNI_DIR_CONNS]);
            atomic_read_relaxed(&dp_offload_threads[tid].ct_bi_dir_connections,
                                &counts[DP_NETDEV_HW_OFFLOADS_STATS_CT_BI_DIR_CONNS]);
        }

        for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
            snprintf(stats->counters[idx + i].name,
                     sizeof(stats->counters[idx + i].name),
                     "  [%3u] %s", tid, hwol_stats[i].name);
            stats->counters[idx + i].value = counts[i];
            hwol_stats[i].total += counts[i];
        }
    }

    free(nb_offloads);

    for (i = 0; i < ARRAY_SIZE(hwol_stats); i++) {
        snprintf(stats->counters[i].name, sizeof(stats->counters[i].name),
                 "  Total %s", hwol_stats[i].name);
        stats->counters[i].value = hwol_stats[i].total;
    }

    return 0;
}

/* Enable or Disable PMD auto load balancing. */
static void
set_pmd_auto_lb(struct dp_netdev *dp, bool always_log)
{
    unsigned int cnt = 0;
    struct dp_netdev_pmd_thread *pmd;
    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    uint8_t rebalance_load_thresh;

    bool enable_alb = false;
    bool multi_rxq = false;
    bool pmd_rxq_assign_cyc = dp->pmd_rxq_assign_cyc;

    /* Ensure that there is at least 2 non-isolated PMDs and
     * one of them is polling more than one rxq. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

        if (hmap_count(&pmd->poll_list) > 1) {
            multi_rxq = true;
        }
        if (cnt && multi_rxq) {
                enable_alb = true;
                break;
        }
        cnt++;
    }

    /* Enable auto LB if it is requested and cycle based assignment is true. */
    enable_alb = enable_alb && pmd_rxq_assign_cyc &&
                    pmd_alb->auto_lb_requested;

    if (pmd_alb->is_enabled != enable_alb || always_log) {
        pmd_alb->is_enabled = enable_alb;
        if (pmd_alb->is_enabled) {
            atomic_read_relaxed(&pmd_alb->rebalance_load_thresh,
                                &rebalance_load_thresh);
            VLOG_INFO("PMD auto load balance is enabled "
                      "interval %"PRIu64" mins, "
                      "pmd load threshold %"PRIu8"%%, "
                      "improvement threshold %"PRIu8"%%",
                       pmd_alb->rebalance_intvl / MIN_TO_MSEC,
                       rebalance_load_thresh,
                       pmd_alb->rebalance_improve_thresh);

        } else {
            pmd_alb->rebalance_poll_timer = 0;
            VLOG_INFO("PMD auto load balance is disabled");
        }
    }
}

static struct ovsthread_once e2e_cache_thread_once
    = OVSTHREAD_ONCE_INITIALIZER;
static void *dp_netdev_e2e_cache_main(void *arg);

/* Applies datapath configuration from the database. Some of the changes are
 * actually applied in dpif_netdev_run(). */
static int
dpif_netdev_set_config(struct dpif *dpif, const struct smap *other_config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    const char *cmask = smap_get(other_config, "pmd-cpu-mask");
    const char *pmd_rxq_assign = smap_get_def(other_config, "pmd-rxq-assign",
                                             "cycles");
    unsigned long long insert_prob =
        smap_get_ullong(other_config, "emc-insert-inv-prob",
                        DEFAULT_EM_FLOW_INSERT_INV_PROB);
    uint32_t insert_min, cur_min;
    uint32_t tx_flush_interval, cur_tx_flush_interval;
    uint64_t rebalance_intvl;
    uint8_t rebalance_load, cur_rebalance_load;
    uint8_t rebalance_improve;
    bool log_autolb = false;

    tx_flush_interval = smap_get_int(other_config, "tx-flush-interval",
                                     DEFAULT_TX_FLUSH_INTERVAL);
    atomic_read_relaxed(&dp->tx_flush_interval, &cur_tx_flush_interval);
    if (tx_flush_interval != cur_tx_flush_interval) {
        atomic_store_relaxed(&dp->tx_flush_interval, tx_flush_interval);
        VLOG_INFO("Flushing interval for tx queues set to %"PRIu32" us",
                  tx_flush_interval);
    }

    if (!nullable_string_is_equal(dp->pmd_cmask, cmask)) {
        free(dp->pmd_cmask);
        dp->pmd_cmask = nullable_xstrdup(cmask);
        dp_netdev_request_reconfigure(dp);
    }

    atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
    if (insert_prob <= UINT32_MAX) {
        insert_min = insert_prob == 0 ? 0 : UINT32_MAX / insert_prob;
    } else {
        insert_min = DEFAULT_EM_FLOW_INSERT_MIN;
        insert_prob = DEFAULT_EM_FLOW_INSERT_INV_PROB;
    }

    if (insert_min != cur_min) {
        atomic_store_relaxed(&dp->emc_insert_min, insert_min);
        if (insert_min == 0) {
            VLOG_INFO("EMC insertion probability changed to zero");
        } else {
            VLOG_INFO("EMC insertion probability changed to 1/%llu (~%.2f%%)",
                      insert_prob, (100 / (float)insert_prob));
        }
    }

    bool perf_enabled = smap_get_bool(other_config, "pmd-perf-metrics", false);
    bool cur_perf_enabled;
    atomic_read_relaxed(&dp->pmd_perf_metrics, &cur_perf_enabled);
    if (perf_enabled != cur_perf_enabled) {
        atomic_store_relaxed(&dp->pmd_perf_metrics, perf_enabled);
        if (perf_enabled) {
            VLOG_INFO("PMD performance metrics collection enabled");
        } else {
            VLOG_INFO("PMD performance metrics collection disabled");
        }
    }

    bool smc_enable = smap_get_bool(other_config, "smc-enable", false);
    bool cur_smc;
    atomic_read_relaxed(&dp->smc_enable_db, &cur_smc);
    if (smc_enable != cur_smc) {
        atomic_store_relaxed(&dp->smc_enable_db, smc_enable);
        if (smc_enable) {
            VLOG_INFO("SMC cache is enabled");
        } else {
            VLOG_INFO("SMC cache is disabled");
        }
    }

    dp_netdev_e2e_cache_enabled = netdev_is_e2e_cache_enabled();
#ifdef E2E_CACHE_ENABLED
    dp_netdev_e2e_cache_size = netdev_get_e2e_cache_size();
    if (dp_netdev_e2e_cache_enabled) {
        static bool done = false;
        int i_value = smap_get_int(other_config, "e2e-cache-trace-q-size",
                                   E2E_CACHE_MAX_TRACE_Q_SIZE);
        if (i_value < 0) {
            i_value = 0;
        }
        if (!done || dp_netdev_e2e_cache_trace_q_size != (uint32_t) i_value) {
            dp_netdev_e2e_cache_trace_q_size = (uint32_t) i_value;
            if (dp_netdev_e2e_cache_trace_q_size) {
                VLOG_INFO("E2E cache trace queue size %u",
                        dp_netdev_e2e_cache_trace_q_size);
            } else {
                VLOG_INFO("E2E cache trace queue unlimited");
            }
            done = true;
        }
        if (ovsthread_once_start(&e2e_cache_thread_once)) {
            ovs_thread_create("e2e_cache", dp_netdev_e2e_cache_main, NULL);
            ovsthread_once_done(&e2e_cache_thread_once);
        }
    }
#endif

    bool pmd_rxq_assign_cyc = !strcmp(pmd_rxq_assign, "cycles");
    if (!pmd_rxq_assign_cyc && strcmp(pmd_rxq_assign, "roundrobin")) {
        VLOG_WARN("Unsupported Rxq to PMD assignment mode in pmd-rxq-assign. "
                      "Defaulting to 'cycles'.");
        pmd_rxq_assign_cyc = true;
        pmd_rxq_assign = "cycles";
    }
    if (dp->pmd_rxq_assign_cyc != pmd_rxq_assign_cyc) {
        dp->pmd_rxq_assign_cyc = pmd_rxq_assign_cyc;
        VLOG_INFO("Rxq to PMD assignment mode changed to: \'%s\'.",
                  pmd_rxq_assign);
        dp_netdev_request_reconfigure(dp);
    }

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    bool cur_rebalance_requested = pmd_alb->auto_lb_requested;
    pmd_alb->auto_lb_requested = smap_get_bool(other_config, "pmd-auto-lb",
                              false);
    if (cur_rebalance_requested != pmd_alb->auto_lb_requested) {
        log_autolb = true;
    }

    rebalance_intvl = smap_get_int(other_config, "pmd-auto-lb-rebal-interval",
                                   ALB_REBALANCE_INTERVAL);

    /* Input is in min, convert it to msec. */
    rebalance_intvl =
        rebalance_intvl ? rebalance_intvl * MIN_TO_MSEC : MIN_TO_MSEC;

    if (pmd_alb->rebalance_intvl != rebalance_intvl) {
        pmd_alb->rebalance_intvl = rebalance_intvl;
        VLOG_INFO("PMD auto load balance interval set to "
                  "%"PRIu64" mins\n", rebalance_intvl / MIN_TO_MSEC);
        log_autolb = true;
    }

    rebalance_improve = smap_get_int(other_config,
                                     "pmd-auto-lb-improvement-threshold",
                                     ALB_IMPROVEMENT_THRESHOLD);
    if (rebalance_improve > 100) {
        rebalance_improve = ALB_IMPROVEMENT_THRESHOLD;
    }
    if (rebalance_improve != pmd_alb->rebalance_improve_thresh) {
        pmd_alb->rebalance_improve_thresh = rebalance_improve;
        VLOG_INFO("PMD auto load balance improvement threshold set to "
                  "%"PRIu8"%%", rebalance_improve);
        log_autolb = true;
    }

    rebalance_load = smap_get_int(other_config, "pmd-auto-lb-load-threshold",
                                  ALB_LOAD_THRESHOLD);
    if (rebalance_load > 100) {
        rebalance_load = ALB_LOAD_THRESHOLD;
    }
    atomic_read_relaxed(&pmd_alb->rebalance_load_thresh, &cur_rebalance_load);
    if (rebalance_load != cur_rebalance_load) {
        atomic_store_relaxed(&pmd_alb->rebalance_load_thresh,
                             rebalance_load);
        VLOG_INFO("PMD auto load balance load threshold set to %"PRIu8"%%",
                  rebalance_load);
        log_autolb = true;
    }
    set_pmd_auto_lb(dp, log_autolb);
    return 0;
}

/* Parses affinity list and returns result in 'core_ids'. */
static int
parse_affinity_list(const char *affinity_list, unsigned *core_ids, int n_rxq)
{
    unsigned i;
    char *list, *copy, *key, *value;
    int error = 0;

    for (i = 0; i < n_rxq; i++) {
        core_ids[i] = OVS_CORE_UNSPEC;
    }

    if (!affinity_list) {
        return 0;
    }

    list = copy = xstrdup(affinity_list);

    while (ofputil_parse_key_value(&list, &key, &value)) {
        int rxq_id, core_id;

        if (!str_to_int(key, 0, &rxq_id) || rxq_id < 0
            || !str_to_int(value, 0, &core_id) || core_id < 0) {
            error = EINVAL;
            break;
        }

        if (rxq_id < n_rxq) {
            core_ids[rxq_id] = core_id;
        }
    }

    free(copy);
    return error;
}

/* Parses 'affinity_list' and applies configuration if it is valid. */
static int
dpif_netdev_port_set_rxq_affinity(struct dp_netdev_port *port,
                                  const char *affinity_list)
{
    unsigned *core_ids, i;
    int error = 0;

    core_ids = xmalloc(port->n_rxq * sizeof *core_ids);
    if (parse_affinity_list(affinity_list, core_ids, port->n_rxq)) {
        error = EINVAL;
        goto exit;
    }

    for (i = 0; i < port->n_rxq; i++) {
        port->rxqs[i].core_id = core_ids[i];
    }

exit:
    free(core_ids);
    return error;
}

/* Returns 'true' if one of the 'port's RX queues exists in 'poll_list'
 * of given PMD thread. */
static bool
dpif_netdev_pmd_polls_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_port *port)
    OVS_EXCLUDED(pmd->port_mutex)
{
    struct rxq_poll *poll;
    bool found = false;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        if (port == poll->rxq->port) {
            found = true;
            break;
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
    return found;
}

/* Updates port configuration from the database.  The changes are actually
 * applied in dpif_netdev_run(). */
static int
dpif_netdev_port_set_config(struct dpif *dpif, odp_port_t port_no,
                            const struct smap *cfg)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_port *port;
    int error = 0;
    const char *affinity_list = smap_get(cfg, "pmd-rxq-affinity");
    bool emc_enabled = smap_get_bool(cfg, "emc-enable", true);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    error = get_port_by_number(dp, port_no, &port);
    if (error) {
        goto unlock;
    }

    if (emc_enabled != port->emc_enabled) {
        struct dp_netdev_pmd_thread *pmd;
        struct ds ds = DS_EMPTY_INITIALIZER;
        uint32_t cur_min, insert_prob;

        port->emc_enabled = emc_enabled;
        /* Mark for reload all the threads that polls this port and request
         * for reconfiguration for the actual reloading of threads. */
        CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
            if (dpif_netdev_pmd_polls_port(pmd, port)) {
                pmd->need_reload = true;
            }
        }
        dp_netdev_request_reconfigure(dp);

        ds_put_format(&ds, "%s: EMC has been %s.",
                      netdev_get_name(port->netdev),
                      (emc_enabled) ? "enabled" : "disabled");
        if (emc_enabled) {
            ds_put_cstr(&ds, " Current insertion probability is ");
            atomic_read_relaxed(&dp->emc_insert_min, &cur_min);
            if (!cur_min) {
                ds_put_cstr(&ds, "zero.");
            } else {
                insert_prob = UINT32_MAX / cur_min;
                ds_put_format(&ds, "1/%"PRIu32" (~%.2f%%).",
                              insert_prob, 100 / (float) insert_prob);
            }
        }
        VLOG_INFO("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    /* Checking for RXq affinity changes. */
    if (!netdev_is_pmd(port->netdev)
        || nullable_string_is_equal(affinity_list, port->rxq_affinity_list)) {
        goto unlock;
    }

    error = dpif_netdev_port_set_rxq_affinity(port, affinity_list);
    if (error) {
        goto unlock;
    }
    free(port->rxq_affinity_list);
    port->rxq_affinity_list = nullable_xstrdup(affinity_list);

    dp_netdev_request_reconfigure(dp);
unlock:
    ovs_rwlock_unlock(&dp->port_rwlock);
    return error;
}

static int
dpif_netdev_queue_to_priority(const struct dpif *dpif OVS_UNUSED,
                              uint32_t queue_id, uint32_t *priority)
{
    *priority = queue_id;
    return 0;
}


/* Creates and returns a new 'struct dp_netdev_actions', whose actions are
 * a copy of the 'size' bytes of 'actions' input parameters. */
struct dp_netdev_actions *
dp_netdev_actions_create(const struct nlattr *actions, size_t size)
{
    struct dp_netdev_actions *netdev_actions;

    netdev_actions = xmalloc(sizeof *netdev_actions + size);
    memcpy(netdev_actions->actions, actions, size);
    netdev_actions->size = size;

    return netdev_actions;
}

struct dp_netdev_actions *
dp_netdev_flow_get_actions(const struct dp_netdev_flow *flow)
{
    return ovsrcu_get(struct dp_netdev_actions *, &flow->actions);
}

static void
dp_netdev_actions_free(struct dp_netdev_actions *actions)
{
    free(actions);
}

static void
dp_netdev_rxq_set_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
   atomic_store_relaxed(&rx->cycles[type], cycles);
}

static void
dp_netdev_rxq_add_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type,
                         unsigned long long cycles)
{
    non_atomic_ullong_add(&rx->cycles[type], cycles);
}

static uint64_t
dp_netdev_rxq_get_cycles(struct dp_netdev_rxq *rx,
                         enum rxq_cycles_counter_type type)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles[type], &processing_cycles);
    return processing_cycles;
}

static void
dp_netdev_rxq_set_intrvl_cycles(struct dp_netdev_rxq *rx,
                                unsigned long long cycles)
{
    unsigned int idx = rx->intrvl_idx++ % PMD_RXQ_INTERVAL_MAX;
    atomic_store_relaxed(&rx->cycles_intrvl[idx], cycles);
}

static uint64_t
dp_netdev_rxq_get_intrvl_cycles(struct dp_netdev_rxq *rx, unsigned idx)
{
    unsigned long long processing_cycles;
    atomic_read_relaxed(&rx->cycles_intrvl[idx], &processing_cycles);
    return processing_cycles;
}

#if ATOMIC_ALWAYS_LOCK_FREE_8B
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd)
{
    bool pmd_perf_enabled;
    atomic_read_relaxed(&pmd->dp->pmd_perf_metrics, &pmd_perf_enabled);
    return pmd_perf_enabled;
}
#else
/* If stores and reads of 64-bit integers are not atomic, the full PMD
 * performance metrics are not available as locked access to 64 bit
 * integers would be prohibitively expensive. */
static inline bool
pmd_perf_metrics_enabled(const struct dp_netdev_pmd_thread *pmd OVS_UNUSED)
{
    return false;
}
#endif

static int
dp_netdev_pmd_flush_output_on_port(struct dp_netdev_pmd_thread *pmd,
                                   struct tx_port *p)
{
    int i;
    int tx_qid;
    int output_cnt;
    bool dynamic_txqs;
    struct cycle_timer timer;
    uint64_t cycles;
    uint32_t tx_flush_interval;

    cycle_timer_start(&pmd->perf_stats, &timer);

    dynamic_txqs = p->port->dynamic_txqs;
    if (dynamic_txqs) {
        tx_qid = dpif_netdev_xps_get_tx_qid(pmd, p);
    } else {
        tx_qid = pmd->static_tx_qid;
    }

    output_cnt = dp_packet_batch_size(&p->output_pkts);
    ovs_assert(output_cnt > 0);

    netdev_send(p->port->netdev, tx_qid, &p->output_pkts, dynamic_txqs);
    dp_packet_batch_init(&p->output_pkts);

    /* Update time of the next flush. */
    atomic_read_relaxed(&pmd->dp->tx_flush_interval, &tx_flush_interval);
    p->flush_time = pmd->ctx.now + tx_flush_interval;

    ovs_assert(pmd->n_output_batches > 0);
    pmd->n_output_batches--;

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_PKTS, output_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SENT_BATCHES, 1);

    /* Distribute send cycles evenly among transmitted packets and assign to
     * their respective rx queues. */
    cycles = cycle_timer_stop(&pmd->perf_stats, &timer) / output_cnt;
    for (i = 0; i < output_cnt; i++) {
        if (p->output_pkts_rxqs[i]) {
            dp_netdev_rxq_add_cycles(p->output_pkts_rxqs[i],
                                     RXQ_CYCLES_PROC_CURR, cycles);
        }
    }

    return output_cnt;
}

static int
dp_netdev_pmd_flush_output_packets(struct dp_netdev_pmd_thread *pmd,
                                   bool force)
{
    struct tx_port *p;
    int output_cnt = 0;

    if (!pmd->n_output_batches) {
        return 0;
    }

    HMAP_FOR_EACH (p, node, &pmd->send_port_cache) {
        if (!dp_packet_batch_is_empty(&p->output_pkts)
            && (force || pmd->ctx.now >= p->flush_time)) {
            output_cnt += dp_netdev_pmd_flush_output_on_port(pmd, p);
        }
    }
    return output_cnt;
}

static int
dp_netdev_process_rxq_port(struct dp_netdev_pmd_thread *pmd,
                           struct dp_netdev_rxq *rxq,
                           odp_port_t port_no)
{
    struct pmd_perf_stats *s = &pmd->perf_stats;
    struct dp_packet_batch batch;
    struct cycle_timer timer;
    int error;
    int batch_cnt = 0;
    int rem_qlen = 0, *qlen_p = NULL;
    uint64_t cycles;

    /* Measure duration for polling and processing rx burst. */
    cycle_timer_start(&pmd->perf_stats, &timer);

    pmd->ctx.last_rxq = rxq;
    dp_packet_batch_init(&batch);

    /* Fetch the rx queue length only for vhostuser ports. */
    if (pmd_perf_metrics_enabled(pmd) && rxq->is_vhost) {
        qlen_p = &rem_qlen;
    }

    error = netdev_rxq_recv(rxq->rx, &batch, qlen_p);
    if (!error) {
        /* At least one packet received. */
        *recirc_depth_get() = 0;
        pmd_thread_ctx_time_update(pmd);
        batch_cnt = dp_packet_batch_size(&batch);
        if (pmd_perf_metrics_enabled(pmd)) {
            /* Update batch histogram. */
            s->current.batches++;
            histogram_add_sample(&s->pkts_per_batch, batch_cnt);
            /* Update the maximum vhost rx queue fill level. */
            if (rxq->is_vhost && rem_qlen >= 0) {
                uint32_t qfill = batch_cnt + rem_qlen;
                if (qfill > s->current.max_vhost_qfill) {
                    s->current.max_vhost_qfill = qfill;
                }
            }
        }
        /* Process packet batch. */
        dp_netdev_input(pmd, &batch, port_no);

        /* Assign processing cycles to rx queue. */
        cycles = cycle_timer_stop(&pmd->perf_stats, &timer);
        dp_netdev_rxq_add_cycles(rxq, RXQ_CYCLES_PROC_CURR, cycles);

        dp_netdev_pmd_flush_output_packets(pmd, false);
    } else {
        /* Discard cycles. */
        cycle_timer_stop(&pmd->perf_stats, &timer);
        if (error != EAGAIN && error != EOPNOTSUPP) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_ERR_RL(&rl, "error receiving data from %s: %s",
                    netdev_rxq_get_name(rxq->rx), ovs_strerror(error));
        }
    }

    pmd->ctx.last_rxq = NULL;

    return batch_cnt;
}

static struct tx_port *
tx_port_lookup(const struct hmap *hmap, odp_port_t port_no)
{
    struct tx_port *tx;

    HMAP_FOR_EACH_IN_BUCKET (tx, node, hash_port_no(port_no), hmap) {
        if (tx->port->port_no == port_no) {
            return tx;
        }
    }

    return NULL;
}

static struct tx_bond *
tx_bond_lookup(const struct cmap *tx_bonds, uint32_t bond_id)
{
    uint32_t hash = hash_bond_id(bond_id);
    struct tx_bond *tx;

    CMAP_FOR_EACH_WITH_HASH (tx, node, hash, tx_bonds) {
        if (tx->bond_id == bond_id) {
            return tx;
        }
    }
    return NULL;
}

static int
port_reconfigure(struct dp_netdev_port *port)
{
    struct netdev *netdev = port->netdev;
    int i, err;

    /* Closes the existing 'rxq's. */
    for (i = 0; i < port->n_rxq; i++) {
        netdev_rxq_close(port->rxqs[i].rx);
        port->rxqs[i].rx = NULL;
    }
    unsigned last_nrxq = port->n_rxq;
    port->n_rxq = 0;

    /* Allows 'netdev' to apply the pending configuration changes. */
    if (netdev_is_reconf_required(netdev) || port->need_reconfigure) {
        err = netdev_reconfigure(netdev);
        if (err && (err != EOPNOTSUPP)) {
            VLOG_ERR("Failed to set interface %s new configuration",
                     netdev_get_name(netdev));
            return err;
        }
    }
    /* If the netdev_reconfigure() above succeeds, reopens the 'rxq's. */
    port->rxqs = xrealloc(port->rxqs,
                          sizeof *port->rxqs * netdev_n_rxq(netdev));
    /* Realloc 'used' counters for tx queues. */
    free(port->txq_used);
    port->txq_used = xcalloc(netdev_n_txq(netdev), sizeof *port->txq_used);

    for (i = 0; i < netdev_n_rxq(netdev); i++) {
        bool new_queue = i >= last_nrxq;
        if (new_queue) {
            memset(&port->rxqs[i], 0, sizeof port->rxqs[i]);
        }

        port->rxqs[i].port = port;
        port->rxqs[i].is_vhost = !strncmp(port->type, "dpdkvhost", 9);

        err = netdev_rxq_open(netdev, &port->rxqs[i].rx, i);
        if (err) {
            return err;
        }
        port->n_rxq++;
    }

    /* Parse affinity list to apply configuration for new queues. */
    dpif_netdev_port_set_rxq_affinity(port, port->rxq_affinity_list);

    /* If reconfiguration was successful mark it as such, so we can use it */
    port->need_reconfigure = false;

    return 0;
}

struct rr_numa_list {
    struct hmap numas;  /* Contains 'struct rr_numa' */
};

struct rr_numa {
    struct hmap_node node;

    int numa_id;

    /* Non isolated pmds on numa node 'numa_id' */
    struct dp_netdev_pmd_thread **pmds;
    int n_pmds;

    int cur_index;
    bool idx_inc;
};

static struct rr_numa *
rr_numa_list_lookup(struct rr_numa_list *rr, int numa_id)
{
    struct rr_numa *numa;

    HMAP_FOR_EACH_WITH_HASH (numa, node, hash_int(numa_id, 0), &rr->numas) {
        if (numa->numa_id == numa_id) {
            return numa;
        }
    }

    return NULL;
}

/* Returns the next node in numa list following 'numa' in round-robin fashion.
 * Returns first node if 'numa' is a null pointer or the last node in 'rr'.
 * Returns NULL if 'rr' numa list is empty. */
static struct rr_numa *
rr_numa_list_next(struct rr_numa_list *rr, const struct rr_numa *numa)
{
    struct hmap_node *node = NULL;

    if (numa) {
        node = hmap_next(&rr->numas, &numa->node);
    }
    if (!node) {
        node = hmap_first(&rr->numas);
    }

    return (node) ? CONTAINER_OF(node, struct rr_numa, node) : NULL;
}

static void
rr_numa_list_populate(struct dp_netdev *dp, struct rr_numa_list *rr)
{
    struct dp_netdev_pmd_thread *pmd;
    struct rr_numa *numa;

    hmap_init(&rr->numas);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID || pmd->isolated) {
            continue;
        }

        numa = rr_numa_list_lookup(rr, pmd->numa_id);
        if (!numa) {
            numa = xzalloc(sizeof *numa);
            numa->numa_id = pmd->numa_id;
            hmap_insert(&rr->numas, &numa->node, hash_int(pmd->numa_id, 0));
        }
        numa->n_pmds++;
        numa->pmds = xrealloc(numa->pmds, numa->n_pmds * sizeof *numa->pmds);
        numa->pmds[numa->n_pmds - 1] = pmd;
        /* At least one pmd so initialise curr_idx and idx_inc. */
        numa->cur_index = 0;
        numa->idx_inc = true;
    }
}

/*
 * Returns the next pmd from the numa node.
 *
 * If 'updown' is 'true' it will alternate between selecting the next pmd in
 * either an up or down walk, switching between up/down when the first or last
 * core is reached. e.g. 1,2,3,3,2,1,1,2...
 *
 * If 'updown' is 'false' it will select the next pmd wrapping around when last
 * core reached. e.g. 1,2,3,1,2,3,1,2...
 */
static struct dp_netdev_pmd_thread *
rr_numa_get_pmd(struct rr_numa *numa, bool updown)
{
    int numa_idx = numa->cur_index;

    if (numa->idx_inc == true) {
        /* Incrementing through list of pmds. */
        if (numa->cur_index == numa->n_pmds-1) {
            /* Reached the last pmd. */
            if (updown) {
                numa->idx_inc = false;
            } else {
                numa->cur_index = 0;
            }
        } else {
            numa->cur_index++;
        }
    } else {
        /* Decrementing through list of pmds. */
        if (numa->cur_index == 0) {
            /* Reached the first pmd. */
            numa->idx_inc = true;
        } else {
            numa->cur_index--;
        }
    }
    return numa->pmds[numa_idx];
}

static void
rr_numa_list_destroy(struct rr_numa_list *rr)
{
    struct rr_numa *numa;

    HMAP_FOR_EACH_POP (numa, node, &rr->numas) {
        free(numa->pmds);
        free(numa);
    }
    hmap_destroy(&rr->numas);
}

/* Sort Rx Queues by the processing cycles they are consuming. */
static int
compare_rxq_cycles(const void *a, const void *b)
{
    struct dp_netdev_rxq *qa;
    struct dp_netdev_rxq *qb;
    uint64_t cycles_qa, cycles_qb;

    qa = *(struct dp_netdev_rxq **) a;
    qb = *(struct dp_netdev_rxq **) b;

    cycles_qa = dp_netdev_rxq_get_cycles(qa, RXQ_CYCLES_PROC_HIST);
    cycles_qb = dp_netdev_rxq_get_cycles(qb, RXQ_CYCLES_PROC_HIST);

    if (cycles_qa != cycles_qb) {
        return (cycles_qa < cycles_qb) ? 1 : -1;
    } else {
        /* Cycles are the same so tiebreak on port/queue id.
         * Tiebreaking (as opposed to return 0) ensures consistent
         * sort results across multiple OS's. */
        uint32_t port_qa = odp_to_u32(qa->port->port_no);
        uint32_t port_qb = odp_to_u32(qb->port->port_no);
        if (port_qa != port_qb) {
            return port_qa > port_qb ? 1 : -1;
        } else {
            return netdev_rxq_get_queue_id(qa->rx)
                    - netdev_rxq_get_queue_id(qb->rx);
        }
    }
}

/* Assign pmds to queues.  If 'pinned' is true, assign pmds to pinned
 * queues and marks the pmds as isolated.  Otherwise, assign non isolated
 * pmds to unpinned queues.
 *
 * The function doesn't touch the pmd threads, it just stores the assignment
 * in the 'pmd' member of each rxq. */
static void
rxq_scheduling(struct dp_netdev *dp, bool pinned)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;
    struct rr_numa_list rr;
    struct rr_numa *non_local_numa = NULL;
    struct dp_netdev_rxq ** rxqs = NULL;
    int n_rxqs = 0;
    struct rr_numa *numa = NULL;
    int numa_id;
    bool assign_cyc = dp->pmd_rxq_assign_cyc;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (pinned && q->core_id != OVS_CORE_UNSPEC) {
                struct dp_netdev_pmd_thread *pmd;

                pmd = dp_netdev_get_pmd(dp, q->core_id);
                if (!pmd) {
                    VLOG_WARN("There is no PMD thread on core %d. Queue "
                              "%d on port \'%s\' will not be polled.",
                              q->core_id, qid, netdev_get_name(port->netdev));
                } else {
                    q->pmd = pmd;
                    pmd->isolated = true;
                    VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
                              "rx queue %d.", pmd->core_id, pmd->numa_id,
                              netdev_rxq_get_name(q->rx),
                              netdev_rxq_get_queue_id(q->rx));
                    dp_netdev_pmd_unref(pmd);
                }
            } else if (!pinned && q->core_id == OVS_CORE_UNSPEC) {
                uint64_t cycle_hist = 0;

                if (n_rxqs == 0) {
                    rxqs = xmalloc(sizeof *rxqs);
                } else {
                    rxqs = xrealloc(rxqs, sizeof *rxqs * (n_rxqs + 1));
                }

                if (assign_cyc) {
                    /* Sum the queue intervals and store the cycle history. */
                    for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) {
                        cycle_hist += dp_netdev_rxq_get_intrvl_cycles(q, i);
                    }
                    dp_netdev_rxq_set_cycles(q, RXQ_CYCLES_PROC_HIST,
                                             cycle_hist);
                }
                /* Store the queue. */
                rxqs[n_rxqs++] = q;
            }
        }
    }

    if (n_rxqs > 1 && assign_cyc) {
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }

    rr_numa_list_populate(dp, &rr);
    /* Assign the sorted queues to pmds in round robin. */
    for (int i = 0; i < n_rxqs; i++) {
        numa_id = netdev_get_numa_id(rxqs[i]->port->netdev);
        numa = rr_numa_list_lookup(&rr, numa_id);
        if (!numa) {
            /* There are no pmds on the queue's local NUMA node.
               Round robin on the NUMA nodes that do have pmds. */
            non_local_numa = rr_numa_list_next(&rr, non_local_numa);
            if (!non_local_numa) {
                VLOG_ERR("There is no available (non-isolated) pmd "
                         "thread for port \'%s\' queue %d. This queue "
                         "will not be polled. Is pmd-cpu-mask set to "
                         "zero? Or are all PMDs isolated to other "
                         "queues?", netdev_rxq_get_name(rxqs[i]->rx),
                         netdev_rxq_get_queue_id(rxqs[i]->rx));
                continue;
            }
            rxqs[i]->pmd = rr_numa_get_pmd(non_local_numa, assign_cyc);
            VLOG_WARN("There's no available (non-isolated) pmd thread "
                      "on numa node %d. Queue %d on port \'%s\' will "
                      "be assigned to the pmd on core %d "
                      "(numa node %d). Expect reduced performance.",
                      numa_id, netdev_rxq_get_queue_id(rxqs[i]->rx),
                      netdev_rxq_get_name(rxqs[i]->rx),
                      rxqs[i]->pmd->core_id, rxqs[i]->pmd->numa_id);
        } else {
            rxqs[i]->pmd = rr_numa_get_pmd(numa, assign_cyc);
            if (assign_cyc) {
                VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
                          "rx queue %d "
                          "(measured processing cycles %"PRIu64").",
                          rxqs[i]->pmd->core_id, numa_id,
                          netdev_rxq_get_name(rxqs[i]->rx),
                          netdev_rxq_get_queue_id(rxqs[i]->rx),
                          dp_netdev_rxq_get_cycles(rxqs[i],
                                                   RXQ_CYCLES_PROC_HIST));
            } else {
                VLOG_INFO("Core %d on numa node %d assigned port \'%s\' "
                          "rx queue %d.", rxqs[i]->pmd->core_id, numa_id,
                          netdev_rxq_get_name(rxqs[i]->rx),
                          netdev_rxq_get_queue_id(rxqs[i]->rx));
            }
        }
    }

    rr_numa_list_destroy(&rr);
    free(rxqs);
}

static void
reload_affected_pmds(struct dp_netdev *dp)
{
    struct dp_netdev_pmd_thread *pmd;

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            flow_mark_flush(pmd);
            dp_netdev_reload_pmd__(pmd);
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->need_reload) {
            if (pmd->core_id != NON_PMD_CORE_ID) {
                bool reload;

                do {
                    atomic_read_explicit(&pmd->reload, &reload,
                                         memory_order_acquire);
                } while (reload);
            }
            pmd->need_reload = false;
        }
    }
}

static void
reconfigure_pmd_threads(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_pmd_thread *pmd;
    struct ovs_numa_dump *pmd_cores;
    struct ovs_numa_info_core *core;
    struct hmapx to_delete = HMAPX_INITIALIZER(&to_delete);
    struct hmapx_node *node;
    bool changed = false;
    bool need_to_adjust_static_tx_qids = false;

    /* The pmd threads should be started only if there's a pmd port in the
     * datapath.  If the user didn't provide any "pmd-cpu-mask", we start
     * NR_PMD_THREADS per numa node. */
    if (!has_pmd_port(dp)) {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(0);
    } else if (dp->pmd_cmask && dp->pmd_cmask[0]) {
        pmd_cores = ovs_numa_dump_cores_with_cmask(dp->pmd_cmask);
    } else {
        pmd_cores = ovs_numa_dump_n_cores_per_numa(NR_PMD_THREADS);
    }

    /* We need to adjust 'static_tx_qid's only if we're reducing number of
     * PMD threads. Otherwise, new threads will allocate all the freed ids. */
    if (ovs_numa_dump_count(pmd_cores) < cmap_count(&dp->poll_threads) - 1) {
        /* Adjustment is required to keep 'static_tx_qid's sequential and
         * avoid possible issues, for example, imbalanced tx queue usage
         * and unnecessary locking caused by remapping on netdev level. */
        need_to_adjust_static_tx_qids = true;
    }

    /* Check for unwanted pmd threads */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        if (!ovs_numa_dump_contains_core(pmd_cores, pmd->numa_id,
                                                    pmd->core_id)) {
            hmapx_add(&to_delete, pmd);
        } else if (need_to_adjust_static_tx_qids) {
            atomic_store_relaxed(&pmd->reload_tx_qid, true);
            pmd->need_reload = true;
        }
    }

    HMAPX_FOR_EACH (node, &to_delete) {
        pmd = (struct dp_netdev_pmd_thread *) node->data;
        VLOG_INFO("PMD thread on numa_id: %d, core id: %2d destroyed.",
                  pmd->numa_id, pmd->core_id);
        dp_netdev_del_pmd(dp, pmd);
    }
    changed = !hmapx_is_empty(&to_delete);
    hmapx_destroy(&to_delete);

    if (need_to_adjust_static_tx_qids) {
        /* 'static_tx_qid's are not sequential now.
         * Reload remaining threads to fix this. */
        reload_affected_pmds(dp);
    }

    /* Check for required new pmd threads */
    FOR_EACH_CORE_ON_DUMP(core, pmd_cores) {
        pmd = dp_netdev_get_pmd(dp, core->core_id);
        if (!pmd) {
            struct ds name = DS_EMPTY_INITIALIZER;

            pmd = xzalloc(sizeof *pmd);
            dp_netdev_configure_pmd(pmd, dp, core->core_id, core->numa_id);

            ds_put_format(&name, "pmd-c%02d/id:", core->core_id);
            pmd->thread = ovs_thread_create(ds_cstr(&name),
                                            pmd_thread_main, pmd);
            ds_destroy(&name);

            VLOG_INFO("PMD thread on numa_id: %d, core id: %2d created.",
                      pmd->numa_id, pmd->core_id);
            changed = true;
        } else {
            dp_netdev_pmd_unref(pmd);
        }
    }

    if (changed) {
        struct ovs_numa_info_numa *numa;

        /* Log the number of pmd threads per numa node. */
        FOR_EACH_NUMA_ON_DUMP (numa, pmd_cores) {
            VLOG_INFO("There are %"PRIuSIZE" pmd threads on numa node %d",
                      numa->n_cores, numa->numa_id);
        }
    }

    ovs_numa_dump_destroy(pmd_cores);
}

static void
pmd_remove_stale_ports(struct dp_netdev *dp,
                       struct dp_netdev_pmd_thread *pmd)
    OVS_EXCLUDED(pmd->port_mutex)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct rxq_poll *poll, *poll_next;
    struct tx_port *tx, *tx_next;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) {
        struct dp_netdev_port *port = poll->rxq->port;

        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_rxq_from_pmd(pmd, poll);
        }
    }
    HMAP_FOR_EACH_SAFE (tx, tx_next, node, &pmd->tx_ports) {
        struct dp_netdev_port *port = tx->port;

        if (port->need_reconfigure
            || !hmap_contains(&dp->ports, &port->node)) {
            dp_netdev_del_port_tx_from_pmd(pmd, tx);
        }
    }
    ovs_mutex_unlock(&pmd->port_mutex);
}

/* Must be called each time a port is added/removed or the cmask changes.
 * This creates and destroys pmd threads, reconfigures ports, opens their
 * rxqs and assigns all rxqs/txqs to pmd threads. */
static void
reconfigure_datapath(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct hmapx busy_threads = HMAPX_INITIALIZER(&busy_threads);
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_port *port;
    int wanted_txqs;

    dp->last_reconfigure_seq = seq_read(dp->reconfigure_seq);

    /* Step 1: Adjust the pmd threads based on the datapath ports, the cores
     * on the system and the user configuration. */
    reconfigure_pmd_threads(dp);

    wanted_txqs = cmap_count(&dp->poll_threads);

    /* The number of pmd threads might have changed, or a port can be new:
     * adjust the txqs. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_set_tx_multiq(port->netdev, wanted_txqs);
    }

    /* Step 2: Remove from the pmd threads ports that have been removed or
     * need reconfiguration. */

    /* Check for all the ports that need reconfiguration.  We cache this in
     * 'port->need_reconfigure', because netdev_is_reconf_required() can
     * change at any time.
     * Also mark for reconfiguration all ports which will likely change their
     * 'dynamic_txqs' parameter.  It's required to stop using them before
     * changing this setting and it's simpler to mark ports here and allow
     * 'pmd_remove_stale_ports' to remove them from threads.  There will be
     * no actual reconfiguration in 'port_reconfigure' because it's
     * unnecessary.  */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)
            || (port->dynamic_txqs
                != (netdev_n_txq(port->netdev) < wanted_txqs))) {
            port->need_reconfigure = true;
        }
    }

    /* Remove from the pmd threads all the ports that have been deleted or
     * need reconfiguration. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd_remove_stale_ports(dp, pmd);
    }

    /* Reload affected pmd threads.  We must wait for the pmd threads before
     * reconfiguring the ports, because a port cannot be reconfigured while
     * it's being used. */
    reload_affected_pmds(dp);

    /* Step 3: Reconfigure ports. */

    /* We only reconfigure the ports that we determined above, because they're
     * not being used by any pmd thread at the moment.  If a port fails to
     * reconfigure we remove it from the datapath. */
    struct dp_netdev_port *next_port;
    HMAP_FOR_EACH_SAFE (port, next_port, node, &dp->ports) {
        int err;

        if (!port->need_reconfigure) {
            continue;
        }

        err = port_reconfigure(port);
        if (err) {
            hmap_remove(&dp->ports, &port->node);
            seq_change(dp->port_seq);
            port_destroy(port);
        } else {
            port->dynamic_txqs = netdev_n_txq(port->netdev) < wanted_txqs;
        }
    }

    /* Step 4: Compute new rxq scheduling.  We don't touch the pmd threads
     * for now, we just update the 'pmd' pointer in each rxq to point to the
     * wanted thread according to the scheduling policy. */

    /* Reset all the pmd threads to non isolated. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        pmd->isolated = false;
    }

    /* Reset all the queues to unassigned */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int i = 0; i < port->n_rxq; i++) {
            port->rxqs[i].pmd = NULL;
        }
    }

    /* Add pinned queues and mark pmd threads isolated. */
    rxq_scheduling(dp, true);

    /* Add non-pinned queues. */
    rxq_scheduling(dp, false);

    /* Step 5: Remove queues not compliant with new scheduling. */

    /* Count all the threads that will have at least one queue to poll. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (q->pmd) {
                hmapx_add(&busy_threads, q->pmd);
            }
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct rxq_poll *poll, *poll_next;

        ovs_mutex_lock(&pmd->port_mutex);
        HMAP_FOR_EACH_SAFE (poll, poll_next, node, &pmd->poll_list) {
            if (poll->rxq->pmd != pmd) {
                dp_netdev_del_rxq_from_pmd(pmd, poll);

                /* This pmd might sleep after this step if it has no rxq
                 * remaining. Tell it to busy wait for new assignment if it
                 * has at least one scheduled queue. */
                if (hmap_count(&pmd->poll_list) == 0 &&
                    hmapx_contains(&busy_threads, pmd)) {
                    atomic_store_relaxed(&pmd->wait_for_reload, true);
                }
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    hmapx_destroy(&busy_threads);

    /* Reload affected pmd threads.  We must wait for the pmd threads to remove
     * the old queues before readding them, otherwise a queue can be polled by
     * two threads at the same time. */
    reload_affected_pmds(dp);

    /* Step 6: Add queues from scheduling, if they're not there already. */
    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];

            if (q->pmd) {
                ovs_mutex_lock(&q->pmd->port_mutex);
                dp_netdev_add_rxq_to_pmd(q->pmd, q);
                ovs_mutex_unlock(&q->pmd->port_mutex);
            }
        }
    }

    /* Add every port and bond to the tx port and bond caches of
     * every pmd thread, if it's not there already and if this pmd
     * has at least one rxq to poll.
     */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        ovs_mutex_lock(&pmd->port_mutex);
        if (hmap_count(&pmd->poll_list) || pmd->core_id == NON_PMD_CORE_ID) {
            struct tx_bond *bond;

            HMAP_FOR_EACH (port, node, &dp->ports) {
                dp_netdev_add_port_tx_to_pmd(pmd, port);
            }

            CMAP_FOR_EACH (bond, node, &dp->tx_bonds) {
                dp_netdev_add_bond_tx_to_pmd(pmd, bond, false);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);
    }

    /* Reload affected pmd threads. */
    reload_affected_pmds(dp);

    /* Check if PMD Auto LB is to be enabled */
    set_pmd_auto_lb(dp, false);
}

/* Returns true if one of the netdevs in 'dp' requires a reconfiguration */
static bool
ports_require_restart(const struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (netdev_is_reconf_required(port->netdev)) {
            return true;
        }
    }

    return false;
}

/* Calculates variance in the values stored in array 'a'. 'n' is the number
 * of elements in array to be considered for calculating vairance.
 * Usage example: data array 'a' contains the processing load of each pmd and
 * 'n' is the number of PMDs. It returns the variance in processing load of
 * PMDs*/
static uint64_t
variance(uint64_t a[], int n)
{
    /* Compute mean (average of elements). */
    uint64_t sum = 0;
    uint64_t mean = 0;
    uint64_t sqDiff = 0;

    if (!n) {
        return 0;
    }

    for (int i = 0; i < n; i++) {
        sum += a[i];
    }

    if (sum) {
        mean = sum / n;

        /* Compute sum squared differences with mean. */
        for (int i = 0; i < n; i++) {
            sqDiff += (a[i] - mean)*(a[i] - mean);
        }
    }
    return (sqDiff ? (sqDiff / n) : 0);
}


/* Returns the variance in the PMDs usage as part of dry run of rxqs
 * assignment to PMDs. */
static bool
get_dry_run_variance(struct dp_netdev *dp, uint32_t *core_list,
                     uint32_t num_pmds, uint64_t *predicted_variance)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_port *port;
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_rxq **rxqs = NULL;
    struct rr_numa *numa = NULL;
    struct rr_numa_list rr;
    int n_rxqs = 0;
    bool ret = false;
    uint64_t *pmd_usage;

    if (!predicted_variance) {
        return ret;
    }

    pmd_usage = xcalloc(num_pmds, sizeof(uint64_t));

    HMAP_FOR_EACH (port, node, &dp->ports) {
        if (!netdev_is_pmd(port->netdev)) {
            continue;
        }

        for (int qid = 0; qid < port->n_rxq; qid++) {
            struct dp_netdev_rxq *q = &port->rxqs[qid];
            uint64_t cycle_hist = 0;

            if (q->pmd->isolated) {
                continue;
            }

            if (n_rxqs == 0) {
                rxqs = xmalloc(sizeof *rxqs);
            } else {
                rxqs = xrealloc(rxqs, sizeof *rxqs * (n_rxqs + 1));
            }

            /* Sum the queue intervals and store the cycle history. */
            for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) {
                cycle_hist += dp_netdev_rxq_get_intrvl_cycles(q, i);
            }
            dp_netdev_rxq_set_cycles(q, RXQ_CYCLES_PROC_HIST,
                                         cycle_hist);
            /* Store the queue. */
            rxqs[n_rxqs++] = q;
        }
    }
    if (n_rxqs > 1) {
        /* Sort the queues in order of the processing cycles
         * they consumed during their last pmd interval. */
        qsort(rxqs, n_rxqs, sizeof *rxqs, compare_rxq_cycles);
    }
    rr_numa_list_populate(dp, &rr);

    for (int i = 0; i < n_rxqs; i++) {
        int numa_id = netdev_get_numa_id(rxqs[i]->port->netdev);
        numa = rr_numa_list_lookup(&rr, numa_id);
        if (!numa) {
            /* Abort if cross NUMA polling. */
            VLOG_DBG("PMD auto lb dry run."
                     " Aborting due to cross-numa polling.");
            goto cleanup;
        }

        pmd = rr_numa_get_pmd(numa, true);
        VLOG_DBG("PMD auto lb dry run. Predicted: Core %d on numa node %d "
                  "to be assigned port \'%s\' rx queue %d "
                  "(measured processing cycles %"PRIu64").",
                  pmd->core_id, numa_id,
                  netdev_rxq_get_name(rxqs[i]->rx),
                  netdev_rxq_get_queue_id(rxqs[i]->rx),
                  dp_netdev_rxq_get_cycles(rxqs[i], RXQ_CYCLES_PROC_HIST));

        for (int id = 0; id < num_pmds; id++) {
            if (pmd->core_id == core_list[id]) {
                /* Add the processing cycles of rxq to pmd polling it. */
                pmd_usage[id] += dp_netdev_rxq_get_cycles(rxqs[i],
                                        RXQ_CYCLES_PROC_HIST);
            }
        }
    }

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        uint64_t total_cycles = 0;

        if ((pmd->core_id == NON_PMD_CORE_ID) || pmd->isolated) {
            continue;
        }

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;
        for (int id = 0; id < num_pmds; id++) {
            if (pmd->core_id == core_list[id]) {
                if (pmd_usage[id]) {
                    pmd_usage[id] = (pmd_usage[id] * 100) / total_cycles;
                }
                VLOG_DBG("PMD auto lb dry run. Predicted: Core %d, "
                         "usage %"PRIu64"", pmd->core_id, pmd_usage[id]);
            }
        }
    }
    *predicted_variance = variance(pmd_usage, num_pmds);
    ret = true;

cleanup:
    rr_numa_list_destroy(&rr);
    free(rxqs);
    free(pmd_usage);
    return ret;
}

/* Does the dry run of Rxq assignment to PMDs and returns true if it gives
 * better distribution of load on PMDs. */
static bool
pmd_rebalance_dry_run(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_pmd_thread *pmd;
    uint64_t *curr_pmd_usage;

    uint64_t curr_variance;
    uint64_t new_variance;
    uint64_t improvement = 0;
    uint32_t num_pmds;
    uint32_t *pmd_corelist;
    struct rxq_poll *poll;
    bool ret;

    num_pmds = cmap_count(&dp->poll_threads);

    if (num_pmds > 1) {
        curr_pmd_usage = xcalloc(num_pmds, sizeof(uint64_t));
        pmd_corelist = xcalloc(num_pmds, sizeof(uint32_t));
    } else {
        return false;
    }

    num_pmds = 0;
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        uint64_t total_cycles = 0;
        uint64_t total_proc = 0;

        if ((pmd->core_id == NON_PMD_CORE_ID) || pmd->isolated) {
            continue;
        }

        /* Get the total pmd cycles for an interval. */
        atomic_read_relaxed(&pmd->intrvl_cycles, &total_cycles);
        /* Estimate the cycles to cover all intervals. */
        total_cycles *= PMD_RXQ_INTERVAL_MAX;

        ovs_mutex_lock(&pmd->port_mutex);
        HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
            for (unsigned i = 0; i < PMD_RXQ_INTERVAL_MAX; i++) {
                total_proc += dp_netdev_rxq_get_intrvl_cycles(poll->rxq, i);
            }
        }
        ovs_mutex_unlock(&pmd->port_mutex);

        if (total_proc) {
            curr_pmd_usage[num_pmds] = (total_proc * 100) / total_cycles;
        }

        VLOG_DBG("PMD auto lb dry run. Current: Core %d, usage %"PRIu64"",
                  pmd->core_id, curr_pmd_usage[num_pmds]);

        if (atomic_count_get(&pmd->pmd_overloaded)) {
            atomic_count_set(&pmd->pmd_overloaded, 0);
        }

        pmd_corelist[num_pmds] = pmd->core_id;
        num_pmds++;
    }

    curr_variance = variance(curr_pmd_usage, num_pmds);
    ret = get_dry_run_variance(dp, pmd_corelist, num_pmds, &new_variance);

    if (ret) {
        VLOG_DBG("PMD auto lb dry run. Current PMD variance: %"PRIu64","
                  " Predicted PMD variance: %"PRIu64"",
                  curr_variance, new_variance);

        if (new_variance < curr_variance) {
            improvement =
                ((curr_variance - new_variance) * 100) / curr_variance;
        }
        if (improvement < dp->pmd_alb.rebalance_improve_thresh) {
            ret = false;
        }
    }

    free(curr_pmd_usage);
    free(pmd_corelist);
    return ret;
}


/* Return true if needs to revalidate datapath flows. */
static bool
dpif_netdev_run(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *non_pmd;
    uint64_t new_tnl_seq;
    bool need_to_flush = true;
    bool pmd_rebalance = false;
    long long int now = time_msec();
    struct dp_netdev_pmd_thread *pmd;

    ovs_rwlock_wrlock(&dp->port_rwlock);
    non_pmd = dp_netdev_get_pmd(dp, NON_PMD_CORE_ID);
    if (non_pmd) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        HMAP_FOR_EACH (port, node, &dp->ports) {
            if (!netdev_is_pmd(port->netdev)) {
                int i;

                if (port->emc_enabled) {
                    atomic_read_relaxed(&dp->emc_insert_min,
                                        &non_pmd->ctx.emc_insert_min);
                } else {
                    non_pmd->ctx.emc_insert_min = 0;
                }

                for (i = 0; i < port->n_rxq; i++) {

                    if (!netdev_rxq_enabled(port->rxqs[i].rx)) {
                        continue;
                    }

                    if (dp_netdev_process_rxq_port(non_pmd,
                                                   &port->rxqs[i],
                                                   port->port_no)) {
                        need_to_flush = false;
                    }
                }
            }
        }
        if (need_to_flush) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(non_pmd);
            dp_netdev_pmd_flush_output_packets(non_pmd, false);
        }

        dpif_netdev_xps_revalidate_pmd(non_pmd, false);
        ovs_mutex_unlock(&dp->non_pmd_mutex);

        dp_netdev_pmd_unref(non_pmd);
    }

    struct pmd_auto_lb *pmd_alb = &dp->pmd_alb;
    if (pmd_alb->is_enabled) {
        if (!pmd_alb->rebalance_poll_timer) {
            pmd_alb->rebalance_poll_timer = now;
        } else if ((pmd_alb->rebalance_poll_timer +
                   pmd_alb->rebalance_intvl) < now) {
            pmd_alb->rebalance_poll_timer = now;
            CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
                if (atomic_count_get(&pmd->pmd_overloaded) >=
                                    PMD_RXQ_INTERVAL_MAX) {
                    pmd_rebalance = true;
                    break;
                }
            }

            if (pmd_rebalance &&
                !dp_netdev_is_reconf_required(dp) &&
                !ports_require_restart(dp) &&
                pmd_rebalance_dry_run(dp)) {
                VLOG_INFO("PMD auto lb dry run."
                          " requesting datapath reconfigure.");
                dp_netdev_request_reconfigure(dp);
            }
        }
    }

    if (dp_netdev_is_reconf_required(dp) || ports_require_restart(dp)) {
        reconfigure_datapath(dp);
    }
    ovs_rwlock_unlock(&dp->port_rwlock);

    tnl_neigh_cache_run();
    tnl_port_map_run();
    new_tnl_seq = seq_read(tnl_conf_seq);

    if (dp->last_tnl_conf_seq != new_tnl_seq) {
        dp->last_tnl_conf_seq = new_tnl_seq;
        return true;
    }
    return false;
}

static void
dpif_netdev_wait(struct dpif *dpif)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp = get_dp_netdev(dpif);

    ovs_mutex_lock(&dp_netdev_mutex);
    ovs_rwlock_wrlock(&dp->port_rwlock);
    HMAP_FOR_EACH (port, node, &dp->ports) {
        netdev_wait_reconf_required(port->netdev);
        if (!netdev_is_pmd(port->netdev)) {
            int i;

            for (i = 0; i < port->n_rxq; i++) {
                netdev_rxq_wait(port->rxqs[i].rx);
            }
        }
    }
    ovs_rwlock_unlock(&dp->port_rwlock);
    ovs_mutex_unlock(&dp_netdev_mutex);
    seq_wait(tnl_conf_seq, dp->last_tnl_conf_seq);
}

static void
pmd_free_cached_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct tx_port *tx_port_cached;

    /* Flush all the queued packets. */
    dp_netdev_pmd_flush_output_packets(pmd, true);
    /* Free all used tx queue ids. */
    dpif_netdev_xps_revalidate_pmd(pmd, true);

    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->tnl_port_cache) {
        free(tx_port_cached);
    }
    HMAP_FOR_EACH_POP (tx_port_cached, node, &pmd->send_port_cache) {
        free(tx_port_cached);
    }
}

/* Copies ports from 'pmd->tx_ports' (shared with the main thread) to
 * thread-local copies. Copy to 'pmd->tnl_port_cache' if it is a tunnel
 * device, otherwise to 'pmd->send_port_cache' if the port has at least
 * one txq. */
static void
pmd_load_cached_ports(struct dp_netdev_pmd_thread *pmd)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx_port, *tx_port_cached;

    pmd_free_cached_ports(pmd);
    hmap_shrink(&pmd->send_port_cache);
    hmap_shrink(&pmd->tnl_port_cache);

    HMAP_FOR_EACH (tx_port, node, &pmd->tx_ports) {
        if (netdev_has_tunnel_push_pop(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            hmap_insert(&pmd->tnl_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }

        if (netdev_n_txq(tx_port->port->netdev)) {
            tx_port_cached = xmemdup(tx_port, sizeof *tx_port_cached);
            hmap_insert(&pmd->send_port_cache, &tx_port_cached->node,
                        hash_port_no(tx_port_cached->port->port_no));
        }
    }
}

static void
pmd_alloc_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    if (!id_pool_alloc_id(pmd->dp->tx_qid_pool, &pmd->static_tx_qid)) {
        VLOG_ABORT("static_tx_qid allocation failed for PMD on core %2d"
                   ", numa_id %d.", pmd->core_id, pmd->numa_id);
    }
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);

    VLOG_DBG("static_tx_qid = %d allocated for PMD thread on core %2d"
             ", numa_id %d.", pmd->static_tx_qid, pmd->core_id, pmd->numa_id);
}

static void
pmd_free_static_tx_qid(struct dp_netdev_pmd_thread *pmd)
{
    ovs_mutex_lock(&pmd->dp->tx_qid_pool_mutex);
    id_pool_free_id(pmd->dp->tx_qid_pool, pmd->static_tx_qid);
    ovs_mutex_unlock(&pmd->dp->tx_qid_pool_mutex);
}

static int
pmd_load_queues_and_ports(struct dp_netdev_pmd_thread *pmd,
                          struct polled_queue **ppoll_list)
{
    struct polled_queue *poll_list = *ppoll_list;
    struct rxq_poll *poll;
    int i;

    ovs_mutex_lock(&pmd->port_mutex);
    poll_list = xrealloc(poll_list, hmap_count(&pmd->poll_list)
                                    * sizeof *poll_list);

    i = 0;
    HMAP_FOR_EACH (poll, node, &pmd->poll_list) {
        poll_list[i].rxq = poll->rxq;
        poll_list[i].port_no = poll->rxq->port->port_no;
        poll_list[i].emc_enabled = poll->rxq->port->emc_enabled;
        poll_list[i].rxq_enabled = netdev_rxq_enabled(poll->rxq->rx);
        poll_list[i].change_seq =
                     netdev_get_change_seq(poll->rxq->port->netdev);
        i++;
    }

    pmd_load_cached_ports(pmd);

    ovs_mutex_unlock(&pmd->port_mutex);

    *ppoll_list = poll_list;
    return i;
}

static void *
pmd_thread_main(void *f_)
{
    struct dp_netdev_pmd_thread *pmd = f_;
    struct pmd_perf_stats *s = &pmd->perf_stats;
    unsigned int lc = 0;
    struct polled_queue *poll_list;
    bool wait_for_reload = false;
    bool reload_tx_qid;
    bool exiting;
    bool reload;
    int poll_cnt;
    int i;
    int process_packets = 0;

    poll_list = NULL;

    /* Stores the pmd thread's 'pmd' to 'per_pmd_key'. */
    ovsthread_setspecific(pmd->dp->per_pmd_key, pmd);
    ovs_numa_thread_setaffinity_core(pmd->core_id);
    dpdk_set_lcore_id(pmd->core_id);
    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    dfc_cache_init(&pmd->flow_cache);
    pmd_alloc_static_tx_qid(pmd);

reload:
    atomic_count_init(&pmd->pmd_overloaded, 0);

    /* List port/core affinity */
    for (i = 0; i < poll_cnt; i++) {
       VLOG_DBG("Core %d processing port \'%s\' with queue-id %d\n",
                pmd->core_id, netdev_rxq_get_name(poll_list[i].rxq->rx),
                netdev_rxq_get_queue_id(poll_list[i].rxq->rx));
       /* Reset the rxq current cycles counter. */
       dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR, 0);
    }

    if (!poll_cnt) {
        if (wait_for_reload) {
            /* Don't sleep, control thread will ask for a reload shortly. */
            do {
                atomic_read_explicit(&pmd->reload, &reload,
                                     memory_order_acquire);
            } while (!reload);
        } else {
            while (seq_read(pmd->reload_seq) == pmd->last_reload_seq) {
                seq_wait(pmd->reload_seq, pmd->last_reload_seq);
                poll_block();
            }
        }
    }

    pmd->intrvl_tsc_prev = 0;
    atomic_store_relaxed(&pmd->intrvl_cycles, 0);
    cycles_counter_update(s);

    pmd->next_rcu_quiesce = pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;

    /* Protect pmd stats from external clearing while polling. */
    ovs_mutex_lock(&pmd->perf_stats.stats_mutex);
    for (;;) {
        uint64_t rx_packets = 0, tx_packets = 0;

        pmd_perf_start_iteration(s);

        for (i = 0; i < poll_cnt; i++) {

            if (!poll_list[i].rxq_enabled) {
                continue;
            }

            if (poll_list[i].emc_enabled) {
                atomic_read_relaxed(&pmd->dp->emc_insert_min,
                                    &pmd->ctx.emc_insert_min);
            } else {
                pmd->ctx.emc_insert_min = 0;
            }

            process_packets =
                dp_netdev_process_rxq_port(pmd, poll_list[i].rxq,
                                           poll_list[i].port_no);
            rx_packets += process_packets;
        }

        if (!rx_packets) {
            /* We didn't receive anything in the process loop.
             * Check if we need to send something.
             * There was no time updates on current iteration. */
            pmd_thread_ctx_time_update(pmd);
            tx_packets = dp_netdev_pmd_flush_output_packets(pmd, false);
        }

        /* Do RCU synchronization at fixed interval.  This ensures that
         * synchronization would not be delayed long even at high load of
         * packet processing. */
        if (pmd->ctx.now > pmd->next_rcu_quiesce) {
            if (!ovsrcu_try_quiesce()) {
                pmd->next_rcu_quiesce =
                    pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
            }
        }

        if (lc++ > 1024) {
            lc = 0;

            coverage_try_clear();
            dp_netdev_pmd_try_optimize(pmd, poll_list, poll_cnt);
            if (!ovsrcu_try_quiesce()) {
                emc_cache_slow_sweep(&((pmd->flow_cache).emc_cache));
                pmd->next_rcu_quiesce =
                    pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
            }

            for (i = 0; i < poll_cnt; i++) {
                uint64_t current_seq =
                         netdev_get_change_seq(poll_list[i].rxq->port->netdev);
                if (poll_list[i].change_seq != current_seq) {
                    poll_list[i].change_seq = current_seq;
                    poll_list[i].rxq_enabled =
                                 netdev_rxq_enabled(poll_list[i].rxq->rx);
                }
            }
        }

        atomic_read_explicit(&pmd->reload, &reload, memory_order_acquire);
        if (OVS_UNLIKELY(reload)) {
            break;
        }

        pmd_perf_end_iteration(s, rx_packets, tx_packets,
                               pmd_perf_metrics_enabled(pmd));
    }
    ovs_mutex_unlock(&pmd->perf_stats.stats_mutex);

    poll_cnt = pmd_load_queues_and_ports(pmd, &poll_list);
    atomic_read_relaxed(&pmd->wait_for_reload, &wait_for_reload);
    atomic_read_relaxed(&pmd->reload_tx_qid, &reload_tx_qid);
    atomic_read_relaxed(&pmd->exit, &exiting);
    /* Signal here to make sure the pmd finishes
     * reloading the updated configuration. */
    dp_netdev_pmd_reload_done(pmd);

    if (reload_tx_qid) {
        pmd_free_static_tx_qid(pmd);
        pmd_alloc_static_tx_qid(pmd);
    }

    if (!exiting) {
        goto reload;
    }

    pmd_free_static_tx_qid(pmd);
    dfc_cache_uninit(&pmd->flow_cache);
    free(poll_list);
    pmd_free_cached_ports(pmd);
    return NULL;
}

static void
dp_netdev_disable_upcall(struct dp_netdev *dp)
    OVS_ACQUIRES(dp->upcall_rwlock)
{
    fat_rwlock_wrlock(&dp->upcall_rwlock);
}


/* Meters */
static void
dpif_netdev_meter_get_features(const struct dpif * dpif OVS_UNUSED,
                               struct ofputil_meter_features *features)
{
    features->max_meters = MAX_METERS;
    features->band_types = DP_SUPPORTED_METER_BAND_TYPES;
    features->capabilities = DP_SUPPORTED_METER_FLAGS_MASK;
    features->max_bands = MAX_BANDS;
    features->max_color = 0;
}

/* Applies the meter identified by 'meter_id' to 'packets_'.  Packets
 * that exceed a band are dropped in-place. */
static void
dp_netdev_run_meter(struct dp_netdev *dp, struct dp_packet_batch *packets_,
                    uint32_t meter_id, long long int now)
{
    struct dp_meter *meter;
    struct dp_meter_band *band;
    struct dp_packet *packet;
    long long int long_delta_t; /* msec */
    uint32_t delta_t; /* msec */
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t bytes, volume;
    int exceeded_band[NETDEV_MAX_BURST];
    uint32_t exceeded_rate[NETDEV_MAX_BURST];
    int exceeded_pkt = cnt; /* First packet that exceeded a band rate. */

    if (meter_id >= MAX_METERS) {
        return;
    }

    meter_lock(dp, meter_id);
    meter = dp->meters[meter_id];
    if (!meter) {
        goto out;
    }

    /* Initialize as negative values. */
    memset(exceeded_band, 0xff, cnt * sizeof *exceeded_band);
    /* Initialize as zeroes. */
    memset(exceeded_rate, 0, cnt * sizeof *exceeded_rate);

    /* All packets will hit the meter at the same time. */
    long_delta_t = now / 1000 - meter->used / 1000; /* msec */

    if (long_delta_t < 0) {
        /* This condition means that we have several threads fighting for a
           meter lock, and the one who received the packets a bit later wins.
           Assuming that all racing threads received packets at the same time
           to avoid overflow. */
        long_delta_t = 0;
    }

    /* Make sure delta_t will not be too large, so that bucket will not
     * wrap around below. */
    delta_t = (long_delta_t > (long long int)meter->max_delta_t)
        ? meter->max_delta_t : (uint32_t)long_delta_t;

    /* Update meter stats. */
    meter->used = now;
    meter->packet_count += cnt;
    bytes = 0;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        bytes += dp_packet_size(packet);
    }
    meter->byte_count += bytes;

    /* Meters can operate in terms of packets per second or kilobits per
     * second. */
    if (meter->flags & OFPMF13_PKTPS) {
        /* Rate in packets/second, bucket 1/1000 packets. */
        /* msec * packets/sec = 1/1000 packets. */
        volume = cnt * 1000; /* Take 'cnt' packets from the bucket. */
    } else {
        /* Rate in kbps, bucket in bits. */
        /* msec * kbps = bits */
        volume = bytes * 8;
    }

    /* Update all bands and find the one hit with the highest rate for each
     * packet (if any). */
    for (int m = 0; m < meter->n_bands; ++m) {
        uint64_t max_bucket_size;

        band = &meter->bands[m];
        max_bucket_size = band->burst_size * 1000ULL;
        /* Update band's bucket. */
        band->bucket += (uint64_t) delta_t * band->rate;
        if (band->bucket > max_bucket_size) {
            band->bucket = max_bucket_size;
        }

        /* Drain the bucket for all the packets, if possible. */
        if (band->bucket >= volume) {
            band->bucket -= volume;
        } else {
            int band_exceeded_pkt;

            /* Band limit hit, must process packet-by-packet. */
            if (meter->flags & OFPMF13_PKTPS) {
                band_exceeded_pkt = band->bucket / 1000;
                band->bucket %= 1000; /* Remainder stays in bucket. */

                /* Update the exceeding band for each exceeding packet.
                 * (Only one band will be fired by a packet, and that
                 * can be different for each packet.) */
                for (int i = band_exceeded_pkt; i < cnt; i++) {
                    if (band->rate > exceeded_rate[i]) {
                        exceeded_rate[i] = band->rate;
                        exceeded_band[i] = m;
                    }
                }
            } else {
                /* Packet sizes differ, must process one-by-one. */
                band_exceeded_pkt = cnt;
                DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                    uint32_t bits = dp_packet_size(packet) * 8;

                    if (band->bucket >= bits) {
                        band->bucket -= bits;
                    } else {
                        if (i < band_exceeded_pkt) {
                            band_exceeded_pkt = i;
                        }
                        /* Update the exceeding band for the exceeding packet.
                         * (Only one band will be fired by a packet, and that
                         * can be different for each packet.) */
                        if (band->rate > exceeded_rate[i]) {
                            exceeded_rate[i] = band->rate;
                            exceeded_band[i] = m;
                        }
                    }
                }
            }
            /* Remember the first exceeding packet. */
            if (exceeded_pkt > band_exceeded_pkt) {
                exceeded_pkt = band_exceeded_pkt;
            }
        }
    }

    /* Fire the highest rate band exceeded by each packet, and drop
     * packets if needed. */
    size_t j;
    DP_PACKET_BATCH_REFILL_FOR_EACH (j, cnt, packet, packets_) {
        if (exceeded_band[j] >= 0) {
            /* Meter drop packet. */
            band = &meter->bands[exceeded_band[j]];
            band->packet_count += 1;
            band->byte_count += dp_packet_size(packet);
            COVERAGE_INC(datapath_drop_meter);
            dp_packet_delete(packet);
        } else {
            /* Meter accepts packet. */
            dp_packet_batch_refill(packets_, packet, j);
        }
    }
 out:
    meter_unlock(dp, meter_id);
}

/* Meter set/get/del processing is still single-threaded. */
static int
dpif_netdev_meter_set(struct dpif *dpif, ofproto_meter_id meter_id,
                      struct ofputil_meter_config *config)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t mid = meter_id.uint32;
    struct dp_meter *meter;
    int i;

    if (mid >= MAX_METERS) {
        return EFBIG; /* Meter_id out of range. */
    }

    if (config->flags & ~DP_SUPPORTED_METER_FLAGS_MASK) {
        return EBADF; /* Unsupported flags set */
    }

    if (config->n_bands > MAX_BANDS) {
        return EINVAL;
    }

    for (i = 0; i < config->n_bands; ++i) {
        switch (config->bands[i].type) {
        case OFPMBT13_DROP:
            break;
        default:
            return ENODEV; /* Unsupported band type */
        }
    }

    /* Allocate meter */
    meter = xzalloc(sizeof *meter
                    + config->n_bands * sizeof(struct dp_meter_band));

    meter->flags = config->flags;
    meter->n_bands = config->n_bands;
    meter->max_delta_t = 0;
    meter->used = time_usec();

    /* set up bands */
    for (i = 0; i < config->n_bands; ++i) {
        uint32_t band_max_delta_t;

        /* Set burst size to a workable value if none specified. */
        if (config->bands[i].burst_size == 0) {
            config->bands[i].burst_size = config->bands[i].rate;
        }

        meter->bands[i].rate = config->bands[i].rate;
        meter->bands[i].burst_size = config->bands[i].burst_size;
        /* Start with a full bucket. */
        meter->bands[i].bucket = meter->bands[i].burst_size * 1000ULL;

        /* Figure out max delta_t that is enough to fill any bucket. */
        band_max_delta_t
            = meter->bands[i].bucket / meter->bands[i].rate;
        if (band_max_delta_t > meter->max_delta_t) {
            meter->max_delta_t = band_max_delta_t;
        }
    }

    meter_lock(dp, mid);
    dp_delete_meter(dp, mid); /* Free existing meter, if any */
    dp->meters[mid] = meter;
    meter_unlock(dp, mid);

    return 0;
}

static int
dpif_netdev_meter_get(const struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    const struct dp_netdev *dp = get_dp_netdev(dpif);
    uint32_t meter_id = meter_id_.uint32;
    int retval = 0;

    if (meter_id >= MAX_METERS) {
        return EFBIG;
    }

    meter_lock(dp, meter_id);
    const struct dp_meter *meter = dp->meters[meter_id];
    if (!meter) {
        retval = ENOENT;
        goto done;
    }
    if (stats) {
        int i = 0;

        stats->packet_in_count = meter->packet_count;
        stats->byte_in_count = meter->byte_count;

        for (i = 0; i < n_bands && i < meter->n_bands; ++i) {
            stats->bands[i].packet_count = meter->bands[i].packet_count;
            stats->bands[i].byte_count = meter->bands[i].byte_count;
        }

        stats->n_bands = i;
    }

done:
    meter_unlock(dp, meter_id);
    return retval;
}

static int
dpif_netdev_meter_del(struct dpif *dpif,
                      ofproto_meter_id meter_id_,
                      struct ofputil_meter_stats *stats, uint16_t n_bands)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    int error;

    error = dpif_netdev_meter_get(dpif, meter_id_, stats, n_bands);
    if (!error) {
        uint32_t meter_id = meter_id_.uint32;

        meter_lock(dp, meter_id);
        dp_delete_meter(dp, meter_id);
        meter_unlock(dp, meter_id);
    }
    return error;
}


static void
dpif_netdev_disable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_disable_upcall(dp);
}

static void
dp_netdev_enable_upcall(struct dp_netdev *dp)
    OVS_RELEASES(dp->upcall_rwlock)
{
    fat_rwlock_unlock(&dp->upcall_rwlock);
}

static void
dpif_netdev_enable_upcall(struct dpif *dpif)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp_netdev_enable_upcall(dp);
}

static void
dp_netdev_pmd_reload_done(struct dp_netdev_pmd_thread *pmd)
{
    atomic_store_relaxed(&pmd->wait_for_reload, false);
    atomic_store_relaxed(&pmd->reload_tx_qid, false);
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_store_explicit(&pmd->reload, false, memory_order_release);
}

/* Finds and refs the dp_netdev_pmd_thread on core 'core_id'.  Returns
 * the pointer if succeeds, otherwise, NULL (it can return NULL even if
 * 'core_id' is NON_PMD_CORE_ID).
 *
 * Caller must unrefs the returned reference.  */
static struct dp_netdev_pmd_thread *
dp_netdev_get_pmd(struct dp_netdev *dp, unsigned core_id)
{
    struct dp_netdev_pmd_thread *pmd;
    const struct cmap_node *pnode;

    pnode = cmap_find(&dp->poll_threads, hash_int(core_id, 0));
    if (!pnode) {
        return NULL;
    }
    pmd = CONTAINER_OF(pnode, struct dp_netdev_pmd_thread, node);

    return dp_netdev_pmd_try_ref(pmd) ? pmd : NULL;
}

/* Sets the 'struct dp_netdev_pmd_thread' for non-pmd threads. */
static void
dp_netdev_set_nonpmd(struct dp_netdev *dp)
    OVS_REQ_WRLOCK(dp->port_rwlock)
{
    struct dp_netdev_pmd_thread *non_pmd;

    non_pmd = xzalloc(sizeof *non_pmd);
    dp_netdev_configure_pmd(non_pmd, dp, NON_PMD_CORE_ID, OVS_NUMA_UNSPEC);
}

/* Caller must have valid pointer to 'pmd'. */
static bool
dp_netdev_pmd_try_ref(struct dp_netdev_pmd_thread *pmd)
{
    return ovs_refcount_try_ref_rcu(&pmd->ref_cnt);
}

static void
dp_netdev_pmd_unref(struct dp_netdev_pmd_thread *pmd)
{
    if (pmd && ovs_refcount_unref(&pmd->ref_cnt) == 1) {
        ovsrcu_postpone(dp_netdev_destroy_pmd, pmd);
    }
}

/* Given cmap position 'pos', tries to ref the next node.  If try_ref()
 * fails, keeps checking for next node until reaching the end of cmap.
 *
 * Caller must unrefs the returned reference. */
static struct dp_netdev_pmd_thread *
dp_netdev_pmd_get_next(struct dp_netdev *dp, struct cmap_position *pos)
{
    struct dp_netdev_pmd_thread *next;

    do {
        struct cmap_node *node;

        node = cmap_next_position(&dp->poll_threads, pos);
        next = node ? CONTAINER_OF(node, struct dp_netdev_pmd_thread, node)
            : NULL;
    } while (next && !dp_netdev_pmd_try_ref(next));

    return next;
}

/* Configures the 'pmd' based on the input argument. */
static void
dp_netdev_configure_pmd(struct dp_netdev_pmd_thread *pmd, struct dp_netdev *dp,
                        unsigned core_id, int numa_id)
{
    pmd->dp = dp;
    pmd->core_id = core_id;
    pmd->numa_id = numa_id;
    pmd->need_reload = false;
    pmd->n_output_batches = 0;

    ovs_refcount_init(&pmd->ref_cnt);
    atomic_init(&pmd->exit, false);
    pmd->reload_seq = seq_create();
    pmd->last_reload_seq = seq_read(pmd->reload_seq);
    atomic_init(&pmd->reload, false);
    ovs_mutex_init(&pmd->flow_mutex);
    ovs_mutex_init(&pmd->port_mutex);
    ovs_mutex_init(&pmd->bond_mutex);
    cmap_init(&pmd->flow_table);
    cmap_init(&pmd->classifiers);
    pmd->ctx.last_rxq = NULL;
    pmd_thread_ctx_time_update(pmd);
    pmd->next_optimization = pmd->ctx.now + DPCLS_OPTIMIZATION_INTERVAL;
    pmd->next_rcu_quiesce = pmd->ctx.now + PMD_RCU_QUIESCE_INTERVAL;
    pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;
    hmap_init(&pmd->poll_list);
    hmap_init(&pmd->tx_ports);
    hmap_init(&pmd->tnl_port_cache);
    hmap_init(&pmd->send_port_cache);
    cmap_init(&pmd->tx_bonds);
    /* init the 'flow_cache' since there is no
     * actual thread created for NON_PMD_CORE_ID. */
    if (core_id == NON_PMD_CORE_ID) {
        dfc_cache_init(&pmd->flow_cache);
        pmd_alloc_static_tx_qid(pmd);
    }
    pmd_perf_stats_init(&pmd->perf_stats);
    cmap_insert(&dp->poll_threads, CONST_CAST(struct cmap_node *, &pmd->node),
                hash_int(core_id, 0));
}

static void
dp_netdev_destroy_pmd(struct dp_netdev_pmd_thread *pmd)
{
    struct dpcls *cls;

    dp_netdev_pmd_flow_flush(pmd);
    hmap_destroy(&pmd->send_port_cache);
    hmap_destroy(&pmd->tnl_port_cache);
    hmap_destroy(&pmd->tx_ports);
    cmap_destroy(&pmd->tx_bonds);
    hmap_destroy(&pmd->poll_list);
    /* All flows (including their dpcls_rules) have been deleted already */
    CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
        dpcls_destroy(cls);
        ovsrcu_postpone(free, cls);
    }
    cmap_destroy(&pmd->classifiers);
    cmap_destroy(&pmd->flow_table);
    ovs_mutex_destroy(&pmd->flow_mutex);
    seq_destroy(pmd->reload_seq);
    ovs_mutex_destroy(&pmd->port_mutex);
    ovs_mutex_destroy(&pmd->bond_mutex);
    free(pmd);
}

/* Stops the pmd thread, removes it from the 'dp->poll_threads',
 * and unrefs the struct. */
static void
dp_netdev_del_pmd(struct dp_netdev *dp, struct dp_netdev_pmd_thread *pmd)
{
    /* NON_PMD_CORE_ID doesn't have a thread, so we don't have to synchronize,
     * but extra cleanup is necessary */
    if (pmd->core_id == NON_PMD_CORE_ID) {
        ovs_mutex_lock(&dp->non_pmd_mutex);
        dfc_cache_uninit(&pmd->flow_cache);
        pmd_free_cached_ports(pmd);
        pmd_free_static_tx_qid(pmd);
        ovs_mutex_unlock(&dp->non_pmd_mutex);
    } else {
        atomic_store_relaxed(&pmd->exit, true);
        dp_netdev_reload_pmd__(pmd);
        xpthread_join(pmd->thread, NULL);
    }

    dp_netdev_pmd_clear_ports(pmd);

    /* Purges the 'pmd''s flows after stopping the thread, but before
     * destroying the flows, so that the flow stats can be collected. */
    if (dp->dp_purge_cb) {
        dp->dp_purge_cb(dp->dp_purge_aux, pmd->core_id);
    }
    cmap_remove(&pmd->dp->poll_threads, &pmd->node, hash_int(pmd->core_id, 0));
    dp_netdev_pmd_unref(pmd);
}

/* Destroys all pmd threads. If 'non_pmd' is true it also destroys the non pmd
 * thread. */
static void
dp_netdev_destroy_all_pmds(struct dp_netdev *dp, bool non_pmd)
{
    struct dp_netdev_pmd_thread *pmd;
    struct dp_netdev_pmd_thread **pmd_list;
    size_t k = 0, n_pmds;

    n_pmds = cmap_count(&dp->poll_threads);
    pmd_list = xcalloc(n_pmds, sizeof *pmd_list);

    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        if (!non_pmd && pmd->core_id == NON_PMD_CORE_ID) {
            continue;
        }
        /* We cannot call dp_netdev_del_pmd(), since it alters
         * 'dp->poll_threads' (while we're iterating it) and it
         * might quiesce. */
        ovs_assert(k < n_pmds);
        pmd_list[k++] = pmd;
    }

    for (size_t i = 0; i < k; i++) {
        dp_netdev_del_pmd(dp, pmd_list[i]);
    }
    free(pmd_list);
}

/* Deletes all rx queues from pmd->poll_list and all the ports from
 * pmd->tx_ports. */
static void
dp_netdev_pmd_clear_ports(struct dp_netdev_pmd_thread *pmd)
{
    struct rxq_poll *poll;
    struct tx_port *port;
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->port_mutex);
    HMAP_FOR_EACH_POP (poll, node, &pmd->poll_list) {
        free(poll);
    }
    HMAP_FOR_EACH_POP (port, node, &pmd->tx_ports) {
        free(port);
    }
    ovs_mutex_unlock(&pmd->port_mutex);

    ovs_mutex_lock(&pmd->bond_mutex);
    CMAP_FOR_EACH (tx, node, &pmd->tx_bonds) {
        cmap_remove(&pmd->tx_bonds, &tx->node, hash_bond_id(tx->bond_id));
        ovsrcu_postpone(free, tx);
    }
    ovs_mutex_unlock(&pmd->bond_mutex);
}

/* Adds rx queue to poll_list of PMD thread, if it's not there already. */
static void
dp_netdev_add_rxq_to_pmd(struct dp_netdev_pmd_thread *pmd,
                         struct dp_netdev_rxq *rxq)
    OVS_REQUIRES(pmd->port_mutex)
{
    int qid = netdev_rxq_get_queue_id(rxq->rx);
    uint32_t hash = hash_2words(odp_to_u32(rxq->port->port_no), qid);
    struct rxq_poll *poll;

    HMAP_FOR_EACH_WITH_HASH (poll, node, hash, &pmd->poll_list) {
        if (poll->rxq == rxq) {
            /* 'rxq' is already polled by this thread. Do nothing. */
            return;
        }
    }

    poll = xmalloc(sizeof *poll);
    poll->rxq = rxq;
    hmap_insert(&pmd->poll_list, &poll->node, hash);

    pmd->need_reload = true;
}

/* Delete 'poll' from poll_list of PMD thread. */
static void
dp_netdev_del_rxq_from_pmd(struct dp_netdev_pmd_thread *pmd,
                           struct rxq_poll *poll)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->poll_list, &poll->node);
    free(poll);

    pmd->need_reload = true;
}

/* Add 'port' to the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_add_port_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                             struct dp_netdev_port *port)
    OVS_REQUIRES(pmd->port_mutex)
{
    struct tx_port *tx;

    tx = tx_port_lookup(&pmd->tx_ports, port->port_no);
    if (tx) {
        /* 'port' is already on this thread tx cache. Do nothing. */
        return;
    }

    tx = xzalloc(sizeof *tx);

    tx->port = port;
    tx->qid = -1;
    tx->flush_time = 0LL;
    dp_packet_batch_init(&tx->output_pkts);

    hmap_insert(&pmd->tx_ports, &tx->node, hash_port_no(tx->port->port_no));
    pmd->need_reload = true;
}

/* Del 'tx' from the tx port cache of 'pmd', which must be reloaded for the
 * changes to take effect. */
static void
dp_netdev_del_port_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                               struct tx_port *tx)
    OVS_REQUIRES(pmd->port_mutex)
{
    hmap_remove(&pmd->tx_ports, &tx->node);
    free(tx);
    pmd->need_reload = true;
}

/* Add bond to the tx bond cmap of 'pmd'. */
static void
dp_netdev_add_bond_tx_to_pmd(struct dp_netdev_pmd_thread *pmd,
                             struct tx_bond *bond, bool update)
    OVS_EXCLUDED(pmd->bond_mutex)
{
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->bond_mutex);
    tx = tx_bond_lookup(&pmd->tx_bonds, bond->bond_id);

    if (tx && !update) {
        /* It's not an update and the entry already exists.  Do nothing. */
        goto unlock;
    }

    if (tx) {
        struct tx_bond *new_tx = xmemdup(bond, sizeof *bond);

        /* Copy the stats for each bucket. */
        for (int i = 0; i < BOND_BUCKETS; i++) {
            uint64_t n_packets, n_bytes;

            atomic_read_relaxed(&tx->member_buckets[i].n_packets, &n_packets);
            atomic_read_relaxed(&tx->member_buckets[i].n_bytes, &n_bytes);
            atomic_init(&new_tx->member_buckets[i].n_packets, n_packets);
            atomic_init(&new_tx->member_buckets[i].n_bytes, n_bytes);
        }
        cmap_replace(&pmd->tx_bonds, &tx->node, &new_tx->node,
                     hash_bond_id(bond->bond_id));
        ovsrcu_postpone(free, tx);
    } else {
        tx = xmemdup(bond, sizeof *bond);
        cmap_insert(&pmd->tx_bonds, &tx->node, hash_bond_id(bond->bond_id));
    }
unlock:
    ovs_mutex_unlock(&pmd->bond_mutex);
}

/* Delete bond from the tx bond cmap of 'pmd'. */
static void
dp_netdev_del_bond_tx_from_pmd(struct dp_netdev_pmd_thread *pmd,
                               uint32_t bond_id)
    OVS_EXCLUDED(pmd->bond_mutex)
{
    struct tx_bond *tx;

    ovs_mutex_lock(&pmd->bond_mutex);
    tx = tx_bond_lookup(&pmd->tx_bonds, bond_id);
    if (tx) {
        cmap_remove(&pmd->tx_bonds, &tx->node, hash_bond_id(tx->bond_id));
        ovsrcu_postpone(free, tx);
    }
    ovs_mutex_unlock(&pmd->bond_mutex);
}

static char *
dpif_netdev_get_datapath_version(void)
{
     return xstrdup("<built-in>");
}

static void
dp_netdev_flow_used(struct dp_netdev_flow *netdev_flow, int cnt, int size,
                    uint16_t tcp_flags, long long now)
{
    uint16_t flags;

    atomic_store_relaxed(&netdev_flow->stats.used, now);
    non_atomic_ullong_add(&netdev_flow->stats.packet_count, cnt);
    non_atomic_ullong_add(&netdev_flow->stats.byte_count, size);
    atomic_read_relaxed(&netdev_flow->stats.tcp_flags, &flags);
    flags |= tcp_flags;
    atomic_store_relaxed(&netdev_flow->stats.tcp_flags, flags);
}

static int
dp_netdev_upcall(struct dp_netdev_pmd_thread *pmd, struct dp_packet *packet_,
                 struct flow *flow, struct flow_wildcards *wc, ovs_u128 *ufid,
                 enum dpif_upcall_type type, const struct nlattr *userdata,
                 struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct dp_netdev *dp = pmd->dp;

    if (OVS_UNLIKELY(!dp->upcall_cb)) {
        return ENODEV;
    }

    if (OVS_UNLIKELY(!VLOG_DROP_DBG(&upcall_rl))) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        char *packet_str;
        struct ofpbuf key;
        struct odp_flow_key_parms odp_parms = {
            .flow = flow,
            .mask = wc ? &wc->masks : NULL,
            .support = dp_netdev_support,
        };

        ofpbuf_init(&key, 0);
        odp_flow_key_from_flow(&odp_parms, &key);
        packet_str = ofp_dp_packet_to_string(packet_);

        odp_flow_key_format(key.data, key.size, &ds);

        VLOG_DBG("%s: %s upcall:\n%s\n%s", dp->name,
                 dpif_upcall_type_to_string(type), ds_cstr(&ds), packet_str);

        ofpbuf_uninit(&key);
        free(packet_str);

        ds_destroy(&ds);
    }

    return dp->upcall_cb(packet_, flow, ufid, pmd->core_id, type, userdata,
                         actions, wc, put_actions, dp->upcall_aux);
}

static inline uint32_t
dpif_netdev_packet_get_rss_hash_orig_pkt(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    return hash;
}

static inline uint32_t
dpif_netdev_packet_get_rss_hash(struct dp_packet *packet,
                                const struct miniflow *mf)
{
    uint32_t hash, recirc_depth;

    if (OVS_LIKELY(dp_packet_rss_valid(packet))) {
        hash = dp_packet_get_rss_hash(packet);
    } else {
        hash = miniflow_hash_5tuple(mf, 0);
        dp_packet_set_rss_hash(packet, hash);
    }

    /* The RSS hash must account for the recirculation depth to avoid
     * collisions in the exact match cache */
    recirc_depth = *recirc_depth_get_unsafe();
    if (OVS_UNLIKELY(recirc_depth)) {
        hash = hash_finish(hash, recirc_depth);
    }
    return hash;
}

struct packet_batch_per_flow {
    unsigned int byte_count;
    uint16_t tcp_flags;
    struct dp_netdev_flow *flow;

    struct dp_packet_batch array;
};

static inline void
packet_batch_per_flow_update(struct packet_batch_per_flow *batch,
                             struct dp_packet *packet,
                             uint16_t tcp_flags)
{
    batch->byte_count += dp_packet_size(packet);
    batch->tcp_flags |= tcp_flags;
    dp_packet_batch_add(&batch->array, packet);
}

static inline void
packet_batch_per_flow_init(struct packet_batch_per_flow *batch,
                           struct dp_netdev_flow *flow)
{
    flow->batch = batch;

    batch->flow = flow;
    dp_packet_batch_init(&batch->array);
    batch->byte_count = 0;
    batch->tcp_flags = 0;
}

static inline void
packet_batch_per_flow_execute(struct packet_batch_per_flow *batch,
                              struct dp_netdev_pmd_thread *pmd)
{
    struct dp_netdev_actions *actions;
    struct dp_netdev_flow *flow = batch->flow;

    dp_netdev_flow_used(flow, dp_packet_batch_size(&batch->array),
                        batch->byte_count,
                        batch->tcp_flags, pmd->ctx.now / 1000);

    actions = dp_netdev_flow_get_actions(flow);

    dp_netdev_execute_actions(pmd, &batch->array, true, &flow->flow,
                              actions->actions, actions->size);
}

static inline void
dp_netdev_queue_batches(struct dp_packet *pkt,
                        struct dp_netdev_flow *flow, uint16_t tcp_flags,
                        struct packet_batch_per_flow *batches,
                        size_t *n_batches)
{
    struct packet_batch_per_flow *batch = flow->batch;

    if (OVS_UNLIKELY(!batch)) {
        batch = &batches[(*n_batches)++];
        packet_batch_per_flow_init(batch, flow);
    }

    packet_batch_per_flow_update(batch, pkt, tcp_flags);
}

static inline void
packet_enqueue_to_flow_map(struct dp_packet *packet,
                           struct dp_netdev_flow *flow,
                           uint16_t tcp_flags,
                           struct dp_packet_flow_map *flow_map,
                           size_t index)
{
    struct dp_packet_flow_map *map = &flow_map[index];
    map->flow = flow;
    map->packet = packet;
    map->tcp_flags = tcp_flags;
}

#ifdef E2E_CACHE_ENABLED

enum {
    E2E_UFID_MSG_PUT = 1,
    E2E_UFID_MSG_DEL = 2,
    E2E_UFID_MSG_FLUSH = 3,
};

struct e2e_cache_ufid_msg {
    struct mpsc_queue_node node;
    ovs_u128 ufid;
    int op;
    bool is_ct;
    struct nlattr *actions;
    struct dp_netdev *dp;
    struct netdev *netdev;
    struct ovs_barrier *barrier;
    size_t actions_len;
    union {
        struct match match[0];
        struct ct_match ct_match[0];
    };
};

struct e2e_cache_thread_msg_queues {
    struct mpsc_queue ufid_queue;
    struct mpsc_queue trace_queue;
};

/* This struct holds the e2e-cache statistic counters
 * generated_msgs = Amount of trace messages generated/dispatched to E2E cache.
 * processed_msgs = Amount of trace messages processed by E2E cache.
 * discarded_msgs = Amount of trace messages discarded by E2E cache.
 * aborted_msgs = Amount of trace messages aborted by E2E cache.
 * throttled_msgs = Amount of trace messages throttled due to high message
 *                  rate.
 * trace_msgs_in_queue = Amount of trace messages in E2E cache queue.
 * trace_msgs_queue_overflow = Amount of trace messages dropped due to
 *                             queue overflow.
 * new_flow_msgs = Amount of new flow messages received by E2E cache.
 * del_flow_msgs = Amount of delete flow messages received by E2E cache.
 * flush_flow_msgs = Amount of flush flow messages received by E2E cache.
 * succ_merged_flows = Amount of successfully merged flows.
 * merge_rej_flows = Amount of flows rejected by the merge engine.
 * add_merged_flow_hw = Amount of add merged flow messages dispatched to
 *                      HW offload.
 * del_merged_flow_hw = Amount of delete merged flow messages dispatched to
 *                      HW offload.
 * merged_flows_in_cache = Amount of merged flows in E2E cache.
 * add_ct_flow_hw = Amount of successful CT offload operations to MT.
 * add_ct_flow_err = Amount of failed CT offload operations MT.
 * add_ct_mt_flow_async = Amount of CT offload add operations sent to MT.
 * del_ct_mt_flow_async = Amount of CT offload del operations sent to MT.
 */
struct e2e_cache_stats {
    atomic_count generated_msgs;
    uint32_t processed_msgs;
    atomic_count discarded_msgs;
    atomic_count aborted_msgs;
    atomic_count throttled_msgs;
    atomic_count trace_msgs_in_queue;
    atomic_count trace_msgs_queue_overflow;
    atomic_count new_flow_msgs;
    atomic_count del_flow_msgs;
    uint32_t flush_flow_msgs;
    uint32_t succ_merged_flows;
    uint32_t merge_rej_flows;
    uint32_t add_merged_flow_hw;
    uint32_t del_merged_flow_hw;
    uint32_t merged_flows_in_cache;
    uint32_t add_ct_mt_flow_hw;
    uint32_t del_ct_mt_flow_hw;
    uint32_t add_ct_mt_flow_err;
    uint32_t del_ct_mt_flow_err;
    uint32_t add_ct_mt_flow_async;
    uint32_t del_ct_mt_flow_async;
};

static struct e2e_cache_thread_msg_queues e2e_cache_thread_msg_queues = {
    .ufid_queue =
        MPSC_QUEUE_INITIALIZER(&e2e_cache_thread_msg_queues.ufid_queue),
    .trace_queue =
        MPSC_QUEUE_INITIALIZER(&e2e_cache_thread_msg_queues.trace_queue)
};

static struct hmap counter_map = HMAP_INITIALIZER(&counter_map);

static inline int
e2e_cache_counter_cmp_key(const struct e2e_cache_counter_item *item,
                          const struct flows_counter_key *key)
{
    if (item->is_ct) {
        /* In case of CT compare only first 128 bits where 'ptr_key'
         * resides. It's not enough to compare only 'ptr_key' - second
         * argument can be not CT but first 64 bits of its key can be
         * equal to 'ptr_key' value of the first argument. In case of CT
         * next 64 bits after 'ptr_key' must always be 0, which cannot
         * happen in case of UFID.
         */
        const ovs_u128 *key0 = &item->key.ufid_key[0];
        const ovs_u128 *key1 = &key->ufid_key[0];

        return ovs_u128_equals(*key0, *key1) ? 0 : 1;
    }
    return memcmp(&item->key, key, sizeof *key);
}

static struct e2e_cache_counter_item *
e2e_cache_counter_find(size_t hash, const struct flows_counter_key *key)
{
    struct e2e_cache_counter_item *data;

    HMAP_FOR_EACH_WITH_HASH (data, node, hash, &counter_map) {
        if (data->hash == hash && !e2e_cache_counter_cmp_key(data, key)) {
            return data;
        }
    }
    return NULL;
}

static struct e2e_cache_counter_item *
e2e_cache_counter_alloc(const struct flows_counter_key *key, size_t hash,
                        bool is_ct)
{
    struct e2e_cache_counter_item *item;

    item = (struct e2e_cache_counter_item *) xmalloc(sizeof *item);
    item->hash = hash;
    item->is_ct = is_ct;
    ovs_list_init(&item->merged_flows);
    memcpy(&item->key, key, sizeof *key);
    return item;
}

static struct e2e_cache_stats e2e_stats = {
    .generated_msgs = ATOMIC_COUNT_INIT(0),
    .processed_msgs = 0,
    .discarded_msgs = ATOMIC_COUNT_INIT(0),
    .aborted_msgs = ATOMIC_COUNT_INIT(0),
    .throttled_msgs = ATOMIC_COUNT_INIT(0),
    .trace_msgs_in_queue = ATOMIC_COUNT_INIT(0),
    .trace_msgs_queue_overflow = ATOMIC_COUNT_INIT(0),
    .new_flow_msgs = ATOMIC_COUNT_INIT(0),
    .del_flow_msgs = ATOMIC_COUNT_INIT(0),
    .flush_flow_msgs = 0,
    .succ_merged_flows = 0,
    .merge_rej_flows = 0,
    .add_merged_flow_hw = 0,
    .del_merged_flow_hw = 0,
    .merged_flows_in_cache = 0,
    .add_ct_mt_flow_hw = 0,
    .del_ct_mt_flow_hw = 0,
    .add_ct_mt_flow_err = 0,
    .del_ct_mt_flow_err = 0,
    .add_ct_mt_flow_async = 0,
    .del_ct_mt_flow_async = 0,
};

static struct ovs_mutex flows_map_mutex = OVS_MUTEX_INITIALIZER;
static struct hmap flows_map OVS_GUARDED_BY(flows_map_mutex) =
    HMAP_INITIALIZER(&flows_map);

static struct ovs_mutex merged_flows_map_mutex = OVS_MUTEX_INITIALIZER;
static struct hmap merged_flows_map OVS_GUARDED_BY(merged_flows_map_mutex) =
    HMAP_INITIALIZER(&merged_flows_map);

static void
dpif_netdev_dump_e2e_stats(struct ds *s)
{
    struct e2e_cache_stats *stats = &e2e_stats;

    ds_put_format(s, "%-45s : %"PRIu32"", "generated messages",
                  atomic_count_get(&stats->generated_msgs));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "processed messages",
                  stats->processed_msgs);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "discarded messages",
                  atomic_count_get(&stats->discarded_msgs));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "aborted messages",
                  atomic_count_get(&stats->aborted_msgs));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "throttled messages",
                  atomic_count_get(&stats->throttled_msgs));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "messages in e2e queue",
                  atomic_count_get(&stats->trace_msgs_in_queue));
    ds_put_format(s, "\n%-45s : %"PRIu32,"dropped due to e2e queue overflow",
                  atomic_count_get(&stats->trace_msgs_queue_overflow));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "new flow messages",
                  atomic_count_get(&stats->new_flow_msgs));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "delete flow messages",
                  atomic_count_get(&stats->del_flow_msgs));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "flush flow messages",
                  stats->flush_flow_msgs);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "successfully merged flows",
                  stats->succ_merged_flows);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "flows rejected by the merge engine",
                  stats->merge_rej_flows);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "add merged flows messages to HW",
                  stats->add_merged_flow_hw);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "delete merged flows messages to HW",
                  stats->del_merged_flow_hw);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "merged flows in e2e cache",
                  stats->merged_flows_in_cache);
    ds_put_format(s, "\n%-45s : %"PRIu64"", "flows in e2e DB",
                  (uint64_t)hmap_count(&flows_map));
    ds_put_format(s, "\n%-45s : %"PRIu32"", "successful CT MT flows to HW",
                  stats->add_ct_mt_flow_hw);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "successful deleted CT MT flows "
                  "from HW", stats->del_ct_mt_flow_hw);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "failed CT MT flows to HW",
                  stats->add_ct_mt_flow_err);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "failed CT MT flow removals from "
                  "HW", stats->del_ct_mt_flow_err);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "Sent CT MT flows add",
                  stats->add_ct_mt_flow_async);
    ds_put_format(s, "\n%-45s : %"PRIu32"", "Sent CT MT flows delete",
                  stats->del_ct_mt_flow_async);
}

static void
dpif_netdev_dump_e2e_flows(struct hmap *portno_names,
                           struct ofputil_port_map *port_map, struct ds *s)
{
    struct e2e_cache_merged_flow *merged_flow;
    struct dp_netdev_flow netdev_flow;

    memset(&netdev_flow, 0, sizeof netdev_flow);

    ovs_mutex_lock(&merged_flows_map_mutex);

    HMAP_FOR_EACH (merged_flow, node.in_hmap, &merged_flows_map) {
        odp_format_ufid(&merged_flow->ufid, s);
        ds_put_cstr(s, ", ");
        match_format(&merged_flow->match, port_map, s, OFP_DEFAULT_PRIORITY);
        *CONST_CAST(ovs_u128 *, &netdev_flow.mega_ufid) = merged_flow->ufid;
        CONST_CAST(struct flow *, &netdev_flow.flow)->in_port =
            merged_flow->match.flow.in_port;
        ds_put_cstr(s, ", actions:");
        format_odp_actions(s, merged_flow->actions, merged_flow->actions_size,
                           portno_names);
        ds_put_cstr(s, "\n");
    }

    ovs_mutex_unlock(&merged_flows_map_mutex);
}

static inline void
e2e_cache_trace_init(struct dp_packet *p)
{
    p->e2e_trace_size = 0;
    p->e2e_trace_flags = 0;
    p->e2e_trace_ct_ufids = 0;
}

static inline void
e2e_cache_trace_add_flow(struct dp_packet *p,
                         const ovs_u128 *ufid)
{
    uint32_t e2e_trace_size = p->e2e_trace_size;

    if (OVS_UNLIKELY(e2e_trace_size >= E2E_CACHE_MAX_TRACE)) {
        p->e2e_trace_flags |= E2E_CACHE_TRACE_FLAG_OVERFLOW;
        return;
    }
    p->e2e_trace[e2e_trace_size] = *ufid;
    p->e2e_trace_size = e2e_trace_size + 1;
}

static inline void
e2e_cache_trace_msg_enqueue(struct e2e_cache_trace_message *msg)
{
    mpsc_queue_insert(&e2e_cache_thread_msg_queues.trace_queue,
                      &msg->node);
    atomic_count_inc(&e2e_stats.trace_msgs_in_queue);
}

#define E2E_CACHE_BACKOFF_MS_MIN 1
#define E2E_CACHE_BACKOFF_MS_MAX 64

static inline void
e2e_cache_poll_queues(struct e2e_cache_ufid_msg **ufid_msg,
                      struct e2e_cache_trace_message **trace_msg)
{
    struct mpsc_queue *trace_list = &e2e_cache_thread_msg_queues.trace_queue;
    struct mpsc_queue *ufid_list = &e2e_cache_thread_msg_queues.ufid_queue;
    enum mpsc_queue_poll_result trace_poll_result;
    enum mpsc_queue_poll_result ufid_poll_result;
    struct mpsc_queue_node *trace_node;
    struct mpsc_queue_node *ufid_node;
    uint64_t backoff;

    *ufid_msg = NULL;
    *trace_msg = NULL;

    backoff = E2E_CACHE_BACKOFF_MS_MIN;
    while (1) {
        ufid_poll_result = mpsc_queue_poll(ufid_list, &ufid_node);
        trace_poll_result = mpsc_queue_poll(trace_list, &trace_node);

        if (ufid_poll_result != MPSC_QUEUE_EMPTY ||
            trace_poll_result != MPSC_QUEUE_EMPTY) {
            break;
        }

        /* The thread is flagged as quiescent during xnanosleep(). */
        xnanosleep(backoff * 1E6);
        if (backoff < E2E_CACHE_BACKOFF_MS_MAX) {
            backoff <<= 1;
        }
    }

    while (ufid_poll_result == MPSC_QUEUE_RETRY) {
        ufid_poll_result = mpsc_queue_poll(ufid_list, &ufid_node);
    }

    while (trace_poll_result == MPSC_QUEUE_RETRY) {
        trace_poll_result = mpsc_queue_poll(trace_list, &trace_node);
    }

    if (ufid_poll_result == MPSC_QUEUE_ITEM) {
        *ufid_msg = CONTAINER_OF(ufid_node, struct e2e_cache_ufid_msg, node);
    }

    if (trace_poll_result == MPSC_QUEUE_ITEM) {
        *trace_msg = CONTAINER_OF(trace_node,
                                  struct e2e_cache_trace_message, node);
        atomic_count_dec(&e2e_stats.trace_msgs_in_queue);
    }
}

static inline void
e2e_cache_populate_offload_item(struct dp_offload_thread_item *offload_item,
                                int op,
                                struct dp_netdev *dp,
                                struct dp_netdev_flow *flow)
{
    memset(offload_item, 0, sizeof *offload_item);
    offload_item->type = DP_FLOW_OFFLOAD_ITEM;
    offload_item->dp = dp;
    offload_item->data->flow_offload.flow = flow;
    offload_item->data->flow_offload.op = op;
    offload_item->data->flow_offload.is_e2e_cache_flow = true;
}

static void
e2e_cache_disassociate_counters(struct e2e_cache_merged_flow *merged_flow)
{
    size_t counter_hash, ct_counter_hash, flows_counter_hash;
    struct flows_counter_key counter_key_on_stack;
    const struct flows_counter_key *counter_key;
    struct e2e_cache_counter_item *counter_item;
    struct e2e_cache_ovs_flow *mt_flow;
    struct ovs_list *next_counter;
    uint16_t i;

    /* If flow_counter_list is empty this means e2e_cache_associate_counters
     * was not executed for this e2e_cache_merged_flow.
     * In such case ct_counter_list must also empty.
     */
    if (OVS_UNLIKELY(ovs_list_is_empty(&merged_flow->flow_counter_list))) {
        return;
    }

    memset(&counter_key_on_stack, 0, sizeof counter_key_on_stack);
    ct_counter_hash = merged_flow->ct_counter_key;
    counter_key_on_stack.ptr_key = ct_counter_hash;
    flows_counter_hash = hash_bytes(&merged_flow->flows_counter_key,
                                    sizeof merged_flow->flows_counter_key,
                                    0);

    ovs_mutex_lock(&flows_map_mutex);
    for (i = 0; i < merged_flow->associated_flows_len; i++) {
        mt_flow = merged_flow->associated_flows[i].mt_flow;
        if (mt_flow->offload_state == E2E_OL_STATE_FLOW) {
            counter_hash = flows_counter_hash;
            counter_key = &merged_flow->flows_counter_key;
        } else {
            counter_hash = ct_counter_hash;
            counter_key = &counter_key_on_stack;
        }
        HMAP_FOR_EACH_WITH_HASH (counter_item, node, counter_hash,
                                 &mt_flow->merged_counters) {
            if (counter_item->hash == counter_hash &&
                !e2e_cache_counter_cmp_key(counter_item, counter_key)) {
                break;
            }
        }
        if (OVS_LIKELY(counter_item)) {
            hmap_remove(&mt_flow->merged_counters, &counter_item->node);
            free(counter_item);
        }
    }
    next_counter = ovs_list_front(&merged_flow->flow_counter_list);
    ovs_list_remove(&merged_flow->flow_counter_list);
    if (ovs_list_is_empty(next_counter)) {
        counter_item = CONTAINER_OF(next_counter,
                                    struct e2e_cache_counter_item,
                                    merged_flows);
        hmap_remove(&counter_map, &counter_item->node);
        free(counter_item);
    }
    next_counter = ovs_list_front(&merged_flow->ct_counter_list);
    ovs_list_remove(&merged_flow->ct_counter_list);
    if (ovs_list_is_empty(next_counter)) {
        counter_item = CONTAINER_OF(next_counter,
                                    struct e2e_cache_counter_item,
                                    merged_flows);
        hmap_remove(&counter_map, &counter_item->node);
        free(counter_item);
    }
    ovs_mutex_unlock(&flows_map_mutex);
}

static void
e2e_cache_associate_counters(struct e2e_cache_merged_flow *merged_flow,
                             struct e2e_cache_ovs_flow *mt_flows[],
                             const struct e2e_cache_trace_info *trc_info)
{
    size_t counter_hash, ct_counter_key_hash, flows_counter_key_hash;
    struct flows_counter_key counter_key_on_stack;
    const struct flows_counter_key *counter_key;
    struct e2e_cache_counter_item *counter_item;
    uint16_t mt_index, flows_index = 0;

    BUILD_ASSERT_DECL(sizeof(size_t) >= sizeof(uintptr_t));

    memset(&counter_key_on_stack, 0, sizeof counter_key_on_stack);
    ct_counter_key_hash = merged_flow->ct_counter_key;
    counter_key_on_stack.ptr_key = ct_counter_key_hash;
    flows_counter_key_hash = hash_bytes(&merged_flow->flows_counter_key,
                                        sizeof merged_flow->flows_counter_key,
                                        0);
    ovs_mutex_lock(&flows_map_mutex);

    for (mt_index = 0; mt_index < trc_info->num_elements; mt_index++) {
        bool is_ct = trc_info->e2e_trace_ct_ufids & (1 << mt_index);
        bool counter_found = false;

        if (is_ct) {
            counter_key = &counter_key_on_stack;
            counter_hash = ct_counter_key_hash;
        } else {
            counter_key = &merged_flow->flows_counter_key;
            counter_hash = flows_counter_key_hash;
        }
        /* Search if this counter is already used by this flow. */
        HMAP_FOR_EACH_WITH_HASH (counter_item, node, counter_hash,
                                 &mt_flows[flows_index]->merged_counters) {
            if (counter_item->hash == counter_hash &&
                !e2e_cache_counter_cmp_key(counter_item, counter_key)) {
                if (OVS_UNLIKELY(counter_item->is_ct != is_ct)) {
                    OVS_NOT_REACHED();
                }
                counter_found = true;
                break;
            }
        }
        /* If this counter is not in use by this flow, add it. */
        if (!counter_found) {
            counter_item = e2e_cache_counter_alloc(counter_key, counter_hash,
                                                   is_ct);
            hmap_insert(&mt_flows[flows_index]->merged_counters,
                        &counter_item->node, counter_hash);
        }
        flows_index++;
    }

    /* Search for an already existing CT counter item, or create if not. */
    counter_hash = ct_counter_key_hash;
    counter_key = &counter_key_on_stack;
    counter_item = e2e_cache_counter_find(counter_hash, counter_key);
    if (!counter_item) {
        counter_item = e2e_cache_counter_alloc(counter_key, counter_hash,
                                               true);
        hmap_insert(&counter_map, &counter_item->node, counter_hash);
    }
    /* Add the merged flow to the counter item. */
    ovs_list_push_back(&counter_item->merged_flows,
                       &merged_flow->ct_counter_list);

    /* Search for an already existing flows counter item, or create if not. */
    counter_hash = flows_counter_key_hash;
    counter_key = &merged_flow->flows_counter_key;
    counter_item = e2e_cache_counter_find(counter_hash, counter_key);
    if (!counter_item) {
        counter_item = e2e_cache_counter_alloc(counter_key, counter_hash,
                                               false);
        hmap_insert(&counter_map, &counter_item->node, counter_hash);
    }
    /* Add the merged flow to the counter item. */
    ovs_list_push_back(&counter_item->merged_flows,
                       &merged_flow->flow_counter_list);

    ovs_mutex_unlock(&flows_map_mutex);
}

static int
e2e_cache_merged_flow_offload_del(struct e2e_cache_merged_flow *merged_flow)
{
    struct dp_offload_thread_item *offload_item;
    struct dp_netdev *dp = merged_flow->dp;
    struct dp_netdev_flow flow;
    int rv;

    ovs_assert(dp);

    memset(&flow, 0, sizeof flow);
    *CONST_CAST(ovs_u128 *, &flow.mega_ufid) = merged_flow->ufid;
    CONST_CAST(struct flow *, &flow.flow)->in_port =
        merged_flow->match.flow.in_port;

    offload_item = xmalloc(sizeof *offload_item +
                           sizeof offload_item->data->flow_offload);
    e2e_cache_populate_offload_item(offload_item,
                                    DP_NETDEV_FLOW_OFFLOAD_OP_DEL, dp, &flow);

    merged_flow->dp = NULL;
    e2e_stats.del_merged_flow_hw++;
    rv = dp_netdev_flow_offload_del(offload_item);
    free(offload_item);
    return rv;
}

static void
e2e_cache_calc_counters(struct e2e_cache_merged_flow *merged_flow,
                        struct e2e_cache_ovs_flow *mt_flows[],
                        const struct e2e_cache_trace_info *trc_info)
{
    uintptr_t ptr, ct_counter_key = UINTPTR_MAX;
    uint16_t mt_index, flows_index = 0;

    merged_flow->ct_counter_key = 0;
    memset(&merged_flow->flows_counter_key, 0,
           sizeof merged_flow->flows_counter_key);

    for (mt_index = 0; mt_index < trc_info->num_elements; mt_index++) {
        if (trc_info->e2e_trace_ct_ufids & (1 << mt_index)) {
            if (trc_info->e2e_trace_ct_ufids & (1 << (mt_index + 1))) {
                continue;
            }
            /* CT are traced only for both directions, adjacent. Calc
             * ct_counter as the lowest value among all pointers to DB items
             * for all CT in the trace.
             */
            ptr = (uintptr_t) mt_flows[mt_index];
            if (ptr < ct_counter_key) {
                ct_counter_key = ptr;
            }
            ptr = (uintptr_t) mt_flows[mt_index - 1];
            if (ptr < ct_counter_key) {
                ct_counter_key = ptr;
            }
        } else {
            merged_flow->flows_counter_key.ufid_key[flows_index++] =
                trc_info->ufids[mt_index];
        }
    }

    if (trc_info->e2e_trace_ct_ufids) {
        merged_flow->ct_counter_key = ct_counter_key;
    }
}

static int
e2e_cache_merged_flow_offload_put(struct dp_netdev *dp,
                                  struct e2e_cache_merged_flow *merged_flow,
                                  struct e2e_cache_ovs_flow *mt_flows[],
                                  const struct e2e_cache_trace_info *trc_info)
{
    struct dp_offload_thread_item *offload_item;
    struct dp_flow_offload_item *flow_offload;
    struct dp_netdev_flow flow;
    union flow_in_port in_port;
    int err;

    in_port = merged_flow->match.flow.in_port;

    memset(&flow, 0, sizeof flow);
    flow.mark = INVALID_FLOW_MARK;
    flow.dead = false;
    *CONST_CAST(ovs_u128 *, &flow.mega_ufid) = merged_flow->ufid;
    CONST_CAST(struct flow *, &flow.flow)->in_port = in_port;

    offload_item = xmalloc(sizeof *offload_item +
                           sizeof offload_item->data->flow_offload);
    e2e_cache_populate_offload_item(offload_item,
                                    DP_NETDEV_FLOW_OFFLOAD_OP_ADD, dp, &flow);

    e2e_cache_calc_counters(merged_flow, mt_flows, trc_info);
    e2e_cache_associate_counters(merged_flow, mt_flows, trc_info);

    flow_offload = &offload_item->data->flow_offload;
    memcpy(&flow_offload->match, &merged_flow->match,
           sizeof merged_flow->match);
    flow_offload->actions = xmalloc(merged_flow->actions_size);
    if (OVS_UNLIKELY(!flow_offload->actions)) {
        err = -1;
        goto error;
    }

    memcpy(flow_offload->actions, merged_flow->actions,
           merged_flow->actions_size);
    flow_offload->actions_len = merged_flow->actions_size;
    offload_item->data->flow_offload.ct_counter_key =
        merged_flow->ct_counter_key;
    memcpy(&offload_item->data->flow_offload.flows_counter_key,
           &merged_flow->flows_counter_key,
           sizeof offload_item->data->flow_offload.flows_counter_key);
    err = dp_netdev_flow_offload_put(offload_item);
    free(flow_offload->actions);
    free(offload_item);
    if (OVS_UNLIKELY(err != 0)) {
        goto error;
    }

    merged_flow->dp = dp;
    e2e_stats.add_merged_flow_hw++;
    return 0;

error:
    return err;
}

/* Associate the merged flow to each of its composing flows,
 * to allow accessing:
 * - From the merged flow to all its composing flows.
 * - From each flow to all the merged flow it is part of.
 */
static void
e2e_cache_associate_merged_flow(struct e2e_cache_merged_flow *merged_flow,
                                struct e2e_cache_ovs_flow *flows[],
                                uint16_t num_flows)
{
    uint16_t i, j;

    for (j = 0, i = 0; j < num_flows; j++) {
        if (flows[j]->offload_state != E2E_OL_STATE_FLOW && j > 0 &&
            flows[j - 1]->offload_state != E2E_OL_STATE_FLOW) {
            continue;
        }
        merged_flow->associated_flows[i].index = i;
        ovs_list_push_back(&flows[j]->associated_merged_flows,
                           &merged_flow->associated_flows[i].list);
        merged_flow->associated_flows[i].mt_flow = flows[j];
        i++;
    }
    merged_flow->associated_flows_len = i;
}

static void
e2e_cache_disassociate_merged_flow(struct e2e_cache_merged_flow *merged_flow)
{
    uint16_t i, num_flows = merged_flow->associated_flows_len;

    for (i = 0; i < num_flows; i++) {
        ovs_list_remove(&merged_flow->associated_flows[i].list);
    }
}

/* Find e2e_cache_merged_flow with @ufid.
 * merged_flows_map_mutex mutex must be locked.
 */
static inline struct e2e_cache_merged_flow *
e2e_cache_merged_flow_find(const ovs_u128 *ufid, uint32_t hash)
{
    struct e2e_cache_merged_flow *merged_flow;

    HMAP_FOR_EACH_WITH_HASH (merged_flow, node.in_hmap, hash,
                             &merged_flows_map) {
        if (ovs_u128_equals(*ufid, merged_flow->ufid)) {
            return merged_flow;
        }
    }

    return NULL;
}

static inline struct e2e_cache_ovs_flow *
e2e_cache_flow_alloc(bool is_ct)
{
    struct e2e_cache_ovs_flow *flow;
    size_t alloc_bytes;

    alloc_bytes = sizeof *flow;
    alloc_bytes += is_ct ? sizeof flow->ct_match[0] : sizeof flow->match[0];

    flow = (struct e2e_cache_ovs_flow *) xzalloc(alloc_bytes);
    return flow;
}

static void
e2e_cache_flow_free(void *arg)
{
    struct e2e_cache_ovs_flow *flow = (struct e2e_cache_ovs_flow *) arg;

    if (flow->actions) {
        free(flow->actions);
    }
    free(flow);
}

static inline struct e2e_cache_ufid_msg *
e2e_cache_ufid_msg_alloc(int op, bool is_ct, size_t actions_len)
{
    struct e2e_cache_ufid_msg *msg;
    struct nlattr *actions = NULL;
    size_t alloc_size;

    alloc_size = sizeof *msg;
    if (op == E2E_UFID_MSG_PUT) {
        if (actions_len) {
            actions = (struct nlattr *) xmalloc(actions_len);
            if (OVS_UNLIKELY(!actions)) {
                return NULL;
            }
        }
        alloc_size += is_ct ? sizeof msg->ct_match[0] :
                              sizeof msg->match[0];
    }

    msg = (struct e2e_cache_ufid_msg *) xmalloc(alloc_size);
    if (OVS_UNLIKELY(!msg)) {
        goto err;
    }

    msg->op = op;
    msg->is_ct = is_ct;
    msg->actions = actions;
    msg->actions_len = actions_len;
    return msg;

err:
    if (actions) {
        free(actions);
    }
    return NULL;
}

static inline void
e2e_cache_ufid_msg_free(struct e2e_cache_ufid_msg *msg)
{
    if (msg->actions) {
        free(msg->actions);
    }
    free(msg);
}

static void
e2e_cache_merged_flow_free(struct e2e_cache_merged_flow *merged_flow)
{
    e2e_cache_disassociate_counters(merged_flow);
    if (merged_flow->actions) {
        free(merged_flow->actions);
    }
    free(merged_flow);
}

static void
e2e_cache_merged_flow_db_rem(struct e2e_cache_merged_flow *merged_flow)
{
    e2e_cache_disassociate_merged_flow(merged_flow);

    ovs_mutex_lock(&merged_flows_map_mutex);
    hmap_remove(&merged_flows_map, &merged_flow->node.in_hmap);
    e2e_stats.merged_flows_in_cache--;
    ovs_mutex_unlock(&merged_flows_map_mutex);
}

static void
e2e_cache_merged_flow_db_del(struct e2e_cache_merged_flow *merged_flow)
{
    /* Lock/unlock to prevent race condition with
     * e2e_cache_get_merged_flows_stats()
     */
    ovs_mutex_lock(&flows_map_mutex);
    e2e_cache_merged_flow_db_rem(merged_flow);
    ovs_mutex_unlock(&flows_map_mutex);

    e2e_cache_merged_flow_free(merged_flow);
}

static inline int
e2e_cache_merged_flow_db_put(struct e2e_cache_merged_flow *merged_flow)
{
    uint32_t hash =
        hash_bytes(&merged_flow->ufid, sizeof merged_flow->ufid, 0);
    struct e2e_cache_merged_flow *old_merged_flow;

    ovs_mutex_lock(&merged_flows_map_mutex);

    old_merged_flow = e2e_cache_merged_flow_find(&merged_flow->ufid, hash);
    /* In case the merged flow exists do nothing. */
    if (old_merged_flow) {
        uint16_t actions_size = merged_flow->actions_size;

        if (old_merged_flow->actions_size == actions_size &&
            !memcmp(old_merged_flow->actions, merged_flow->actions,
                    actions_size)) {
            ovs_mutex_unlock(&merged_flows_map_mutex);
            return -1;
        }

        /* Must unlock merged_flows_map_mutex before calling next functions */
        ovs_mutex_unlock(&merged_flows_map_mutex);

        /* In case it's a flow modification delete the current flow
         * before inserting the updated one.
         */
        e2e_cache_merged_flow_offload_del(old_merged_flow);
        e2e_cache_merged_flow_db_del(old_merged_flow);

        ovs_mutex_lock(&merged_flows_map_mutex);
    }

    hmap_insert(&merged_flows_map, &merged_flow->node.in_hmap, hash);
    e2e_stats.merged_flows_in_cache++;

    ovs_mutex_unlock(&merged_flows_map_mutex);
    return 0;
}

/* Find e2e_cache_ovs_flow with @ufid and calculated @hash */
static inline struct e2e_cache_ovs_flow *
e2e_cache_flow_find(const ovs_u128 *ufid, uint32_t hash)
{
    struct e2e_cache_ovs_flow *flow;

    HMAP_FOR_EACH_WITH_HASH (flow, node, hash, &flows_map) {
        if (ovs_u128_equals(*ufid, flow->ufid)) {
            return flow;
        }
    }

    return NULL;
}

static void
e2e_cache_update_ct_stats(struct e2e_cache_ovs_flow *mt_flow, int op)
{
    struct dp_offload_thread *ofl_thread;
    struct e2e_cache_ovs_flow *ct_peer;

    ofl_thread = &dp_offload_threads[netdev_offload_thread_id()];

    ct_peer = mt_flow->ct_peer;
    if (op == DP_NETDEV_FLOW_OFFLOAD_OP_ADD) {
        if (ct_peer &&
            (ct_peer->offload_state == E2E_OL_STATE_CT_HW ||
             ct_peer->offload_state == E2E_OL_STATE_CT_MT_LOCAL ||
             !ovs_list_is_empty(&ct_peer->associated_merged_flows))) {
            atomic_count_inc64(&ofl_thread->ct_bi_dir_connections);
            atomic_count_dec64(&ofl_thread->ct_uni_dir_connections);
        } else {
            atomic_count_inc64(&ofl_thread->ct_uni_dir_connections);
        }
    } else if (op == DP_NETDEV_FLOW_OFFLOAD_OP_DEL) {
        if (ct_peer &&
            (ct_peer->offload_state == E2E_OL_STATE_CT_HW ||
             ct_peer->offload_state == E2E_OL_STATE_CT_MT_LOCAL ||
             !ovs_list_is_empty(&ct_peer->associated_merged_flows))) {
            atomic_count_dec64(&ofl_thread->ct_bi_dir_connections);
            atomic_count_inc64(&ofl_thread->ct_uni_dir_connections);
        } else {
            atomic_count_dec64(&ofl_thread->ct_uni_dir_connections);
        }
    } else {
        OVS_NOT_REACHED();
    }
}

static void
e2e_cache_del_associated_merged_flows(struct e2e_cache_ovs_flow *flow,
                                      struct ovs_list *merged_flows_to_delete)
{
    struct flow2flow_item *associated_flow_item, *next_item;
    struct e2e_cache_merged_flow *merged_flow;

    LIST_FOR_EACH_SAFE (associated_flow_item, next_item, list,
                        &flow->associated_merged_flows) {
        merged_flow =
            CONTAINER_OF(associated_flow_item,
                         struct e2e_cache_merged_flow,
                         associated_flows[associated_flow_item->index]);

        e2e_cache_merged_flow_db_rem(merged_flow);
        ovs_list_push_back(merged_flows_to_delete, &merged_flow->node.in_list);
    }
}

static void
e2e_cache_del_merged_flows(struct ovs_list *merged_flows_to_delete)
{
    struct e2e_cache_merged_flow *merged_flow;
    struct ovs_list *l;

    while (!ovs_list_is_empty(merged_flows_to_delete)) {
        l = ovs_list_pop_front(merged_flows_to_delete);

        merged_flow =
            CONTAINER_OF(l, struct e2e_cache_merged_flow, node.in_list);

        e2e_cache_merged_flow_offload_del(merged_flow);
        e2e_cache_merged_flow_free(merged_flow);
    }
}

static struct e2e_cache_ovs_flow *
e2e_cache_flow_db_del_protected(const ovs_u128 *ufid, uint32_t hash,
                                struct ovs_list *merged_flows_to_delete)
{
    struct e2e_cache_ovs_flow *flow;

    flow = e2e_cache_flow_find(ufid, hash);
    if (OVS_UNLIKELY(!flow)) {
        return NULL;
    }
    e2e_cache_del_associated_merged_flows(flow, merged_flows_to_delete);
    hmap_remove(&flows_map, &flow->node);
    if (flow->offload_state == E2E_OL_STATE_FLOW) {
        ovsrcu_postpone(e2e_cache_flow_free, flow);
        flow = NULL;
    }
    return flow;
}

static void
e2e_cache_flow_state_set_at(struct e2e_cache_ovs_flow *flow,
                            enum e2e_offload_state next_state,
                            const char *where)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(100, 100);
    static const int op[E2E_OL_STATE_NUM][E2E_OL_STATE_NUM] = {
        [E2E_OL_STATE_CT_SW] = {
            [E2E_OL_STATE_CT_HW] = DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
            [E2E_OL_STATE_CT_MT_LOCAL] = DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
        },
        [E2E_OL_STATE_CT_HW] = {
            [E2E_OL_STATE_CT_SW] = DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
            [E2E_OL_STATE_CT_MT_ASYNC] = DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
            [E2E_OL_STATE_CT_ERR] = DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
        },
        [E2E_OL_STATE_CT_MT_LOCAL] = {
            [E2E_OL_STATE_CT_SW] = DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
            [E2E_OL_STATE_CT_MT_ASYNC] = DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
            [E2E_OL_STATE_CT_ERR] = DP_NETDEV_FLOW_OFFLOAD_OP_DEL,
        },
        [E2E_OL_STATE_CT_MT_ASYNC] = {
            [E2E_OL_STATE_CT_HW] = DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
            [E2E_OL_STATE_CT_MT_LOCAL] = DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
        },
        [E2E_OL_STATE_CT_ERR] = {
            [E2E_OL_STATE_CT_HW] = DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
            [E2E_OL_STATE_CT_MT_LOCAL] = DP_NETDEV_FLOW_OFFLOAD_OP_ADD,
        },
    };
    enum e2e_offload_state prev_state = flow->offload_state;
    int flow_op;

    if (prev_state < E2E_OL_STATE_FLOW || prev_state >= E2E_OL_STATE_NUM) {
        /* If flow state was not yet initialized, assume a start state that
         * is assured to be a no-op regarding CT stats.
         */
        prev_state = E2E_OL_STATE_FLOW;
    }

    ovs_assert(next_state >= E2E_OL_STATE_FLOW &&
               next_state < E2E_OL_STATE_NUM);

    VLOG_DBG_RL(&rl, "%s: e2e-flow " UUID_FMT " state is %s", where,
                UUID_ARGS((struct uuid *) &flow->ufid),
                e2e_offload_state_names[next_state]);
    flow->offload_state = next_state;

    flow_op = op[prev_state][next_state];
    if (flow_op == DP_NETDEV_FLOW_OFFLOAD_OP_NONE) {
        return;
    }

    e2e_cache_update_ct_stats(flow, flow_op);
}
#define e2e_cache_flow_state_set(f, s) \
    e2e_cache_flow_state_set_at(f, s, __func__)

static void
e2e_cache_offload_ct_mt_build(struct ct_flow_offload_item *offload,
                              ovs_u128 ufid, struct dp_netdev *dp,
                              struct ct_match ct_match,
                              struct nlattr *actions, size_t actions_size)
{
    offload->ct_actions_set = true;
    if (actions != NULL) {
        offload->actions = xmalloc(actions_size);
        memcpy(offload->actions, actions, actions_size);
        offload->actions_size = actions_size;
    } else {
        offload->actions = NULL;
        offload->actions_size = 0;
    }

    offload->ct_match = ct_match;
    offload->ufid = ufid;
    offload->dp = dp;
}

static void
e2e_cache_ct_mt_del_local(struct dp_netdev *dp,
                          struct e2e_cache_ovs_flow *ct_flow)
{
    struct {
        struct dp_offload_thread_item header;
        struct ct_flow_offload_item offload[1];
    } item = {
        .header = {
            .type = DP_CT_OFFLOAD_ITEM,
            .dp = dp,
        },
    };
    int ret;

    memset(item.offload, 0, sizeof item.offload);

    item.offload->op = DP_NETDEV_FLOW_OFFLOAD_OP_DEL;
    e2e_cache_offload_ct_mt_build(item.offload,
                                  ct_flow->ufid, dp,
                                  ct_flow->ct_match[0],
                                  NULL, 0);

    ret = dp_netdev_ct_offload_del(&item.header, CT_DIR_INIT);

    if (OVS_LIKELY(ret == 0)) {
        e2e_cache_flow_state_set(ct_flow, E2E_OL_STATE_CT_SW);
        e2e_stats.del_ct_mt_flow_hw++;
    } else {
        e2e_cache_flow_state_set(ct_flow, E2E_OL_STATE_CT_ERR);
        e2e_stats.del_ct_mt_flow_err++;
    }
}

static void
e2e_cache_ct_mt_del_async(struct dp_netdev *dp,
                          struct e2e_cache_ovs_flow *ct_flow)
{
    struct ct_flow_offload_item offload[CT_DIR_NUM];
    struct e2e_cache_ovs_flow *ct_peer;
    struct ovs_refcount *refcnt;

    ct_peer = ct_flow->ct_peer;
    refcnt = ct_flow->mt_refcnt;

    /* Deletion could be done in reverse order from
     * addition, meaning the refcnt would be set on the ct_peer.
     */
    if (refcnt == NULL) {
        refcnt = ct_peer->mt_refcnt;
    }

    if (ovs_refcount_unref(refcnt) > 1) {
        /* MT request is still in the queue. The refcnt
         * will signal to discard the request. It will be freed
         * in the MT-thread.
         */
        goto update_state;
    }

    memset(offload, 0, sizeof offload);

    offload[CT_DIR_INIT].refcnt = refcnt;
    offload[CT_DIR_INIT].op = DP_NETDEV_FLOW_OFFLOAD_OP_DEL;
    offload[CT_DIR_REP].op = DP_NETDEV_FLOW_OFFLOAD_OP_DEL;

    e2e_cache_offload_ct_mt_build(&offload[CT_DIR_INIT],
                                  ct_flow->ufid, dp,
                                  ct_flow->ct_match[0],
                                  NULL, 0);
    e2e_cache_offload_ct_mt_build(&offload[CT_DIR_REP],
                                  ct_peer->ufid, dp,
                                  ct_peer->ct_match[0],
                                  NULL, 0);

    dp_netdev_append_ct_offload(offload);

    e2e_stats.del_ct_mt_flow_async += 2;

update_state:
    e2e_cache_flow_state_set(ct_flow, E2E_OL_STATE_CT_SW);
    e2e_cache_flow_state_set(ct_peer, E2E_OL_STATE_CT_SW);
}

static void
e2e_cache_ct_flow_offload_del_mt(struct dp_netdev *dp,
                                 struct e2e_cache_ovs_flow *ct_flow)
{

    if (ct_flow->offload_state != E2E_OL_STATE_CT_MT_ASYNC &&
        ct_flow->offload_state != E2E_OL_STATE_CT_MT_LOCAL) {
        return;
    }

    if (ct_flow->offload_state == E2E_OL_STATE_CT_MT_ASYNC) {
        e2e_cache_ct_mt_del_async(dp, ct_flow);
    } else {
        e2e_cache_ct_mt_del_local(dp, ct_flow);
    }
}

static void
e2e_cache_ct_mt_add_local(struct dp_netdev *dp,
                          struct e2e_cache_ovs_flow *ct_flow)
{
    struct ct_flow_offload_item offload[1];
    /* Maximum number of action was tested and found to be 204 in size. */
    struct nlattr actions[256 / sizeof(struct nlattr)];
    size_t actions_size;
    int ret;

    actions_size = ct_flow->actions_size;
    ovs_assert(actions_size <= sizeof actions);
    memcpy(actions, ct_flow->actions, actions_size);

    memset(offload, 0, sizeof offload);
    e2e_cache_offload_ct_mt_build(offload,
                                  ct_flow->ufid, dp,
                                  ct_flow->ct_match[0],
                                  NULL, 0);
    ret = dp_netdev_ct_offload_add_cb(offload, dp,
                                      ct_flow->ct_match,
                                      actions, actions_size);

    if (OVS_LIKELY(ret == 0)) {
        e2e_cache_flow_state_set(ct_flow, E2E_OL_STATE_CT_MT_LOCAL);
        e2e_stats.add_ct_mt_flow_hw++;
    } else {
        e2e_cache_flow_state_set(ct_flow, E2E_OL_STATE_CT_ERR);
        e2e_stats.add_ct_mt_flow_err++;
    }
}

static void
e2e_cache_ct_mt_add_async(struct dp_netdev *dp,
                          struct e2e_cache_ovs_flow *ct_flow)
{
    struct ct_flow_offload_item offload[CT_DIR_NUM];
    struct e2e_cache_ovs_flow *ct_peer;
    struct ovs_refcount *refcnt;

    memset(offload, 0, sizeof offload);

    ct_peer = ct_flow->ct_peer;
    refcnt = xmalloc(sizeof *refcnt);
    ovs_refcount_init(refcnt);
    ovs_refcount_ref(refcnt);
    ct_flow->mt_refcnt = refcnt;
    ct_peer->mt_refcnt = NULL;

    e2e_cache_offload_ct_mt_build(&offload[CT_DIR_INIT],
                                  ct_flow->ufid, dp,
                                  ct_flow->ct_match[0],
                                  ct_flow->actions,
                                  ct_flow->actions_size);
    e2e_cache_offload_ct_mt_build(&offload[CT_DIR_REP],
                                  ct_peer->ufid, dp,
                                  ct_peer->ct_match[0],
                                  ct_peer->actions,
                                  ct_peer->actions_size);

    offload[CT_DIR_INIT].refcnt = refcnt;
    offload[CT_DIR_INIT].op = DP_NETDEV_FLOW_OFFLOAD_OP_ADD;
    offload[CT_DIR_REP].op = DP_NETDEV_FLOW_OFFLOAD_OP_ADD;

    dp_netdev_append_ct_offload(offload);

    e2e_cache_flow_state_set(ct_flow, E2E_OL_STATE_CT_MT_ASYNC);
    e2e_cache_flow_state_set(ct_peer, E2E_OL_STATE_CT_MT_ASYNC);
    e2e_stats.add_ct_mt_flow_async += 2;
}

static void
e2e_cache_ct_flow_offload_add_mt(struct dp_netdev *dp,
                                 struct e2e_cache_ovs_flow *ct_flow)
{
    struct e2e_cache_ovs_flow *ct_peer;

    if (ct_flow->offload_state != E2E_OL_STATE_CT_SW) {
        return;
    }

    ct_peer = ct_flow->ct_peer;
    if (ct_peer != NULL && ct_peer->offload_state == E2E_OL_STATE_CT_SW) {
        e2e_cache_ct_mt_add_async(dp, ct_flow);
    } else {
        e2e_cache_ct_mt_add_local(dp, ct_flow);
    }
}

static void
e2e_cache_flow_db_del(const ovs_u128 *ufid, struct dp_netdev *dp)
{
    struct ovs_list merged_flows_to_delete =
        OVS_LIST_INITIALIZER(&merged_flows_to_delete);
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct e2e_cache_ovs_flow *ct_flow, *iter_flow;
    struct e2e_cache_merged_flow *merged_flow;
    uint16_t i;

    ovs_mutex_lock(&flows_map_mutex);
    ct_flow = e2e_cache_flow_db_del_protected(ufid, hash,
                                              &merged_flows_to_delete);
    ovs_mutex_unlock(&flows_map_mutex);

    /* Update CT stats affected by deletion of the merged flows. */
    LIST_FOR_EACH (merged_flow, node.in_list, &merged_flows_to_delete) {
        for (i = 0; i < merged_flow->associated_flows_len; i++) {
            iter_flow = merged_flow->associated_flows[i].mt_flow;
            if (iter_flow->offload_state == E2E_OL_STATE_FLOW) {
                continue;
            }
            if (ovs_list_is_empty(&iter_flow->associated_merged_flows)) {
                e2e_cache_flow_state_set(iter_flow, E2E_OL_STATE_CT_SW);
            }
        }
    }
    if (ct_flow) {
        /* If there was any MT offload, delete it. */
        e2e_cache_ct_flow_offload_del_mt(dp, ct_flow);
        if (ct_flow->offload_state == E2E_OL_STATE_CT_HW) {
            /* If it was offloaded through e2e, update stats. */
            e2e_cache_flow_state_set(ct_flow, E2E_OL_STATE_CT_SW);
        }
        if (ct_flow->ct_peer) {
            ct_flow->ct_peer->ct_peer = NULL;
        }
        ovsrcu_postpone(e2e_cache_flow_free, ct_flow);
    }
    e2e_cache_del_merged_flows(&merged_flows_to_delete);
}

static void
e2e_cache_flow_db_flush(struct netdev *netdev,
                        struct ovs_barrier *barrier,
                        struct dp_netdev *dp)
{
    dp_netdev_offload_init();

    /* From e2e perspective, its flow DB can be cleaned up later.
     * However, the flush request must be forwarded to MT threads.
     * Main thread cannot send it, as it needs to arrive *after* all
     * potential e2e -> MT async CT del requests, that could have been
     * issued by conntrack_destroy(), and that requires 'dp' to still
     * exist.
     *
     * Both types of flush are forwarded: either with 'netdev' defined,
     * used to flush a port HW offloads, or undefined, and used only as
     * a barrier after CT del requests to ensure the datapath exists.
     */

    dp_netdev_offload_flush_enqueue(dp, netdev, barrier);

    ovs_barrier_block(barrier);
}

static int
e2e_cache_flow_db_put(struct e2e_cache_ufid_msg *ufid_msg)
{
    struct e2e_cache_ovs_flow *flow_prev, *flow;
    struct ovs_list merged_flows_to_delete =
        OVS_LIST_INITIALIZER(&merged_flows_to_delete);
    const ovs_u128 *ufid;
    size_t hash;

    flow = e2e_cache_flow_alloc(ufid_msg->is_ct);
    if (OVS_UNLIKELY(!flow)) {
        return -1;
    }

    flow->ufid = ufid_msg->ufid;
    if (ufid_msg->is_ct) {
        flow->ct_match[0] = ufid_msg->ct_match[0];
        e2e_cache_flow_state_set(flow, E2E_OL_STATE_CT_SW);
    } else {
        flow->match[0] = ufid_msg->match[0];
        e2e_cache_flow_state_set(flow, E2E_OL_STATE_FLOW);
    }
    flow->actions = ufid_msg->actions;
    ufid_msg->actions = NULL;
    flow->actions_size = ufid_msg->actions_len;
    ovs_list_init(&flow->associated_merged_flows);
    hmap_init(&flow->merged_counters);

    ufid = &flow->ufid;
    hash = hash_bytes(ufid, sizeof *ufid, 0);

    ovs_mutex_lock(&flows_map_mutex);

    flow_prev = e2e_cache_flow_find(ufid, hash);
    if (flow_prev) {
        e2e_cache_flow_db_del_protected(ufid, hash, &merged_flows_to_delete);
    }

    hmap_insert(&flows_map, &flow->node, hash);

    ovs_mutex_unlock(&flows_map_mutex);

    e2e_cache_del_merged_flows(&merged_flows_to_delete);
    return 0;
}

static int
e2e_cache_flow_del(const ovs_u128 *ufid, struct dp_netdev *dp)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    struct e2e_cache_ufid_msg *del_msg;

    VLOG_DBG_RL(&rl, "%s: ufid="UUID_FMT, __FUNCTION__,
                UUID_ARGS((struct uuid *)ufid));

    del_msg = e2e_cache_ufid_msg_alloc(E2E_UFID_MSG_DEL, false, 0);
    if (OVS_UNLIKELY(!del_msg)) {
        return -1;
    }
    del_msg->ufid = *ufid;
    del_msg->dp = dp;

    /* Insert message into queue, e2e_cache_ufid_msg_dequeue()
     * is used to dequeue it from there.
     */
    mpsc_queue_insert(&e2e_cache_thread_msg_queues.ufid_queue,
                      &del_msg->node);
    atomic_count_inc(&e2e_stats.del_flow_msgs);
    return 0;
}

static int
e2e_cache_flow_put(bool is_ct, const ovs_u128 *ufid, const void *match,
                   const struct nlattr *actions, size_t actions_len)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    struct e2e_cache_ufid_msg *put_msg;

    VLOG_DBG_RL(&rl, "%s: ufid="UUID_FMT, __FUNCTION__,
                UUID_ARGS((struct uuid *)ufid));
    put_msg = e2e_cache_ufid_msg_alloc(E2E_UFID_MSG_PUT, is_ct, actions_len);
    if (OVS_UNLIKELY(!put_msg)) {
        return -1;
    }

    put_msg->ufid = *ufid;
    memcpy(put_msg->actions, actions, actions_len);
    if (is_ct) {
        put_msg->ct_match[0] = *((const struct ct_match *) match);
    } else {
        put_msg->match[0] = *((const struct match *) match);
    }

    /* Insert message into queue, e2e_cache_ufid_msg_dequeue()
     * is used to dequeue it from there.
     */
    mpsc_queue_insert(&e2e_cache_thread_msg_queues.ufid_queue,
                      &put_msg->node);
    atomic_count_inc(&e2e_stats.new_flow_msgs);
    return 0;
}

static int
e2e_cache_flow_flush(struct netdev *netdev, struct ovs_barrier *barrier,
                     struct dp_netdev *dp)
{
    struct e2e_cache_ufid_msg *msg;

    msg = xzalloc(sizeof *msg);
    msg->op = E2E_UFID_MSG_FLUSH;
    msg->netdev = netdev;
    msg->barrier = barrier;
    msg->dp = dp;

    /* Insert message into queue, e2e_cache_ufid_msg_dequeue()
     * is used to dequeue it from there.
     */
    mpsc_queue_insert(&e2e_cache_thread_msg_queues.ufid_queue,
                      &msg->node);
    e2e_stats.flush_flow_msgs++;
    return 0;
}

static int
dp_netdev_ct_e2e_add_cb(struct ct_flow_offload_item *offload,
                        struct dp_netdev *dp OVS_UNUSED,
                        struct ct_match *match,
                        struct nlattr *actions, int actions_len)
{
    return e2e_cache_flow_put(true, &offload->ufid, match, actions,
                              actions_len);
}

static struct e2e_cache_ufid_msg *
e2e_cache_ufid_msg_dequeue(void)
{
    struct mpsc_queue *ufid_list = &e2e_cache_thread_msg_queues.ufid_queue;
    enum mpsc_queue_poll_result poll_result;
    struct e2e_cache_ufid_msg *ufid_msg;
    struct mpsc_queue_node *node;

    do {
        poll_result = mpsc_queue_poll(ufid_list, &node);
        if (poll_result == MPSC_QUEUE_EMPTY) {
            return NULL;
        }
    } while (poll_result == MPSC_QUEUE_RETRY);

    ufid_msg = CONTAINER_OF(node, struct e2e_cache_ufid_msg, node);
    return ufid_msg;
}

static void
e2e_cache_dispatch_trace_message(struct dp_netdev *dp,
                                 struct dp_packet_batch *batch)
{
    struct e2e_cache_trace_info *cur_trace_info;
    struct e2e_cache_trace_message *buffer;
    struct dp_packet *packet;
    uint32_t num_elements;
    size_t buffer_size;

    if (dp_netdev_e2e_cache_trace_q_size) {
        uint32_t cur_q_size = atomic_count_get(&e2e_stats.trace_msgs_in_queue);

        if (OVS_UNLIKELY(cur_q_size >= dp_netdev_e2e_cache_trace_q_size)) {
            atomic_count_inc(&e2e_stats.trace_msgs_queue_overflow);
            return;
        }
    }

    buffer_size = sizeof(struct e2e_cache_trace_message) +
                         2 * batch->count * sizeof(struct e2e_cache_trace_info);

    buffer = (struct e2e_cache_trace_message *) xmalloc_cacheline(buffer_size);
    if (OVS_UNLIKELY(!buffer)) {
        return;
    }

    num_elements = 0;
    cur_trace_info = &buffer->data[0];

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        uint32_t e2e_trace_size = packet->e2e_trace_size;
        ovs_u128 *e2e_trace = &packet->e2e_trace[0];

        /* Don't send aborted traces */
        if (OVS_UNLIKELY(packet->e2e_trace_flags &
                         E2E_CACHE_TRACE_FLAG_ABORT)) {
            atomic_count_inc(&e2e_stats.aborted_msgs);
            continue;
        }
        /* In case the packet had tnl_pop, we split the trace to the tnl_pop
         * ufid (the 1st one in the trace), and the rest of the trace,
         * representing the path of the packet with the virtual port. Once the
         * tnl_pop flow is offloaded, we will get only the virtual port path.
         */
        if (packet->e2e_trace_flags & E2E_CACHE_TRACE_FLAG_TNL_POP) {
            cur_trace_info->num_elements = 1;
            cur_trace_info->e2e_trace_ct_ufids = 0;
            packet->e2e_trace_ct_ufids >>= 1;

            memcpy(&cur_trace_info->ufids[0], e2e_trace, sizeof *e2e_trace);

            e2e_trace_size--;
            e2e_trace++;
            num_elements++;
            cur_trace_info++;
            packet->e2e_trace_flags &= ~E2E_CACHE_TRACE_FLAG_TNL_POP;
            if (!packet->e2e_trace_ct_ufids) {
                continue;
            }
        }
        /* If the trace is marked as "throttled" this means that it must be
         * omitted from sending due to high messages rate.
         */
        if (packet->e2e_trace_flags & E2E_CACHE_TRACE_FLAG_THROTTLED) {
            atomic_count_inc(&e2e_stats.throttled_msgs);
            continue;
        }
        /* Don't send "partial" traces due to overflow of the trace storage */
        if (OVS_UNLIKELY(packet->e2e_trace_flags &
                         E2E_CACHE_TRACE_FLAG_OVERFLOW)) {
            atomic_count_inc(&e2e_stats.discarded_msgs);
            continue;
        }
        /* Send only traces for packet that passed conntrack */
        if (!packet->e2e_trace_ct_ufids) {
            atomic_count_inc(&e2e_stats.discarded_msgs);
            continue;
        }

        cur_trace_info->e2e_trace_ct_ufids = packet->e2e_trace_ct_ufids;
        cur_trace_info->num_elements = e2e_trace_size;

        memcpy(&cur_trace_info->ufids[0], e2e_trace,
               e2e_trace_size * sizeof *e2e_trace);

        num_elements++;
        cur_trace_info++;
    }

    if (num_elements == 0) {
        goto out;
    }

    buffer->dp = dp;
    buffer->num_elements = num_elements;

    e2e_cache_trace_msg_enqueue(buffer);
    atomic_count_inc(&e2e_stats.generated_msgs);
    return;

out:
    free_cacheline(buffer);
}

static void
e2e_cache_trace_tnl_pop(struct dp_packet *packet)
{
    packet->e2e_trace_flags |= E2E_CACHE_TRACE_FLAG_TNL_POP;
}

static int
e2e_cache_trace_info_to_flows(const struct e2e_cache_trace_info *trc_info,
                              struct e2e_cache_ovs_flow *flows[])
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    const ovs_u128 *ufid;
    uint32_t hash;
    uint16_t i;

    for (i = 0; i < trc_info->num_elements; i++) {
        ufid = &trc_info->ufids[i];
        hash = hash_bytes(ufid, sizeof *ufid, 0);
        flows[i] = e2e_cache_flow_find(ufid, hash);
        VLOG_DBG_RL(&rl, "%s: ufids[%d]="UUID_FMT" flows[%d]=%p", __func__,
                    i, UUID_ARGS((struct uuid *)ufid), i, flows[i]);
        if (OVS_UNLIKELY(!flows[i])) {
            return -1;
        }
        if (i > 0 && flows[i - 1]->offload_state != E2E_OL_STATE_FLOW &&
            flows[i]->offload_state != E2E_OL_STATE_FLOW) {
            if (!flows[i - 1]->ct_peer) {
                flows[i - 1]->ct_peer = flows[i];
            }
            if (!flows[i]->ct_peer) {
                flows[i]->ct_peer = flows[i - 1];
            }
        }
    }
    return 0;
}

static void
e2e_cache_offload_ct_mt_flows(struct dp_netdev *dp,
                              struct e2e_cache_ovs_flow *mt_flows[],
                              uint16_t num_flows)
{
    uint16_t i;

    for (i = 0; i < num_flows; i++) {
        e2e_cache_ct_flow_offload_add_mt(dp, mt_flows[i]);
    }
}

static int
e2e_cache_merge_flows(struct e2e_cache_ovs_flow **flows,
                      uint16_t num_flows,
                      struct e2e_cache_merged_flow *merged_flow,
                      struct ofpbuf *merged_actions);

/* CT rules should be offloaded either to MT or cache, but not both. For a
 * merged flow created, remove from HW the MT rules for its composing CT
 * flows.
 */
static void
e2e_cache_purge_ct_flows_from_mt(struct dp_netdev *dp,
                                 struct e2e_cache_ovs_flow *mt_flows[],
                                 uint16_t num_flows)
{
    uint16_t i;

    for (i = 0; i < num_flows; i++) {
        /* Before offloading a ct_flow in e2e, its MT HW rule should be
         * removed. If MT rule was inserted locally (LOCAL), removal is
         * done per-direction -- the peer will be kept in the same state.
         * In this case, the peer must be skipped.
         * In each set of mt_flows passed as a trace, for each pair of
         * CT flows only the first one will be unoffloaded, the second
         * one will be skipped (multiple CT pairs can be part of the same
         * trace).
         *
         * If the MT rule was inserted by MT threads, asynchronously, then
         * both directions have been inserted at once (ct_flow and peer).
         * In this case the peer HW rule will be removed as well. The second
         * CT flow is skipped but it will be unoffloaded in the same async
         * call as the first CT flow.
         */
        if ((mt_flows[i]->offload_state != E2E_OL_STATE_CT_MT_ASYNC &&
             mt_flows[i]->offload_state != E2E_OL_STATE_CT_MT_LOCAL) ||
            (i > 0 && mt_flows[i - 1]->offload_state != E2E_OL_STATE_FLOW)) {
            continue;
        }
        e2e_cache_ct_flow_offload_del_mt(dp, mt_flows[i]);
    }
}

static int
e2e_cache_process_trace_info(struct dp_netdev *dp,
                             const struct e2e_cache_trace_info *trc_info)
{
    struct e2e_cache_merged_flow *merged_flow;
    struct nlattr *actions;
    size_t actions_len;
    struct ofpbuf merged_actions;
    struct e2e_cache_ovs_flow *mt_flows[E2E_CACHE_MAX_TRACE];
    uint64_t merged_actions_buf[1024 / sizeof(uint64_t)];
    uint16_t i, num_flows;
    int err;

    err = e2e_cache_trace_info_to_flows(trc_info, mt_flows);
    if (OVS_UNLIKELY(err)) {
        return -1;
    }
    num_flows = trc_info->num_elements;
    if (e2e_stats.merged_flows_in_cache >= dp_netdev_e2e_cache_size) {
        e2e_cache_offload_ct_mt_flows(dp, mt_flows, num_flows);
        return -1;
    }

    merged_flow = xzalloc(sizeof *merged_flow +
                          num_flows * sizeof merged_flow->associated_flows[0]);
    if (OVS_UNLIKELY(!merged_flow)) {
        return -1;
    }
    ovs_list_init(&merged_flow->flow_counter_list);
    ovs_list_init(&merged_flow->ct_counter_list);
    for (i = 0; i < num_flows; i++) {
        ovs_list_init(&merged_flow->associated_flows[i].list);
    }

    ofpbuf_use_stack(&merged_actions, &merged_actions_buf,
                     sizeof merged_actions_buf);

    err = e2e_cache_merge_flows(mt_flows, num_flows, merged_flow,
                                &merged_actions);
    if (OVS_UNLIKELY(err)) {
        e2e_cache_offload_ct_mt_flows(dp, mt_flows, num_flows);
        goto free_merged_flow;
    }

    actions = (struct nlattr *) ofpbuf_at_assert(&merged_actions, 0,
                                                 sizeof(struct nlattr));
    actions_len = merged_actions.size;
    merged_flow->actions = (struct nlattr *) xmalloc(actions_len);
    if (OVS_UNLIKELY(!merged_flow->actions)) {
        goto free_merged_flow;
    }
    memcpy(merged_flow->actions, actions, actions_len);
    merged_flow->actions_size = actions_len;

    e2e_cache_associate_merged_flow(merged_flow, mt_flows, num_flows);

    err = e2e_cache_merged_flow_db_put(merged_flow);
    if (OVS_UNLIKELY(err)) {
        goto disassociate_merged_flow;
    }

    err = e2e_cache_merged_flow_offload_put(dp, merged_flow, mt_flows,
                                            trc_info);
    if (OVS_UNLIKELY(err)) {
        goto remove_flow_from_db;
    }
    e2e_cache_purge_ct_flows_from_mt(dp, mt_flows, num_flows);
    for (i = 0; i < num_flows; i++) {
        if (mt_flows[i]->offload_state == E2E_OL_STATE_FLOW ||
            (i > 0 && mt_flows[i - 1]->offload_state != E2E_OL_STATE_FLOW)) {
            continue;
        }
        /* Update CT stats affected by offloading the merged flow. */
        e2e_cache_flow_state_set(mt_flows[i], E2E_OL_STATE_CT_HW);
    }
    return 0;

remove_flow_from_db:
    e2e_cache_merged_flow_db_del(merged_flow);
    return err;
disassociate_merged_flow:
    /* Lock/unlock to prevent race condition with
     * e2e_cache_get_merged_flows_stats()
     */
    ovs_mutex_lock(&flows_map_mutex);
    e2e_cache_disassociate_merged_flow(merged_flow);
    ovs_mutex_unlock(&flows_map_mutex);
free_merged_flow:
    e2e_cache_merged_flow_free(merged_flow);
    return err;
}

static bool
e2e_cache_get_merged_flows_stats(struct netdev *netdev,
                                 struct match *match,
                                 struct nlattr **actions,
                                 const ovs_u128 *mt_ufid,
                                 struct dpif_flow_stats *stats,
                                 struct ofpbuf *buf,
                                 long long now,
                                 long long prev_now)
{
    struct e2e_cache_counter_item *mt_counter_item, *mapped_counter_item;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);
    struct e2e_cache_merged_flow *merged_flow;
    struct dpif_flow_stats merged_stats;
    struct dpif_flow_attrs merged_attr;
    struct ovs_list *merged_flow_node;
    struct e2e_cache_ovs_flow *flow;
    bool rv = false;
    uint32_t hash;
    int ret;

    hash = hash_bytes(mt_ufid, sizeof *mt_ufid, 0);

    ovs_mutex_lock(&flows_map_mutex);
    flow = e2e_cache_flow_find(mt_ufid, hash);
    if (OVS_UNLIKELY(!flow) ||
        ovs_list_is_empty(&flow->associated_merged_flows)) {
        ovs_mutex_unlock(&flows_map_mutex);
        return false;
    }
    HMAP_FOR_EACH (mt_counter_item, node, &flow->merged_counters) {
        if (flow->offload_state == E2E_OL_STATE_FLOW) {
            /* Get the counter item from the global map. */
            mapped_counter_item =
                e2e_cache_counter_find(mt_counter_item->hash,
                                       &mt_counter_item->key);
            if (OVS_UNLIKELY(!mapped_counter_item)) {
                VLOG_ERR_RL(&rl, "Failed to get counter item for ufid "
                            UUID_FMT, UUID_ARGS((struct uuid *) &flow->ufid));
                continue;
            }

            /* Get one of the merged flows using this counter. */
            merged_flow_node =
                ovs_list_front(&mapped_counter_item->merged_flows);
            merged_flow = CONTAINER_OF(merged_flow_node,
                                       struct e2e_cache_merged_flow,
                                       flow_counter_list);
            /* Query the counter. */
            ret = netdev_flow_get(netdev, match, actions, &merged_flow->ufid,
                                  &merged_stats, &merged_attr, buf);
            if (ret) {
                VLOG_ERR_RL(&rl, "Failed to get merged flow ufid "UUID_FMT,
                            UUID_ARGS((struct uuid *) &merged_flow->ufid));
                continue;
            }
            stats->n_bytes += merged_stats.n_bytes;
            stats->n_packets += merged_stats.n_packets;
            stats->used = MAX(stats->used, merged_stats.used);
            rv = true;
        } else {
            ret = netdev_ct_counter_query(netdev, mt_counter_item->key.ptr_key,
                                          now, prev_now, stats);
            if (ret) {
                VLOG_ERR_RL(&rl, "Failed to query ct counter netdev=%s, "
                            "ptr_key=%"PRIxPTR, netdev_get_name(netdev),
                            mt_counter_item->key.ptr_key);
                continue;
            }
            rv |= stats->used == now;
        }
    }
    ovs_mutex_unlock(&flows_map_mutex);
    return rv;
}

#define E2E_CACHE_QUIESCE_INTERVAL_MS 10

static void *
dp_netdev_e2e_cache_main(void *arg OVS_UNUSED)
{
    struct e2e_cache_trace_message *trace_msg;
    struct e2e_cache_ufid_msg *ufid_msg;
    uint32_t i, num_elements;
    long long int next_rcu;

    if (!mpsc_queue_acquire(&e2e_cache_thread_msg_queues.ufid_queue)) {
        VLOG_ERR("failed to register as consumer of the ufid queue");
        return NULL;
    }

    if (!mpsc_queue_acquire(&e2e_cache_thread_msg_queues.trace_queue)) {
        VLOG_ERR("failed to register as consumer of the trace queue");
        return NULL;
    }

    next_rcu = time_msec() + E2E_CACHE_QUIESCE_INTERVAL_MS;
    for (;;) {
        e2e_cache_poll_queues(&ufid_msg, &trace_msg);

        while (ufid_msg != NULL) {
            if (ufid_msg->op == E2E_UFID_MSG_PUT) {
                e2e_cache_flow_db_put(ufid_msg);
            } else if (ufid_msg->op == E2E_UFID_MSG_DEL) {
                e2e_cache_flow_db_del(&ufid_msg->ufid, ufid_msg->dp);
            } else if (ufid_msg->op == E2E_UFID_MSG_FLUSH) {
                e2e_cache_flow_db_flush(ufid_msg->netdev,
                                        ufid_msg->barrier,
                                        ufid_msg->dp);
            } else {
                OVS_NOT_REACHED();
            }
            e2e_cache_ufid_msg_free(ufid_msg);
            ufid_msg = e2e_cache_ufid_msg_dequeue();
        }

        if (!trace_msg) {
            continue;
        }

        e2e_stats.processed_msgs++;
        num_elements = trace_msg->num_elements;
        for (i = 0; i < num_elements; i++) {
            e2e_cache_process_trace_info((struct dp_netdev *)trace_msg->dp,
                                         &trace_msg->data[i]);
        }

        free_cacheline(trace_msg);

        if (time_msec() > next_rcu) {
            if (!ovsrcu_try_quiesce()) {
                next_rcu += E2E_CACHE_QUIESCE_INTERVAL_MS;
            }
        }
    }

    return NULL;
}
#else
#define e2e_cache_trace_init(p) do { } while (0)
#define e2e_cache_trace_add_flow(p, ufid) do { } while (0)
#define e2e_cache_trace_msg_enqueue(m) do { } while (0)
#define e2e_cache_poll_queues() do { } while (0)
#define e2e_cache_dispatch_trace_message(d, b) do { } while (0)
#define e2e_cache_trace_tnl_pop(p) do { } while (0)
OVS_UNUSED
static int
e2e_cache_flow_put(bool is_ct OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   const void *match OVS_UNUSED,
                   const struct nlattr *actions OVS_UNUSED,
                   size_t actions_len OVS_UNUSED)
{
    return 0;
}
static int
e2e_cache_flow_del(const ovs_u128 *ufid OVS_UNUSED,
                   struct dp_netdev *dp OVS_UNUSED)
{
    return 0;
}
static int
e2e_cache_flow_flush(struct netdev *netdev OVS_UNUSED,
                     struct ovs_barrier *barrier OVS_UNUSED,
                     struct dp_netdev *dp OVS_UNUSED)
{
    return 0;
}
static bool
e2e_cache_get_merged_flows_stats(struct netdev *netdev OVS_UNUSED,
                                 struct match *match OVS_UNUSED,
                                 struct nlattr **actions OVS_UNUSED,
                                 const ovs_u128 *mt_ufid OVS_UNUSED,
                                 struct dpif_flow_stats *stats OVS_UNUSED,
                                 struct ofpbuf *buf OVS_UNUSED,
                                 long long now OVS_UNUSED,
                                 long long prev_now OVS_UNUSED)
{
}
static void
dpif_netdev_dump_e2e_stats(struct ds *s OVS_UNUSED)
{
}
static void
dpif_netdev_dump_e2e_flows(struct hmap *portno_names OVS_UNUSED,
                           struct ofputil_port_map *port_map OVS_UNUSED,
                           struct ds *s OVS_UNUSED)
{
}
#endif /* E2E_CACHE_ENABLED */

/* SMC lookup function for a batch of packets.
 * By doing batching SMC lookup, we can use prefetch
 * to hide memory access latency.
 */
static inline void
smc_lookup_batch(struct dp_netdev_pmd_thread *pmd,
            struct netdev_flow_key *keys,
            struct netdev_flow_key **missed_keys,
            struct dp_packet_batch *packets_,
            const int cnt,
            struct dp_packet_flow_map *flow_map,
            uint8_t *index_map)
{
    int i;
    struct dp_packet *packet;
    size_t n_smc_hit = 0, n_missed = 0;
    struct dfc_cache *cache = &pmd->flow_cache;
    struct smc_cache *smc_cache = &cache->smc_cache;
    const struct cmap_node *flow_node;
    int recv_idx;
    uint16_t tcp_flags;

    /* Prefetch buckets for all packets */
    for (i = 0; i < cnt; i++) {
        OVS_PREFETCH(&smc_cache->buckets[keys[i].hash & SMC_MASK]);
    }

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow = NULL;
        flow_node = smc_entry_get(pmd, keys[i].hash);
        bool hit = false;
        /* Get the original order of this packet in received batch. */
        recv_idx = index_map[i];

        if (OVS_LIKELY(flow_node != NULL)) {
            CMAP_NODE_FOR_EACH (flow, node, flow_node) {
                /* Since we dont have per-port megaflow to check the port
                 * number, we need to  verify that the input ports match. */
                if (OVS_LIKELY(dpcls_rule_matches_key(&flow->cr, &keys[i]) &&
                flow->flow.in_port.odp_port == packet->md.in_port.odp_port)) {
                    tcp_flags = miniflow_get_tcp_flags(&keys[i].mf);

                    /* SMC hit and emc miss, we insert into EMC */
                    keys[i].len =
                        netdev_flow_key_size(miniflow_n_values(&keys[i].mf));
                    emc_probabilistic_insert(pmd, &keys[i], flow);
                    /* Add these packets into the flow map in the same order
                     * as received.
                     */
                    packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                               flow_map, recv_idx);
                    n_smc_hit++;
                    hit = true;

                    if (dp_netdev_e2e_cache_enabled) {
                        e2e_cache_trace_add_flow(packet, &flow->mega_ufid);
                    }
                    break;
                }
            }
            if (hit) {
                continue;
            }
        }

        /* SMC missed. Group missed packets together at
         * the beginning of the 'packets' array. */
        dp_packet_batch_refill(packets_, packet, i);

        /* Preserve the order of packet for flow batching. */
        index_map[n_missed] = recv_idx;

        /* Put missed keys to the pointer arrays return to the caller */
        missed_keys[n_missed++] = &keys[i];
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_SMC_HIT, n_smc_hit);
}

static struct tx_port *
pmd_send_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                           odp_port_t port_no);

/* Try to process all ('cnt') the 'packets' using only the datapath flow cache
 * 'pmd->flow_cache'. If a flow is not found for a packet 'packets[i]', the
 * miniflow is copied into 'keys' and the packet pointer is moved at the
 * beginning of the 'packets' array. The pointers of missed keys are put in the
 * missed_keys pointer array for future processing.
 *
 * The function returns the number of packets that needs to be processed in the
 * 'packets' array (they have been moved to the beginning of the vector).
 *
 * For performance reasons a caller may choose not to initialize the metadata
 * in 'packets_'.  If 'md_is_valid' is false, the metadata in 'packets'
 * is not valid and must be initialized by this function using 'port_no'.
 * If 'md_is_valid' is true, the metadata is already valid and 'port_no'
 * will be ignored.
 */
static inline size_t
dfc_processing(struct dp_netdev_pmd_thread *pmd,
               struct dp_packet_batch *packets_,
               struct netdev_flow_key *keys,
               struct netdev_flow_key **missed_keys,
               struct packet_batch_per_flow batches[], size_t *n_batches,
               struct dp_packet_flow_map *flow_map,
               size_t *n_flows, uint8_t *index_map,
               bool md_is_valid, odp_port_t port_no)
{
    struct netdev_flow_key *key = &keys[0];
    size_t n_missed = 0, n_emc_hit = 0;
    struct dfc_cache *cache = &pmd->flow_cache;
    struct dp_packet *packet;
    const size_t cnt = dp_packet_batch_size(packets_);
    uint32_t cur_min = pmd->ctx.emc_insert_min;
    int i;
    uint16_t tcp_flags;
    bool smc_enable_db;
    size_t map_cnt = 0;
    bool batch_enable = true;

    atomic_read_relaxed(&pmd->dp->smc_enable_db, &smc_enable_db);
    pmd_perf_update_counter(&pmd->perf_stats,
                            md_is_valid ? PMD_STAT_RECIRC : PMD_STAT_RECV,
                            cnt);

    DP_PACKET_BATCH_REFILL_FOR_EACH (i, cnt, packet, packets_) {
        struct dp_netdev_flow *flow;
        uint32_t mark;

        if (OVS_UNLIKELY(dp_packet_size(packet) < ETH_HEADER_LEN)) {
            dp_packet_delete(packet);
            COVERAGE_INC(datapath_drop_rx_invalid_packet);
            continue;
        }

        if (i != cnt - 1) {
            struct dp_packet **packets = packets_->packets;
            /* Prefetch next packet data and metadata. */
            OVS_PREFETCH(dp_packet_data(packets[i+1]));
            pkt_metadata_prefetch_init(&packets[i+1]->md);
        }

        if (!md_is_valid) {
            pkt_metadata_init(&packet->md, port_no);
            if (dp_netdev_e2e_cache_enabled) {
                e2e_cache_trace_init(packet);
            }
        }

        if ((*recirc_depth_get() == 0) &&
            dp_packet_has_flow_mark(packet, &mark)) {
            /* Restore the packet if it was interrupted in the middle
             * of HW offload processing.
             */
            struct tx_port *p;

            tcp_flags = parse_tcp_flags(packet);
            p = pmd_send_port_cache_lookup(pmd, port_no);
            if (p) {
                netdev_hw_miss_packet_recover(p->port->netdev, mark, packet);
            }
            flow = mark_to_flow_find(pmd, mark);
            if (OVS_LIKELY(flow)) {
                if (OVS_LIKELY(batch_enable)) {
                    dp_netdev_queue_batches(packet, flow, tcp_flags, batches,
                                            n_batches);
                } else {
                    /* Flow batching should be performed only after fast-path
                     * processing is also completed for packets with emc miss
                     * or else it will result in reordering of packets with
                     * same datapath flows. */
                    packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                               flow_map, map_cnt++);
                }
                if (dp_netdev_e2e_cache_enabled) {
                    e2e_cache_trace_add_flow(packet, &flow->mega_ufid);
                }
                continue;
            }
        }

        miniflow_extract(packet, &key->mf);
        key->len = 0; /* Not computed yet. */
        key->hash =
                (md_is_valid == false)
                ? dpif_netdev_packet_get_rss_hash_orig_pkt(packet, &key->mf)
                : dpif_netdev_packet_get_rss_hash(packet, &key->mf);

        /* If EMC is disabled skip emc_lookup */
        flow = (cur_min != 0) ? emc_lookup(&cache->emc_cache, key) : NULL;
        if (OVS_LIKELY(flow)) {
            tcp_flags = miniflow_get_tcp_flags(&key->mf);
            n_emc_hit++;
            if (OVS_LIKELY(batch_enable)) {
                dp_netdev_queue_batches(packet, flow, tcp_flags, batches,
                                        n_batches);
            } else {
                /* Flow batching should be performed only after fast-path
                 * processing is also completed for packets with emc miss
                 * or else it will result in reordering of packets with
                 * same datapath flows. */
                packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                           flow_map, map_cnt++);
            }
            if (dp_netdev_e2e_cache_enabled) {
                e2e_cache_trace_add_flow(packet, &flow->mega_ufid);
            }
        } else {
            /* Exact match cache missed. Group missed packets together at
             * the beginning of the 'packets' array. */
            dp_packet_batch_refill(packets_, packet, i);

            /* Preserve the order of packet for flow batching. */
            index_map[n_missed] = map_cnt;
            flow_map[map_cnt++].flow = NULL;

            /* 'key[n_missed]' contains the key of the current packet and it
             * will be passed to SMC lookup. The next key should be extracted
             * to 'keys[n_missed + 1]'.
             * We also maintain a pointer array to keys missed both SMC and EMC
             * which will be returned to the caller for future processing. */
            missed_keys[n_missed] = key;
            key = &keys[++n_missed];

            /* Skip batching for subsequent packets to avoid reordering. */
            batch_enable = false;
        }
    }
    /* Count of packets which are not flow batched. */
    *n_flows = map_cnt;

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_EXACT_HIT, n_emc_hit);

    if (!smc_enable_db) {
        return dp_packet_batch_size(packets_);
    }

    /* Packets miss EMC will do a batch lookup in SMC if enabled */
    smc_lookup_batch(pmd, keys, missed_keys, packets_,
                     n_missed, flow_map, index_map);

    return dp_packet_batch_size(packets_);
}

static inline int
handle_packet_upcall(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet *packet,
                     const struct netdev_flow_key *key,
                     struct ofpbuf *actions, struct ofpbuf *put_actions)
{
    struct ofpbuf *add_actions;
    struct dp_packet_batch b;
    struct match match;
    ovs_u128 ufid;
    int error;
    uint64_t cycles = cycles_counter_update(&pmd->perf_stats);

    match.tun_md.valid = false;
    miniflow_expand(&key->mf, &match.flow);
    memset(&match.wc, 0, sizeof match.wc);

    ofpbuf_clear(actions);
    ofpbuf_clear(put_actions);

    odp_flow_key_hash(&match.flow, sizeof match.flow, &ufid);
    error = dp_netdev_upcall(pmd, packet, &match.flow, &match.wc,
                             &ufid, DPIF_UC_MISS, NULL, actions,
                             put_actions);
    if (OVS_UNLIKELY(error && error != ENOSPC)) {
        dp_packet_delete(packet);
        COVERAGE_INC(datapath_drop_upcall_error);
        return error;
    }

    /* The Netlink encoding of datapath flow keys cannot express
     * wildcarding the presence of a VLAN tag. Instead, a missing VLAN
     * tag is interpreted as exact match on the fact that there is no
     * VLAN.  Unless we refactor a lot of code that translates between
     * Netlink and struct flow representations, we have to do the same
     * here.  This must be in sync with 'match' in dpif_netdev_flow_put(). */
    if (!match.wc.masks.vlans[0].tci) {
        match.wc.masks.vlans[0].tci = htons(0xffff);
    }

    add_actions = put_actions->size ? put_actions : actions;
    if (OVS_LIKELY(error != ENOSPC)) {
        struct dp_netdev_flow *netdev_flow;

        /* XXX: There's a race window where a flow covering this packet
         * could have already been installed since we last did the flow
         * lookup before upcall.  This could be solved by moving the
         * mutex lock outside the loop, but that's an awful long time
         * to be locking revalidators out of making flow modifications. */
        ovs_mutex_lock(&pmd->flow_mutex);
        netdev_flow = dp_netdev_pmd_lookup_flow(pmd, key, NULL);
        if (OVS_LIKELY(!netdev_flow)) {
            netdev_flow = dp_netdev_flow_add(pmd, &match, &ufid,
                                             add_actions->data,
                                             add_actions->size);
        }
        ovs_mutex_unlock(&pmd->flow_mutex);
        uint32_t hash = dp_netdev_flow_hash(&netdev_flow->ufid);
        smc_insert(pmd, key, hash);
        emc_probabilistic_insert(pmd, key, netdev_flow);
        if (dp_netdev_e2e_cache_enabled) {
            e2e_cache_trace_add_flow(packet, &netdev_flow->mega_ufid);
        }
    }

    /* We can't allow the packet batching in the next loop to execute
     * the actions.  Otherwise, if there are any slow path actions,
     * we'll send the packet up twice. */
    dp_packet_batch_init_packet(&b, packet);
    dp_netdev_execute_actions(pmd, &b, true, &match.flow,
                              actions->data, actions->size);

    if (pmd_perf_metrics_enabled(pmd)) {
        /* Update upcall stats. */
        cycles = cycles_counter_update(&pmd->perf_stats) - cycles;
        struct pmd_perf_stats *s = &pmd->perf_stats;
        s->current.upcalls++;
        s->current.upcall_cycles += cycles;
        histogram_add_sample(&s->cycles_per_upcall, cycles);
    }
    return error;
}

static inline void
fast_path_processing(struct dp_netdev_pmd_thread *pmd,
                     struct dp_packet_batch *packets_,
                     struct netdev_flow_key **keys,
                     struct dp_packet_flow_map *flow_map,
                     uint8_t *index_map,
                     odp_port_t in_port)
{
    const size_t cnt = dp_packet_batch_size(packets_);
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = cnt;
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct dp_packet *packet;
    struct dpcls *cls;
    struct dpcls_rule *rules[PKT_ARRAY_SIZE];
    struct dp_netdev *dp = pmd->dp;
    int upcall_ok_cnt = 0, upcall_fail_cnt = 0;
    int lookup_cnt = 0, add_lookup_cnt;
    bool any_miss;

    for (size_t i = 0; i < cnt; i++) {
        /* Key length is needed in all the cases, hash computed on demand. */
        keys[i]->len = netdev_flow_key_size(miniflow_n_values(&keys[i]->mf));
    }
    /* Get the classifier for the in_port */
    cls = dp_netdev_pmd_lookup_dpcls(pmd, in_port);
    if (OVS_LIKELY(cls)) {
        any_miss = !dpcls_lookup(cls, (const struct netdev_flow_key **)keys,
                                rules, cnt, &lookup_cnt);
    } else {
        any_miss = true;
        memset(rules, 0, sizeof(rules));
    }
    if (OVS_UNLIKELY(any_miss) && !fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
        uint64_t actions_stub[512 / 8], slow_stub[512 / 8];
        struct ofpbuf actions, put_actions;

        ofpbuf_use_stub(&actions, actions_stub, sizeof actions_stub);
        ofpbuf_use_stub(&put_actions, slow_stub, sizeof slow_stub);

        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            struct dp_netdev_flow *netdev_flow;

            if (OVS_LIKELY(rules[i])) {
                continue;
            }

            /* It's possible that an earlier slow path execution installed
             * a rule covering this flow.  In this case, it's a lot cheaper
             * to catch it here than execute a miss. */
            netdev_flow = dp_netdev_pmd_lookup_flow(pmd, keys[i],
                                                    &add_lookup_cnt);
            if (netdev_flow) {
                lookup_cnt += add_lookup_cnt;
                rules[i] = &netdev_flow->cr;
                continue;
            }

            int error = handle_packet_upcall(pmd, packet, keys[i],
                                             &actions, &put_actions);

            if (OVS_UNLIKELY(error)) {
                upcall_fail_cnt++;
            } else {
                upcall_ok_cnt++;
            }
        }

        ofpbuf_uninit(&actions);
        ofpbuf_uninit(&put_actions);
        fat_rwlock_unlock(&dp->upcall_rwlock);
    } else if (OVS_UNLIKELY(any_miss)) {
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
            if (OVS_UNLIKELY(!rules[i])) {
                dp_packet_delete(packet);
                COVERAGE_INC(datapath_drop_lock_error);
                upcall_fail_cnt++;
            }
        }
    }

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        struct dp_netdev_flow *flow;
        /* Get the original order of this packet in received batch. */
        int recv_idx = index_map[i];
        uint16_t tcp_flags;

        if (OVS_UNLIKELY(!rules[i])) {
            continue;
        }

        flow = dp_netdev_flow_cast(rules[i]);
        uint32_t hash =  dp_netdev_flow_hash(&flow->ufid);
        smc_insert(pmd, keys[i], hash);

        emc_probabilistic_insert(pmd, keys[i], flow);

        if (dp_netdev_e2e_cache_enabled) {
            e2e_cache_trace_add_flow(packet, &flow->mega_ufid);
        }

        /* Add these packets into the flow map in the same order
         * as received.
         */
        tcp_flags = miniflow_get_tcp_flags(&keys[i]->mf);
        packet_enqueue_to_flow_map(packet, flow, tcp_flags,
                                   flow_map, recv_idx);
    }

    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_HIT,
                            cnt - upcall_ok_cnt - upcall_fail_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MASKED_LOOKUP,
                            lookup_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_MISS,
                            upcall_ok_cnt);
    pmd_perf_update_counter(&pmd->perf_stats, PMD_STAT_LOST,
                            upcall_fail_cnt);
}

/* Packets enter the datapath from a port (or from recirculation) here.
 *
 * When 'md_is_valid' is true the metadata in 'packets' are already valid.
 * When false the metadata in 'packets' need to be initialized. */
static void
dp_netdev_input__(struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet_batch *packets,
                  bool md_is_valid, odp_port_t port_no)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t PKT_ARRAY_SIZE = dp_packet_batch_size(packets);
#else
    /* Sparse or MSVC doesn't like variable length array. */
    enum { PKT_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)
        struct netdev_flow_key keys[PKT_ARRAY_SIZE];
    struct netdev_flow_key *missed_keys[PKT_ARRAY_SIZE];
    struct packet_batch_per_flow batches[PKT_ARRAY_SIZE];
    size_t n_batches;
    struct dp_packet_flow_map flow_map[PKT_ARRAY_SIZE];
    uint8_t index_map[PKT_ARRAY_SIZE];
    size_t n_flows, i;

    odp_port_t in_port;

    n_batches = 0;
    dfc_processing(pmd, packets, keys, missed_keys, batches, &n_batches,
                   flow_map, &n_flows, index_map, md_is_valid, port_no);

    if (!dp_packet_batch_is_empty(packets)) {
        /* Get ingress port from first packet's metadata. */
        in_port = packets->packets[0]->md.in_port.odp_port;
        fast_path_processing(pmd, packets, missed_keys,
                             flow_map, index_map, in_port);
    }

    /* Batch rest of packets which are in flow map. */
    for (i = 0; i < n_flows; i++) {
        struct dp_packet_flow_map *map = &flow_map[i];

        if (OVS_UNLIKELY(!map->flow)) {
            continue;
        }
        dp_netdev_queue_batches(map->packet, map->flow, map->tcp_flags,
                                batches, &n_batches);
     }

    /* All the flow batches need to be reset before any call to
     * packet_batch_per_flow_execute() as it could potentially trigger
     * recirculation. When a packet matching flow ‘j’ happens to be
     * recirculated, the nested call to dp_netdev_input__() could potentially
     * classify the packet as matching another flow - say 'k'. It could happen
     * that in the previous call to dp_netdev_input__() that same flow 'k' had
     * already its own batches[k] still waiting to be served.  So if its
     * ‘batch’ member is not reset, the recirculated packet would be wrongly
     * appended to batches[k] of the 1st call to dp_netdev_input__(). */
    for (i = 0; i < n_batches; i++) {
        batches[i].flow->batch = NULL;
    }

    for (i = 0; i < n_batches; i++) {
        packet_batch_per_flow_execute(&batches[i], pmd);
    }
}

static void
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet_batch *packets,
                odp_port_t port_no)
{
    dp_netdev_input__(pmd, packets, false, port_no);
}

static void
dp_netdev_recirculate(struct dp_netdev_pmd_thread *pmd,
                      struct dp_packet_batch *packets)
{
    dp_netdev_input__(pmd, packets, true, 0);
}

struct dp_netdev_execute_aux {
    struct dp_netdev_pmd_thread *pmd;
    const struct flow *flow;
};

static void
dpif_netdev_register_dp_purge_cb(struct dpif *dpif, dp_purge_callback *cb,
                                 void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->dp_purge_aux = aux;
    dp->dp_purge_cb = cb;
}

static void
dpif_netdev_register_upcall_cb(struct dpif *dpif, upcall_callback *cb,
                               void *aux)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    dp->upcall_aux = aux;
    dp->upcall_cb = cb;
}

static void
dpif_netdev_xps_revalidate_pmd(const struct dp_netdev_pmd_thread *pmd,
                               bool purge)
{
    struct tx_port *tx;
    struct dp_netdev_port *port;
    long long interval;

    HMAP_FOR_EACH (tx, node, &pmd->send_port_cache) {
        if (!tx->port->dynamic_txqs) {
            continue;
        }
        interval = pmd->ctx.now - tx->last_used;
        if (tx->qid >= 0 && (purge || interval >= XPS_TIMEOUT)) {
            port = tx->port;
            ovs_mutex_lock(&port->txq_used_mutex);
            port->txq_used[tx->qid]--;
            ovs_mutex_unlock(&port->txq_used_mutex);
            tx->qid = -1;
        }
    }
}

static int
dpif_netdev_xps_get_tx_qid(const struct dp_netdev_pmd_thread *pmd,
                           struct tx_port *tx)
{
    struct dp_netdev_port *port;
    long long interval;
    int i, min_cnt, min_qid;

    interval = pmd->ctx.now - tx->last_used;
    tx->last_used = pmd->ctx.now;

    if (OVS_LIKELY(tx->qid >= 0 && interval < XPS_TIMEOUT)) {
        return tx->qid;
    }

    port = tx->port;

    ovs_mutex_lock(&port->txq_used_mutex);
    if (tx->qid >= 0) {
        port->txq_used[tx->qid]--;
        tx->qid = -1;
    }

    min_cnt = -1;
    min_qid = 0;
    for (i = 0; i < netdev_n_txq(port->netdev); i++) {
        if (port->txq_used[i] < min_cnt || min_cnt == -1) {
            min_cnt = port->txq_used[i];
            min_qid = i;
        }
    }

    port->txq_used[min_qid]++;
    tx->qid = min_qid;

    ovs_mutex_unlock(&port->txq_used_mutex);

    dpif_netdev_xps_revalidate_pmd(pmd, false);

    VLOG_DBG("Core %d: New TX queue ID %d for port \'%s\'.",
             pmd->core_id, tx->qid, netdev_get_name(tx->port->netdev));
    return min_qid;
}

static struct tx_port *
pmd_tnl_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                          odp_port_t port_no)
{
    return tx_port_lookup(&pmd->tnl_port_cache, port_no);
}

static struct tx_port *
pmd_send_port_cache_lookup(const struct dp_netdev_pmd_thread *pmd,
                           odp_port_t port_no)
{
    return tx_port_lookup(&pmd->send_port_cache, port_no);
}

static int
push_tnl_action(const struct dp_netdev_pmd_thread *pmd,
                const struct nlattr *attr,
                struct dp_packet_batch *batch)
{
    struct tx_port *tun_port;
    const struct ovs_action_push_tnl *data;
    int err;

    data = nl_attr_get(attr);

    tun_port = pmd_tnl_port_cache_lookup(pmd, data->tnl_port);
    if (!tun_port) {
        err = -EINVAL;
        goto error;
    }
    err = netdev_push_header(tun_port->port->netdev, batch, data);
    if (!err) {
        return 0;
    }
error:
    dp_packet_delete_batch(batch, true);
    return err;
}

static void
dp_execute_userspace_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet *packet, bool should_steal,
                            struct flow *flow, ovs_u128 *ufid,
                            struct ofpbuf *actions,
                            const struct nlattr *userdata)
{
    struct dp_packet_batch b;
    int error;

    ofpbuf_clear(actions);

    error = dp_netdev_upcall(pmd, packet, flow, NULL, ufid,
                             DPIF_UC_ACTION, userdata, actions,
                             NULL);
    if (!error || error == ENOSPC) {
        dp_packet_batch_init_packet(&b, packet);
        dp_netdev_execute_actions(pmd, &b, should_steal, flow,
                                  actions->data, actions->size);
    } else if (should_steal) {
        dp_packet_delete(packet);
        COVERAGE_INC(datapath_drop_userspace_action_error);
    }
}

static bool
dp_execute_output_action(struct dp_netdev_pmd_thread *pmd,
                         struct dp_packet_batch *packets_,
                         bool should_steal, odp_port_t port_no)
{
    struct tx_port *p = pmd_send_port_cache_lookup(pmd, port_no);
    struct dp_packet_batch out;

    if (dp_netdev_e2e_cache_enabled) {
        e2e_cache_dispatch_trace_message(pmd->dp, packets_);
    }

    if (!OVS_LIKELY(p)) {
        COVERAGE_ADD(datapath_drop_invalid_port,
                     dp_packet_batch_size(packets_));
        dp_packet_delete_batch(packets_, should_steal);
        return false;
    }
    if (!should_steal) {
        dp_packet_batch_clone(&out, packets_);
        dp_packet_batch_reset_cutlen(packets_);
        packets_ = &out;
    }
    dp_packet_batch_apply_cutlen(packets_);
#ifdef DPDK_NETDEV
    if (OVS_UNLIKELY(!dp_packet_batch_is_empty(&p->output_pkts)
                     && packets_->packets[0]->source
                        != p->output_pkts.packets[0]->source)) {
        /* XXX: netdev-dpdk assumes that all packets in a single
         *      output batch has the same source. Flush here to
         *      avoid memory access issues. */
        dp_netdev_pmd_flush_output_on_port(pmd, p);
    }
#endif
    if (dp_packet_batch_size(&p->output_pkts)
        + dp_packet_batch_size(packets_) > NETDEV_MAX_BURST) {
        /* Flush here to avoid overflow. */
        dp_netdev_pmd_flush_output_on_port(pmd, p);
    }
    if (dp_packet_batch_is_empty(&p->output_pkts)) {
        pmd->n_output_batches++;
    }

    struct dp_packet *packet;
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        p->output_pkts_rxqs[dp_packet_batch_size(&p->output_pkts)] =
            pmd->ctx.last_rxq;
        dp_packet_batch_add(&p->output_pkts, packet);
    }
    return true;
}

static void
dp_execute_lb_output_action(struct dp_netdev_pmd_thread *pmd,
                            struct dp_packet_batch *packets_,
                            bool should_steal, uint32_t bond)
{
    struct tx_bond *p_bond = tx_bond_lookup(&pmd->tx_bonds, bond);
    struct dp_packet_batch out;
    struct dp_packet *packet;

    if (!p_bond) {
        COVERAGE_ADD(datapath_drop_invalid_bond,
                     dp_packet_batch_size(packets_));
        dp_packet_delete_batch(packets_, should_steal);
        return;
    }
    if (!should_steal) {
        dp_packet_batch_clone(&out, packets_);
        dp_packet_batch_reset_cutlen(packets_);
        packets_ = &out;
    }
    dp_packet_batch_apply_cutlen(packets_);

    DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
        /*
         * Lookup the bond-hash table using hash to get the member.
         */
        uint32_t hash = dp_packet_get_rss_hash(packet);
        struct member_entry *s_entry
            = &p_bond->member_buckets[hash & BOND_MASK];
        odp_port_t bond_member = s_entry->member_id;
        uint32_t size = dp_packet_size(packet);
        struct dp_packet_batch output_pkt;

        dp_packet_batch_init_packet(&output_pkt, packet);
        if (OVS_LIKELY(dp_execute_output_action(pmd, &output_pkt, true,
                                                bond_member))) {
            /* Update member stats. */
            non_atomic_ullong_add(&s_entry->n_packets, 1);
            non_atomic_ullong_add(&s_entry->n_bytes, size);
        }
    }
}

static void
dp_execute_cb(void *aux_, struct dp_packet_batch *packets_,
              const struct nlattr *a, bool should_steal)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct dp_netdev_execute_aux *aux = aux_;
    uint32_t *depth = recirc_depth_get();
    struct dp_netdev_pmd_thread *pmd = aux->pmd;
    struct dp_netdev *dp = pmd->dp;
    int type = nl_attr_type(a);
    struct tx_port *p;
    uint32_t packet_count, packets_dropped;

    switch ((enum ovs_action_attr)type) {
    case OVS_ACTION_ATTR_OUTPUT:
        dp_execute_output_action(pmd, packets_, should_steal,
                                 nl_attr_get_odp_port(a));
        return;

    case OVS_ACTION_ATTR_LB_OUTPUT:
        dp_execute_lb_output_action(pmd, packets_, should_steal,
                                    nl_attr_get_u32(a));
        return;

    case OVS_ACTION_ATTR_TUNNEL_PUSH:
        if (should_steal) {
            /* We're requested to push tunnel header, but also we need to take
             * the ownership of these packets. Thus, we can avoid performing
             * the action, because the caller will not use the result anyway.
             * Just break to free the batch. */
            break;
        }
        dp_packet_batch_apply_cutlen(packets_);
        packet_count = dp_packet_batch_size(packets_);
        if (push_tnl_action(pmd, a, packets_)) {
            COVERAGE_ADD(datapath_drop_tunnel_push_error,
                         packet_count);
        }
        return;

    case OVS_ACTION_ATTR_TUNNEL_POP:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch *orig_packets_ = packets_;
            odp_port_t portno = nl_attr_get_odp_port(a);

            p = pmd_tnl_port_cache_lookup(pmd, portno);
            if (p) {
                struct dp_packet_batch tnl_pkt;

                if (!should_steal) {
                    dp_packet_batch_clone(&tnl_pkt, packets_);
                    packets_ = &tnl_pkt;
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                dp_packet_batch_apply_cutlen(packets_);

                packet_count = dp_packet_batch_size(packets_);
                netdev_pop_header(p->port->netdev, packets_);
                packets_dropped =
                   packet_count - dp_packet_batch_size(packets_);
                if (packets_dropped) {
                    COVERAGE_ADD(datapath_drop_tunnel_pop_error,
                                 packets_dropped);
                }
                if (dp_packet_batch_is_empty(packets_)) {
                    return;
                }

                struct dp_packet *packet;
                DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                    if (dp_netdev_e2e_cache_enabled) {
                        e2e_cache_trace_tnl_pop(packet);
                    }
                    packet->md.in_port.odp_port = portno;
                }

                (*depth)++;
                dp_netdev_recirculate(pmd, packets_);
                (*depth)--;
                return;
            }
            COVERAGE_ADD(datapath_drop_invalid_tnl_port,
                         dp_packet_batch_size(packets_));
        } else {
            COVERAGE_ADD(datapath_drop_recirc_error,
                         dp_packet_batch_size(packets_));
        }
        break;

    case OVS_ACTION_ATTR_USERSPACE:
        if (!fat_rwlock_tryrdlock(&dp->upcall_rwlock)) {
            struct dp_packet_batch *orig_packets_ = packets_;
            const struct nlattr *userdata;
            struct dp_packet_batch usr_pkt;
            struct ofpbuf actions;
            struct flow flow;
            ovs_u128 ufid;
            bool clone = false;

            userdata = nl_attr_find_nested(a, OVS_USERSPACE_ATTR_USERDATA);
            ofpbuf_init(&actions, 0);

            if (packets_->trunc) {
                if (!should_steal) {
                    dp_packet_batch_clone(&usr_pkt, packets_);
                    packets_ = &usr_pkt;
                    clone = true;
                    dp_packet_batch_reset_cutlen(orig_packets_);
                }

                dp_packet_batch_apply_cutlen(packets_);
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                flow_extract(packet, &flow);
                odp_flow_key_hash(&flow, sizeof flow, &ufid);
                dp_execute_userspace_action(pmd, packet, should_steal, &flow,
                                            &ufid, &actions, userdata);
            }

            if (clone) {
                dp_packet_delete_batch(packets_, true);
            }

            ofpbuf_uninit(&actions);
            fat_rwlock_unlock(&dp->upcall_rwlock);

            return;
        }
        COVERAGE_ADD(datapath_drop_lock_error,
                     dp_packet_batch_size(packets_));
        break;

    case OVS_ACTION_ATTR_RECIRC:
        if (*depth < MAX_RECIRC_DEPTH) {
            struct dp_packet_batch recirc_pkts;

            if (!should_steal) {
               dp_packet_batch_clone(&recirc_pkts, packets_);
               packets_ = &recirc_pkts;
            }

            struct dp_packet *packet;
            DP_PACKET_BATCH_FOR_EACH (i, packet, packets_) {
                packet->md.recirc_id = nl_attr_get_u32(a);
            }

            (*depth)++;
            dp_netdev_recirculate(pmd, packets_);
            (*depth)--;

            return;
        }

        COVERAGE_ADD(datapath_drop_recirc_error,
                     dp_packet_batch_size(packets_));
        VLOG_WARN("Packet dropped. Max recirculation depth exceeded.");
        break;

    case OVS_ACTION_ATTR_CT: {
        const struct nlattr *b;
        bool force = false;
        bool commit = false;
        unsigned int left;
        uint16_t zone = 0;
        uint32_t tp_id = 0;
        const char *helper = NULL;
        const uint32_t *setmark = NULL;
        const struct ovs_key_ct_labels *setlabel = NULL;
        struct nat_action_info_t nat_action_info;
        struct nat_action_info_t *nat_action_info_ref = NULL;
        bool nat_config = false;

        NL_ATTR_FOR_EACH_UNSAFE (b, left, nl_attr_get(a),
                                 nl_attr_get_size(a)) {
            enum ovs_ct_attr sub_type = nl_attr_type(b);

            switch(sub_type) {
            case OVS_CT_ATTR_FORCE_COMMIT:
                force = true;
                /* fall through. */
            case OVS_CT_ATTR_COMMIT:
                commit = true;
                break;
            case OVS_CT_ATTR_ZONE:
                zone = nl_attr_get_u16(b);
                break;
            case OVS_CT_ATTR_HELPER:
                helper = nl_attr_get_string(b);
                break;
            case OVS_CT_ATTR_MARK:
                setmark = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_LABELS:
                setlabel = nl_attr_get(b);
                break;
            case OVS_CT_ATTR_EVENTMASK:
                /* Silently ignored, as userspace datapath does not generate
                 * netlink events. */
                break;
            case OVS_CT_ATTR_TIMEOUT:
                if (!str_to_uint(nl_attr_get_string(b), 10, &tp_id)) {
                    VLOG_WARN("Invalid Timeout Policy ID: %s.",
                              nl_attr_get_string(b));
                    tp_id = DEFAULT_TP_ID;
                }
                break;
            case OVS_CT_ATTR_NAT: {
                const struct nlattr *b_nest;
                unsigned int left_nest;
                bool ip_min_specified = false;
                bool proto_num_min_specified = false;
                bool ip_max_specified = false;
                bool proto_num_max_specified = false;
                memset(&nat_action_info, 0, sizeof nat_action_info);
                nat_action_info_ref = &nat_action_info;

                NL_NESTED_FOR_EACH_UNSAFE (b_nest, left_nest, b) {
                    enum ovs_nat_attr sub_type_nest = nl_attr_type(b_nest);

                    switch (sub_type_nest) {
                    case OVS_NAT_ATTR_SRC:
                    case OVS_NAT_ATTR_DST:
                        nat_config = true;
                        nat_action_info.nat_action |=
                            ((sub_type_nest == OVS_NAT_ATTR_SRC)
                                ? NAT_ACTION_SRC : NAT_ACTION_DST);
                        break;
                    case OVS_NAT_ATTR_IP_MIN:
                        memcpy(&nat_action_info.min_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));
                        ip_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_IP_MAX:
                        memcpy(&nat_action_info.max_addr,
                               nl_attr_get(b_nest),
                               nl_attr_get_size(b_nest));
                        ip_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MIN:
                        nat_action_info.min_port =
                            nl_attr_get_u16(b_nest);
                        proto_num_min_specified = true;
                        break;
                    case OVS_NAT_ATTR_PROTO_MAX:
                        nat_action_info.max_port =
                            nl_attr_get_u16(b_nest);
                        proto_num_max_specified = true;
                        break;
                    case OVS_NAT_ATTR_PERSISTENT:
                    case OVS_NAT_ATTR_PROTO_HASH:
                    case OVS_NAT_ATTR_PROTO_RANDOM:
                        break;
                    case OVS_NAT_ATTR_UNSPEC:
                    case __OVS_NAT_ATTR_MAX:
                        OVS_NOT_REACHED();
                    }
                }

                if (ip_min_specified && !ip_max_specified) {
                    nat_action_info.max_addr = nat_action_info.min_addr;
                }
                if (proto_num_min_specified && !proto_num_max_specified) {
                    nat_action_info.max_port = nat_action_info.min_port;
                }
                if (proto_num_min_specified || proto_num_max_specified) {
                    if (nat_action_info.nat_action & NAT_ACTION_SRC) {
                        nat_action_info.nat_action |= NAT_ACTION_SRC_PORT;
                    } else if (nat_action_info.nat_action & NAT_ACTION_DST) {
                        nat_action_info.nat_action |= NAT_ACTION_DST_PORT;
                    }
                }
                break;
            }
            case OVS_CT_ATTR_UNSPEC:
            case __OVS_CT_ATTR_MAX:
                OVS_NOT_REACHED();
            }
        }

        /* We won't be able to function properly in this case, hence
         * complain loudly. */
        if (nat_config && !commit) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
            VLOG_WARN_RL(&rl, "NAT specified without commit.");
        }

        conntrack_execute(dp->conntrack, packets_, aux->flow->dl_type, force,
                          commit, zone, setmark, setlabel, aux->flow->tp_src,
                          aux->flow->tp_dst, helper, nat_action_info_ref,
                          pmd->ctx.now / 1000, tp_id);
        break;
    }

    case OVS_ACTION_ATTR_METER:
        dp_netdev_run_meter(pmd->dp, packets_, nl_attr_get_u32(a),
                            pmd->ctx.now);
        break;

    case OVS_ACTION_ATTR_DROP: {
        const enum xlate_error *drop_reason = nl_attr_get(a);

        odp_update_drop_action_counter((int)*drop_reason,
                                       dp_packet_batch_size(packets_));

        if (dp_netdev_e2e_cache_enabled) {
            e2e_cache_dispatch_trace_message(pmd->dp, packets_);
        }

        dp_packet_delete_batch(packets_, should_steal);
        return;
    }

    case OVS_ACTION_ATTR_PUSH_VLAN:
    case OVS_ACTION_ATTR_POP_VLAN:
    case OVS_ACTION_ATTR_PUSH_MPLS:
    case OVS_ACTION_ATTR_POP_MPLS:
    case OVS_ACTION_ATTR_SET:
    case OVS_ACTION_ATTR_SET_MASKED:
    case OVS_ACTION_ATTR_SAMPLE:
    case OVS_ACTION_ATTR_HASH:
    case OVS_ACTION_ATTR_UNSPEC:
    case OVS_ACTION_ATTR_TRUNC:
    case OVS_ACTION_ATTR_PUSH_ETH:
    case OVS_ACTION_ATTR_POP_ETH:
    case OVS_ACTION_ATTR_CLONE:
    case OVS_ACTION_ATTR_PUSH_NSH:
    case OVS_ACTION_ATTR_POP_NSH:
    case OVS_ACTION_ATTR_CT_CLEAR:
    case OVS_ACTION_ATTR_CHECK_PKT_LEN:
    case __OVS_ACTION_ATTR_MAX:
        OVS_NOT_REACHED();
    }

    dp_packet_delete_batch(packets_, should_steal);
}

static void
dp_netdev_execute_actions(struct dp_netdev_pmd_thread *pmd,
                          struct dp_packet_batch *packets,
                          bool should_steal, const struct flow *flow,
                          const struct nlattr *actions, size_t actions_len)
{
    struct dp_netdev_execute_aux aux = { pmd, flow };

    odp_execute_actions(&aux, packets, should_steal, actions,
                        actions_len, dp_execute_cb);
}

struct dp_netdev_ct_dump {
    struct ct_dpif_dump_state up;
    struct conntrack_dump dump;
    struct conntrack *ct;
    struct dp_netdev *dp;
};

static int
dpif_netdev_ct_dump_start(struct dpif *dpif, struct ct_dpif_dump_state **dump_,
                          const uint16_t *pzone, int *ptot_bkts)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_ct_dump *dump;

    dump = xzalloc(sizeof *dump);
    dump->dp = dp;
    dump->ct = dp->conntrack;

    conntrack_dump_start(dp->conntrack, &dump->dump, pzone, ptot_bkts);

    *dump_ = &dump->up;

    return 0;
}

static int
dpif_netdev_ct_dump_next(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_,
                         struct ct_dpif_entry *entry)
{
    struct dp_netdev_ct_dump *dump;

    INIT_CONTAINER(dump, dump_, up);

    return conntrack_dump_next(&dump->dump, entry);
}

static int
dpif_netdev_ct_dump_done(struct dpif *dpif OVS_UNUSED,
                         struct ct_dpif_dump_state *dump_)
{
    struct dp_netdev_ct_dump *dump;
    int err;

    INIT_CONTAINER(dump, dump_, up);

    err = conntrack_dump_done(&dump->dump);

    free(dump);

    return err;
}

static int
dpif_netdev_ct_flush(struct dpif *dpif, const uint16_t *zone,
                     const struct ct_dpif_tuple *tuple)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    if (tuple) {
        return conntrack_flush_tuple(dp->conntrack, tuple, zone ? *zone : 0);
    }
    return conntrack_flush(dp->conntrack, zone);
}

static int
dpif_netdev_ct_set_maxconns(struct dpif *dpif, uint32_t maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_maxconns(dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_maxconns(struct dpif *dpif, uint32_t *maxconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_maxconns(dp->conntrack, maxconns);
}

static int
dpif_netdev_ct_get_nconns(struct dpif *dpif, uint32_t *nconns)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_get_nconns(dp->conntrack, nconns);
}

static int
dpif_netdev_ct_set_tcp_seq_chk(struct dpif *dpif, bool enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);

    return conntrack_set_tcp_seq_chk(dp->conntrack, enabled);
}

static int
dpif_netdev_ct_get_tcp_seq_chk(struct dpif *dpif, bool *enabled)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    *enabled = conntrack_get_tcp_seq_chk(dp->conntrack);
    return 0;
}

static int
dpif_netdev_ct_set_limits(struct dpif *dpif OVS_UNUSED,
                           const uint32_t *default_limits,
                           const struct ovs_list *zone_limits)
{
    int err = 0;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    if (default_limits) {
        err = zone_limit_update(dp->conntrack, DEFAULT_ZONE, *default_limits);
        if (err != 0) {
            return err;
        }
    }

    struct ct_dpif_zone_limit *zone_limit;
    LIST_FOR_EACH (zone_limit, node, zone_limits) {
        err = zone_limit_update(dp->conntrack, zone_limit->zone,
                                zone_limit->limit);
        if (err != 0) {
            break;
        }
    }
    return err;
}

static int
dpif_netdev_ct_get_limits(struct dpif *dpif OVS_UNUSED,
                           uint32_t *default_limit,
                           const struct ovs_list *zone_limits_request,
                           struct ovs_list *zone_limits_reply)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct conntrack_zone_limit czl;

    czl = zone_limit_get(dp->conntrack, DEFAULT_ZONE);
    if (czl.zone == DEFAULT_ZONE) {
        *default_limit = czl.limit;
    } else {
        return EINVAL;
    }

    if (!ovs_list_is_empty(zone_limits_request)) {
        struct ct_dpif_zone_limit *zone_limit;
        LIST_FOR_EACH (zone_limit, node, zone_limits_request) {
            czl = zone_limit_get(dp->conntrack, zone_limit->zone);
            if (czl.zone == zone_limit->zone || czl.zone == DEFAULT_ZONE) {
                ct_dpif_push_zone_limit(zone_limits_reply, zone_limit->zone,
                                        czl.limit,
                                        atomic_count_get(&czl.count));
            } else {
                return EINVAL;
            }
        }
    } else {
        for (int z = MIN_ZONE; z <= MAX_ZONE; z++) {
            czl = zone_limit_get(dp->conntrack, z);
            if (czl.zone == z) {
                ct_dpif_push_zone_limit(zone_limits_reply, z, czl.limit,
                                        atomic_count_get(&czl.count));
            }
        }
    }

    return 0;
}

static int
dpif_netdev_ct_del_limits(struct dpif *dpif OVS_UNUSED,
                           const struct ovs_list *zone_limits)
{
    int err = 0;
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct ct_dpif_zone_limit *zone_limit;
    LIST_FOR_EACH (zone_limit, node, zone_limits) {
        err = zone_limit_delete(dp->conntrack, zone_limit->zone);
        if (err != 0) {
            break;
        }
    }

    return err;
}

static int
dpif_netdev_ct_set_timeout_policy(struct dpif *dpif,
                                  const struct ct_dpif_timeout_policy *dpif_tp)
{
    struct timeout_policy tp;
    struct dp_netdev *dp;

    dp = get_dp_netdev(dpif);
    memcpy(&tp.policy, dpif_tp, sizeof tp.policy);
    return timeout_policy_update(dp->conntrack, &tp);
}

static int
dpif_netdev_ct_get_timeout_policy(struct dpif *dpif, uint32_t tp_id,
                                  struct ct_dpif_timeout_policy *dpif_tp)
{
    struct timeout_policy *tp;
    struct dp_netdev *dp;
    int err = 0;

    dp = get_dp_netdev(dpif);
    tp = timeout_policy_get(dp->conntrack, tp_id);
    if (!tp) {
        return ENOENT;
    }
    memcpy(dpif_tp, &tp->policy, sizeof tp->policy);
    return err;
}

static int
dpif_netdev_ct_del_timeout_policy(struct dpif *dpif,
                                  uint32_t tp_id)
{
    struct dp_netdev *dp;
    int err = 0;

    dp = get_dp_netdev(dpif);
    err = timeout_policy_delete(dp->conntrack, tp_id);
    return err;
}

static int
dpif_netdev_ct_get_timeout_policy_name(struct dpif *dpif OVS_UNUSED,
                                       uint32_t tp_id,
                                       uint16_t dl_type OVS_UNUSED,
                                       uint8_t nw_proto OVS_UNUSED,
                                       char **tp_name, bool *is_generic)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "%"PRIu32, tp_id);
    *tp_name = ds_steal_cstr(&ds);
    *is_generic = true;
    return 0;
}

static int
dpif_netdev_ipf_set_enabled(struct dpif *dpif, bool v6, bool enable)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_enabled(conntrack_ipf_ctx(dp->conntrack), v6, enable);
}

static int
dpif_netdev_ipf_set_min_frag(struct dpif *dpif, bool v6, uint32_t min_frag)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_min_frag(conntrack_ipf_ctx(dp->conntrack), v6, min_frag);
}

static int
dpif_netdev_ipf_set_max_nfrags(struct dpif *dpif, uint32_t max_frags)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_set_max_nfrags(conntrack_ipf_ctx(dp->conntrack), max_frags);
}

/* Adjust this function if 'dpif_ipf_status' and 'ipf_status' were to
 * diverge. */
static int
dpif_netdev_ipf_get_status(struct dpif *dpif,
                           struct dpif_ipf_status *dpif_ipf_status)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    ipf_get_status(conntrack_ipf_ctx(dp->conntrack),
                   (struct ipf_status *) dpif_ipf_status);
    return 0;
}

static int
dpif_netdev_ipf_dump_start(struct dpif *dpif OVS_UNUSED,
                           struct ipf_dump_ctx **ipf_dump_ctx)
{
    return ipf_dump_start(ipf_dump_ctx);
}

static int
dpif_netdev_ipf_dump_next(struct dpif *dpif, void *ipf_dump_ctx, char **dump)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    return ipf_dump_next(conntrack_ipf_ctx(dp->conntrack), ipf_dump_ctx,
                         dump);
}

static int
dpif_netdev_ipf_dump_done(struct dpif *dpif OVS_UNUSED, void *ipf_dump_ctx)
{
    return ipf_dump_done(ipf_dump_ctx);

}

static int
dpif_netdev_bond_add(struct dpif *dpif, uint32_t bond_id,
                     odp_port_t *member_map)
{
    struct tx_bond *new_tx = xzalloc(sizeof *new_tx);
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    /* Prepare new bond mapping. */
    new_tx->bond_id = bond_id;
    for (int bucket = 0; bucket < BOND_BUCKETS; bucket++) {
        new_tx->member_buckets[bucket].member_id = member_map[bucket];
    }

    ovs_mutex_lock(&dp->bond_mutex);
    /* Check if bond already existed. */
    struct tx_bond *old_tx = tx_bond_lookup(&dp->tx_bonds, bond_id);
    if (old_tx) {
        cmap_replace(&dp->tx_bonds, &old_tx->node, &new_tx->node,
                     hash_bond_id(bond_id));
        ovsrcu_postpone(free, old_tx);
    } else {
        cmap_insert(&dp->tx_bonds, &new_tx->node, hash_bond_id(bond_id));
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    /* Update all PMDs with new bond mapping. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_add_bond_tx_to_pmd(pmd, new_tx, true);
    }
    return 0;
}

static int
dpif_netdev_bond_del(struct dpif *dpif, uint32_t bond_id)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;
    struct tx_bond *tx;

    ovs_mutex_lock(&dp->bond_mutex);
    /* Check if bond existed. */
    tx = tx_bond_lookup(&dp->tx_bonds, bond_id);
    if (tx) {
        cmap_remove(&dp->tx_bonds, &tx->node, hash_bond_id(bond_id));
        ovsrcu_postpone(free, tx);
    } else {
        /* Bond is not present. */
        ovs_mutex_unlock(&dp->bond_mutex);
        return ENOENT;
    }
    ovs_mutex_unlock(&dp->bond_mutex);

    /* Remove the bond map in all pmds. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        dp_netdev_del_bond_tx_from_pmd(pmd, bond_id);
    }
    return 0;
}

static int
dpif_netdev_bond_stats_get(struct dpif *dpif, uint32_t bond_id,
                           uint64_t *n_bytes)
{
    struct dp_netdev *dp = get_dp_netdev(dpif);
    struct dp_netdev_pmd_thread *pmd;

    if (!tx_bond_lookup(&dp->tx_bonds, bond_id)) {
        return ENOENT;
    }

    /* Search the bond in all PMDs. */
    CMAP_FOR_EACH (pmd, node, &dp->poll_threads) {
        struct tx_bond *pmd_bond_entry
            = tx_bond_lookup(&pmd->tx_bonds, bond_id);

        if (!pmd_bond_entry) {
            continue;
        }

        /* Read bond stats. */
        for (int i = 0; i < BOND_BUCKETS; i++) {
            uint64_t pmd_n_bytes;

            atomic_read_relaxed(&pmd_bond_entry->member_buckets[i].n_bytes,
                                &pmd_n_bytes);
            n_bytes[i] += pmd_n_bytes;
        }
    }
    return 0;
}

const struct dpif_class dpif_netdev_class = {
    "netdev",
    true,                       /* cleanup_required */
    dpif_netdev_init,
    dpif_netdev_enumerate,
    dpif_netdev_port_open_type,
    dpif_netdev_open,
    dpif_netdev_close,
    dpif_netdev_destroy,
    dpif_netdev_run,
    dpif_netdev_wait,
    dpif_netdev_get_stats,
    NULL,                      /* set_features */
    dpif_netdev_port_add,
    dpif_netdev_port_del,
    dpif_netdev_port_set_config,
    dpif_netdev_port_query_by_number,
    dpif_netdev_port_query_by_name,
    NULL,                       /* port_get_pid */
    dpif_netdev_port_dump_start,
    dpif_netdev_port_dump_next,
    dpif_netdev_port_dump_done,
    dpif_netdev_port_poll,
    dpif_netdev_port_poll_wait,
    dpif_netdev_flow_flush,
    dpif_netdev_flow_dump_create,
    dpif_netdev_flow_dump_destroy,
    dpif_netdev_flow_dump_thread_create,
    dpif_netdev_flow_dump_thread_destroy,
    dpif_netdev_flow_dump_next,
    dpif_netdev_dump_e2e_stats,
    dpif_netdev_dump_e2e_flows,
    dpif_netdev_operate,
    dpif_netdev_offload_stats_get,
    NULL,                       /* recv_set */
    NULL,                       /* handlers_set */
    dpif_netdev_set_config,
    dpif_netdev_queue_to_priority,
    NULL,                       /* recv */
    NULL,                       /* recv_wait */
    NULL,                       /* recv_purge */
    dpif_netdev_register_dp_purge_cb,
    dpif_netdev_register_upcall_cb,
    dpif_netdev_enable_upcall,
    dpif_netdev_disable_upcall,
    dpif_netdev_get_datapath_version,
    dpif_netdev_ct_dump_start,
    dpif_netdev_ct_dump_next,
    dpif_netdev_ct_dump_done,
    dpif_netdev_ct_flush,
    dpif_netdev_ct_set_maxconns,
    dpif_netdev_ct_get_maxconns,
    dpif_netdev_ct_get_nconns,
    dpif_netdev_ct_set_tcp_seq_chk,
    dpif_netdev_ct_get_tcp_seq_chk,
    dpif_netdev_ct_set_limits,
    dpif_netdev_ct_get_limits,
    dpif_netdev_ct_del_limits,
    dpif_netdev_ct_set_timeout_policy,
    dpif_netdev_ct_get_timeout_policy,
    dpif_netdev_ct_del_timeout_policy,
    NULL,                       /* ct_timeout_policy_dump_start */
    NULL,                       /* ct_timeout_policy_dump_next */
    NULL,                       /* ct_timeout_policy_dump_done */
    dpif_netdev_ct_get_timeout_policy_name,
    dpif_netdev_ipf_set_enabled,
    dpif_netdev_ipf_set_min_frag,
    dpif_netdev_ipf_set_max_nfrags,
    dpif_netdev_ipf_get_status,
    dpif_netdev_ipf_dump_start,
    dpif_netdev_ipf_dump_next,
    dpif_netdev_ipf_dump_done,
    dpif_netdev_meter_get_features,
    dpif_netdev_meter_set,
    dpif_netdev_meter_get,
    dpif_netdev_meter_del,
    dpif_netdev_bond_add,
    dpif_netdev_bond_del,
    dpif_netdev_bond_stats_get,
    NULL,                       /* psample_enabled */
    NULL,                       /* psample_poll */
    NULL,                       /* psample_poll_wait */
};

static void
dpif_dummy_change_port_number(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct dp_netdev_port *port;
    struct dp_netdev *dp;
    odp_port_t port_no;

    ovs_mutex_lock(&dp_netdev_mutex);
    dp = shash_find_data(&dp_netdevs, argv[1]);
    if (!dp || !dpif_netdev_class_is_dummy(dp->class)) {
        ovs_mutex_unlock(&dp_netdev_mutex);
        unixctl_command_reply_error(conn, "unknown datapath or not a dummy");
        return;
    }
    ovs_refcount_ref(&dp->ref_cnt);
    ovs_mutex_unlock(&dp_netdev_mutex);

    ovs_rwlock_wrlock(&dp->port_rwlock);
    if (get_port_by_name(dp, argv[2], &port)) {
        unixctl_command_reply_error(conn, "unknown port");
        goto exit;
    }

    port_no = u32_to_odp(atoi(argv[3]));
    if (!port_no || port_no == ODPP_NONE) {
        unixctl_command_reply_error(conn, "bad port number");
        goto exit;
    }
    if (dp_netdev_lookup_port(dp, port_no)) {
        unixctl_command_reply_error(conn, "port number already in use");
        goto exit;
    }

    /* Remove port. */
    hmap_remove(&dp->ports, &port->node);
    reconfigure_datapath(dp);

    /* Reinsert with new port number. */
    port->port_no = port_no;
    hmap_insert(&dp->ports, &port->node, hash_port_no(port_no));
    reconfigure_datapath(dp);

    seq_change(dp->port_seq);
    unixctl_command_reply(conn, NULL);

exit:
    ovs_rwlock_unlock(&dp->port_rwlock);
    dp_netdev_unref(dp);
}

static void
dpif_dummy_register__(const char *type)
{
    struct dpif_class *class;

    class = xmalloc(sizeof *class);
    *class = dpif_netdev_class;
    class->type = xstrdup(type);
    dp_register_provider(class);
}

static void
dpif_dummy_override(const char *type)
{
    int error;

    /*
     * Ignore EAFNOSUPPORT to allow --enable-dummy=system with
     * a userland-only build.  It's useful for testsuite.
     */
    error = dp_unregister_provider(type);
    if (error == 0 || error == EAFNOSUPPORT) {
        dpif_dummy_register__(type);
    }
}

void
dpif_dummy_register(enum dummy_level level)
{
    if (level == DUMMY_OVERRIDE_ALL) {
        struct sset types;
        const char *type;

        sset_init(&types);
        dp_enumerate_types(&types);
        SSET_FOR_EACH (type, &types) {
            dpif_dummy_override(type);
        }
        sset_destroy(&types);
    } else if (level == DUMMY_OVERRIDE_SYSTEM) {
        dpif_dummy_override("system");
    }

    dpif_dummy_register__("dummy");

    unixctl_command_register("dpif-dummy/change-port-number",
                             "dp port new-number",
                             3, 3, dpif_dummy_change_port_number, NULL);
}

/* Datapath Classifier. */

static void
dpcls_subtable_destroy_cb(struct dpcls_subtable *subtable)
{
    cmap_destroy(&subtable->rules);
    ovsrcu_postpone(free, subtable->mf_masks);
    ovsrcu_postpone(free, subtable);
}

/* Initializes 'cls' as a classifier that initially contains no classification
 * rules. */
static void
dpcls_init(struct dpcls *cls)
{
    cmap_init(&cls->subtables_map);
    pvector_init(&cls->subtables);
}

static void
dpcls_destroy_subtable(struct dpcls *cls, struct dpcls_subtable *subtable)
{
    VLOG_DBG("Destroying subtable %p for in_port %d", subtable, cls->in_port);
    pvector_remove(&cls->subtables, subtable);
    cmap_remove(&cls->subtables_map, &subtable->cmap_node,
                subtable->mask.hash);
    ovsrcu_postpone(dpcls_subtable_destroy_cb, subtable);
}

/* Destroys 'cls'.  Rules within 'cls', if any, are not freed; this is the
 * caller's responsibility.
 * May only be called after all the readers have been terminated. */
static void
dpcls_destroy(struct dpcls *cls)
{
    if (cls) {
        struct dpcls_subtable *subtable;

        CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
            ovs_assert(cmap_count(&subtable->rules) == 0);
            dpcls_destroy_subtable(cls, subtable);
        }
        cmap_destroy(&cls->subtables_map);
        pvector_destroy(&cls->subtables);
    }
}

static struct dpcls_subtable *
dpcls_create_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    /* Need to add one. */
    subtable = xmalloc(sizeof *subtable
                       - sizeof subtable->mask.mf + mask->len);
    cmap_init(&subtable->rules);
    subtable->hit_cnt = 0;
    netdev_flow_key_clone(&subtable->mask, mask);

    /* The count of bits in the mask defines the space required for masks.
     * Then call gen_masks() to create the appropriate masks, avoiding the cost
     * of doing runtime calculations. */
    uint32_t unit0 = count_1bits(mask->mf.map.bits[0]);
    uint32_t unit1 = count_1bits(mask->mf.map.bits[1]);
    subtable->mf_bits_set_unit0 = unit0;
    subtable->mf_bits_set_unit1 = unit1;
    subtable->mf_masks = xmalloc(sizeof(uint64_t) * (unit0 + unit1));
    netdev_flow_key_gen_masks(mask, subtable->mf_masks, unit0, unit1);

    /* Get the preferred subtable search function for this (u0,u1) subtable.
     * The function is guaranteed to always return a valid implementation, and
     * possibly an ISA optimized, and/or specialized implementation.
     */
    subtable->lookup_func = dpcls_subtable_get_best_impl(unit0, unit1);

    cmap_insert(&cls->subtables_map, &subtable->cmap_node, mask->hash);
    /* Add the new subtable at the end of the pvector (with no hits yet) */
    pvector_insert(&cls->subtables, subtable, 0);
    VLOG_DBG("Creating %"PRIuSIZE". subtable %p for in_port %d",
             cmap_count(&cls->subtables_map), subtable, cls->in_port);
    pvector_publish(&cls->subtables);

    return subtable;
}

static inline struct dpcls_subtable *
dpcls_find_subtable(struct dpcls *cls, const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable;

    CMAP_FOR_EACH_WITH_HASH (subtable, cmap_node, mask->hash,
                             &cls->subtables_map) {
        if (netdev_flow_key_equal(&subtable->mask, mask)) {
            return subtable;
        }
    }
    return dpcls_create_subtable(cls, mask);
}

/* Checks for the best available implementation for each subtable lookup
 * function, and assigns it as the lookup function pointer for each subtable.
 * Returns the number of subtables that have changed lookup implementation.
 */
static uint32_t
dpcls_subtable_lookup_reprobe(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    uint32_t subtables_changed = 0;
    struct dpcls_subtable *subtable = NULL;

    PVECTOR_FOR_EACH (subtable, pvec) {
        uint32_t u0_bits = subtable->mf_bits_set_unit0;
        uint32_t u1_bits = subtable->mf_bits_set_unit1;
        void *old_func = subtable->lookup_func;
        subtable->lookup_func = dpcls_subtable_get_best_impl(u0_bits, u1_bits);
        subtables_changed += (old_func != subtable->lookup_func);
    }
    pvector_publish(pvec);

    return subtables_changed;
}

/* Periodically sort the dpcls subtable vectors according to hit counts */
static void
dpcls_sort_subtable_vector(struct dpcls *cls)
{
    struct pvector *pvec = &cls->subtables;
    struct dpcls_subtable *subtable;

    PVECTOR_FOR_EACH (subtable, pvec) {
        pvector_change_priority(pvec, subtable, subtable->hit_cnt);
        subtable->hit_cnt = 0;
    }
    pvector_publish(pvec);
}

static inline void
dp_netdev_pmd_try_optimize(struct dp_netdev_pmd_thread *pmd,
                           struct polled_queue *poll_list, int poll_cnt)
{
    struct dpcls *cls;
    uint64_t tot_idle = 0, tot_proc = 0;
    unsigned int pmd_load = 0;

    if (pmd->ctx.now > pmd->rxq_next_cycle_store) {
        uint64_t curr_tsc;
        uint8_t rebalance_load_trigger;
        struct pmd_auto_lb *pmd_alb = &pmd->dp->pmd_alb;
        if (pmd_alb->is_enabled && !pmd->isolated
            && (pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] >=
                                       pmd->prev_stats[PMD_CYCLES_ITER_IDLE])
            && (pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] >=
                                        pmd->prev_stats[PMD_CYCLES_ITER_BUSY]))
            {
            tot_idle = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE] -
                       pmd->prev_stats[PMD_CYCLES_ITER_IDLE];
            tot_proc = pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY] -
                       pmd->prev_stats[PMD_CYCLES_ITER_BUSY];

            if (tot_proc) {
                pmd_load = ((tot_proc * 100) / (tot_idle + tot_proc));
            }

            atomic_read_relaxed(&pmd_alb->rebalance_load_thresh,
                                &rebalance_load_trigger);
            if (pmd_load >= rebalance_load_trigger) {
                atomic_count_inc(&pmd->pmd_overloaded);
            } else {
                atomic_count_set(&pmd->pmd_overloaded, 0);
            }
        }

        pmd->prev_stats[PMD_CYCLES_ITER_IDLE] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_IDLE];
        pmd->prev_stats[PMD_CYCLES_ITER_BUSY] =
                        pmd->perf_stats.counters.n[PMD_CYCLES_ITER_BUSY];

        /* Get the cycles that were used to process each queue and store. */
        for (unsigned i = 0; i < poll_cnt; i++) {
            uint64_t rxq_cyc_curr = dp_netdev_rxq_get_cycles(poll_list[i].rxq,
                                                        RXQ_CYCLES_PROC_CURR);
            dp_netdev_rxq_set_intrvl_cycles(poll_list[i].rxq, rxq_cyc_curr);
            dp_netdev_rxq_set_cycles(poll_list[i].rxq, RXQ_CYCLES_PROC_CURR,
                                     0);
        }
        curr_tsc = cycles_counter_update(&pmd->perf_stats);
        if (pmd->intrvl_tsc_prev) {
            /* There is a prev timestamp, store a new intrvl cycle count. */
            atomic_store_relaxed(&pmd->intrvl_cycles,
                                 curr_tsc - pmd->intrvl_tsc_prev);
        }
        pmd->intrvl_tsc_prev = curr_tsc;
        /* Start new measuring interval */
        pmd->rxq_next_cycle_store = pmd->ctx.now + PMD_RXQ_INTERVAL_LEN;
    }

    if (pmd->ctx.now > pmd->next_optimization) {
        /* Try to obtain the flow lock to block out revalidator threads.
         * If not possible, just try next time. */
        if (!ovs_mutex_trylock(&pmd->flow_mutex)) {
            /* Optimize each classifier */
            CMAP_FOR_EACH (cls, node, &pmd->classifiers) {
                dpcls_sort_subtable_vector(cls);
            }
            ovs_mutex_unlock(&pmd->flow_mutex);
            /* Start new measuring interval */
            pmd->next_optimization = pmd->ctx.now
                                     + DPCLS_OPTIMIZATION_INTERVAL;
        }
    }
}

/* Insert 'rule' into 'cls'. */
static void
dpcls_insert(struct dpcls *cls, struct dpcls_rule *rule,
             const struct netdev_flow_key *mask)
{
    struct dpcls_subtable *subtable = dpcls_find_subtable(cls, mask);

    /* Refer to subtable's mask, also for later removal. */
    rule->mask = &subtable->mask;
    cmap_insert(&subtable->rules, &rule->cmap_node, rule->flow.hash);
}

/* Removes 'rule' from 'cls', also destructing the 'rule'. */
static void
dpcls_remove(struct dpcls *cls, struct dpcls_rule *rule)
{
    struct dpcls_subtable *subtable;

    ovs_assert(rule->mask);

    /* Get subtable from reference in rule->mask. */
    INIT_CONTAINER(subtable, rule->mask, mask);
    if (cmap_remove(&subtable->rules, &rule->cmap_node, rule->flow.hash)
        == 0) {
        /* Delete empty subtable. */
        dpcls_destroy_subtable(cls, subtable);
        pvector_publish(&cls->subtables);
    }
}

/* Inner loop for mask generation of a unit, see netdev_flow_key_gen_masks. */
static inline void
netdev_flow_key_gen_mask_unit(uint64_t iter,
                              const uint64_t count,
                              uint64_t *mf_masks)
{
    int i;
    for (i = 0; i < count; i++) {
        uint64_t lowest_bit = (iter & -iter);
        iter &= ~lowest_bit;
        mf_masks[i] = (lowest_bit - 1);
    }
    /* Checks that count has covered all bits in the iter bitmap. */
    ovs_assert(iter == 0);
}

/* Generate a mask for each block in the miniflow, based on the bits set. This
 * allows easily masking packets with the generated array here, without
 * calculations. This replaces runtime-calculating the masks.
 * @param key The table to generate the mf_masks for
 * @param mf_masks Pointer to a u64 array of at least *mf_bits* in size
 * @param mf_bits_total Number of bits set in the whole miniflow (both units)
 * @param mf_bits_unit0 Number of bits set in unit0 of the miniflow
 */
void
netdev_flow_key_gen_masks(const struct netdev_flow_key *tbl,
                          uint64_t *mf_masks,
                          const uint32_t mf_bits_u0,
                          const uint32_t mf_bits_u1)
{
    uint64_t iter_u0 = tbl->mf.map.bits[0];
    uint64_t iter_u1 = tbl->mf.map.bits[1];

    netdev_flow_key_gen_mask_unit(iter_u0, mf_bits_u0, &mf_masks[0]);
    netdev_flow_key_gen_mask_unit(iter_u1, mf_bits_u1, &mf_masks[mf_bits_u0]);
}

/* Returns true if 'target' satisfies 'key' in 'mask', that is, if each 1-bit
 * in 'mask' the values in 'key' and 'target' are the same. */
bool
dpcls_rule_matches_key(const struct dpcls_rule *rule,
                       const struct netdev_flow_key *target)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    uint64_t value;

    NETDEV_FLOW_KEY_FOR_EACH_IN_FLOWMAP(value, target, rule->flow.mf.map) {
        if (OVS_UNLIKELY((value & *maskp++) != *keyp++)) {
            return false;
        }
    }
    return true;
}

/* For each miniflow in 'keys' performs a classifier lookup writing the result
 * into the corresponding slot in 'rules'.  If a particular entry in 'keys' is
 * NULL it is skipped.
 *
 * This function is optimized for use in the userspace datapath and therefore
 * does not implement a lot of features available in the standard
 * classifier_lookup() function.  Specifically, it does not implement
 * priorities, instead returning any rule which matches the flow.
 *
 * Returns true if all miniflows found a corresponding rule. */
static bool
dpcls_lookup(struct dpcls *cls, const struct netdev_flow_key *keys[],
             struct dpcls_rule **rules, const size_t cnt,
             int *num_lookups_p)
{
    /* The received 'cnt' miniflows are the search-keys that will be processed
     * to find a matching entry into the available subtables.
     * The number of bits in map_type is equal to NETDEV_MAX_BURST. */
#define MAP_BITS (sizeof(uint32_t) * CHAR_BIT)
    BUILD_ASSERT_DECL(MAP_BITS >= NETDEV_MAX_BURST);

    struct dpcls_subtable *subtable;
    uint32_t keys_map = TYPE_MAXIMUM(uint32_t); /* Set all bits. */

    if (cnt != MAP_BITS) {
        keys_map >>= MAP_BITS - cnt; /* Clear extra bits. */
    }
    memset(rules, 0, cnt * sizeof *rules);

    int lookups_match = 0, subtable_pos = 1;
    uint32_t found_map;

    /* The Datapath classifier - aka dpcls - is composed of subtables.
     * Subtables are dynamically created as needed when new rules are inserted.
     * Each subtable collects rules with matches on a specific subset of packet
     * fields as defined by the subtable's mask.  We proceed to process every
     * search-key against each subtable, but when a match is found for a
     * search-key, the search for that key can stop because the rules are
     * non-overlapping. */
    PVECTOR_FOR_EACH (subtable, &cls->subtables) {
        /* Call the subtable specific lookup function. */
        found_map = subtable->lookup_func(subtable, keys_map, keys, rules);

        /* Count the number of subtables searched for this packet match. This
         * estimates the "spread" of subtables looked at per matched packet. */
        uint32_t pkts_matched = count_1bits(found_map);
        lookups_match += pkts_matched * subtable_pos;

        /* Clear the found rules, and return early if all packets are found. */
        keys_map &= ~found_map;
        if (!keys_map) {
            if (num_lookups_p) {
                *num_lookups_p = lookups_match;
            }
            return true;
        }
        subtable_pos++;
    }

    if (num_lookups_p) {
        *num_lookups_p = lookups_match;
    }
    return false;
}

#ifdef E2E_CACHE_ENABLED
static inline bool
e2e_cache_set_action_is_valid(struct nlattr *a)
{
    const struct nlattr *set_action = nl_attr_get(a);
    const size_t set_len = nl_attr_get_size(a);
    const struct nlattr *sa;
    unsigned int sleft;

    NL_ATTR_FOR_EACH (sa, sleft, set_action, set_len) {
        enum ovs_key_attr type = nl_attr_type(sa);

        if (!(type == OVS_KEY_ATTR_ETHERNET ||
              type == OVS_KEY_ATTR_IPV4 ||
              type == OVS_KEY_ATTR_IPV6 ||
              type == OVS_KEY_ATTR_TCP ||
              type == OVS_KEY_ATTR_UDP)) {
            VLOG_DBG("Unsupported set action type %d", type);
            /* TODO: add statistic counter */
            return false;
        }
    }
    return true;
}

static inline bool
e2e_cache_flows_are_valid(struct e2e_cache_ovs_flow **netdev_flows,
                          uint16_t num)
{
    struct e2e_cache_ovs_flow *flow;
    const struct match *match;
    unsigned int left;
    struct nlattr *a;
    uint16_t i;

    for (i = 0; i < num; i++) {
        flow = netdev_flows[i];
        if (flow->offload_state != E2E_OL_STATE_FLOW) {
            continue;
        }

        match = &flow->match[0];
        /* validate match */
        if ((match->flow.ipv6_label & match->wc.masks.ipv6_label) ||
            (match->flow.nw_tos & match->wc.masks.nw_tos) ||
            (match->flow.tcp_flags & match->wc.masks.tcp_flags) ||
            (match->flow.igmp_group_ip4 & match->wc.masks.igmp_group_ip4)) {
            /* TODO: add statistic counter */
            return false;
        }

        /* validate actions */
        NL_ATTR_FOR_EACH (a, left, flow->actions, flow->actions_size) {
            enum ovs_action_attr type = nl_attr_type(a);
            if (type == OVS_ACTION_ATTR_USERSPACE ||
                type == OVS_ACTION_ATTR_HASH ||
                type == OVS_ACTION_ATTR_TRUNC ||
                type == OVS_ACTION_ATTR_PUSH_NSH ||
                type == OVS_ACTION_ATTR_POP_NSH ||
                type == OVS_ACTION_ATTR_CT_CLEAR ||
                type == OVS_ACTION_ATTR_CHECK_PKT_LEN ||
                type == OVS_ACTION_ATTR_SAMPLE ||
                ((type == OVS_ACTION_ATTR_OUTPUT ||
                  type == OVS_ACTION_ATTR_CLONE) &&
                 left > NLA_ALIGN(a->nla_len)) ||
                ((type == OVS_ACTION_ATTR_SET ||
                  type == OVS_ACTION_ATTR_SET_MASKED) &&
                 !e2e_cache_set_action_is_valid(a))) {
                 /* TODO: add statistic counter */
                return false;
            }
        }
    }
    return true;
}

#define e2e_save_set_attr(mfield, field, flag)                         \
    if (mask) {                                                        \
        if (!is_all_zeros(&mask->field, sizeof mask->field)) {         \
            if (!is_all_ones(&mask->field, sizeof mask->field)) {      \
                VLOG_DBG_RL(&rl, "HW partial mask is not supported");  \
            }                                                          \
            merged->flags |= flag;                                     \
            merged->mfield.field = key->field;                         \
        }                                                              \
    } else if (!is_all_zeros(&key->field, sizeof key->field)) {        \
        merged->flags |= flag;                                         \
        merged->mfield.field = key->field;                             \
    }

static inline void
e2e_cache_save_set_actions(struct e2e_cache_merged_set *merged, bool masked,
                           const struct nlattr *set_action,
                           const size_t set_len)
{
    const struct nlattr *sa;
    unsigned int sleft;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(10, 10);

    NL_ATTR_FOR_EACH (sa, sleft, set_action, set_len) {
        if (nl_attr_type(sa) == OVS_KEY_ATTR_ETHERNET) {
            const struct ovs_key_ethernet *key = nl_attr_get(sa);
            const struct ovs_key_ethernet *mask = masked ? key + 1 : NULL;

            e2e_save_set_attr(eth, eth_src, E2E_SET_ETH_SRC);
            e2e_save_set_attr(eth, eth_dst, E2E_SET_ETH_DST);
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV4) {
            const struct ovs_key_ipv4 *key = nl_attr_get(sa);
            const struct ovs_key_ipv4 *mask = masked ? key + 1 : NULL;

            e2e_save_set_attr(ipv4, ipv4_src, E2E_SET_IPV4_SRC);
            e2e_save_set_attr(ipv4, ipv4_dst, E2E_SET_IPV4_DST);
            e2e_save_set_attr(ipv4, ipv4_ttl, E2E_SET_IPV4_TTL);
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV6) {
            const struct ovs_key_ipv6 *key = nl_attr_get(sa);
            const struct ovs_key_ipv6 *mask = masked ? key + 1 : NULL;

            e2e_save_set_attr(ipv6, ipv6_src, E2E_SET_IPV6_SRC);
            e2e_save_set_attr(ipv6, ipv6_dst, E2E_SET_IPV6_DST);
            e2e_save_set_attr(ipv6, ipv6_hlimit, E2E_SET_IPV6_HLMT);
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_TCP) {
            const struct ovs_key_tcp *key = nl_attr_get(sa);
            const struct ovs_key_tcp *mask = masked ? key + 1 : NULL;

            e2e_save_set_attr(tcp, tcp_src, E2E_SET_TCP_SRC);
            e2e_save_set_attr(tcp, tcp_dst, E2E_SET_TCP_DST);
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_UDP) {
            const struct ovs_key_udp *key = nl_attr_get(sa);
            const struct ovs_key_udp *mask = masked ? key + 1 : NULL;

            e2e_save_set_attr(udp, udp_src, E2E_SET_UDP_SRC);
            e2e_save_set_attr(udp, udp_dst, E2E_SET_UDP_DST);
        }
    }
}

#define e2e_construct_set_attr(mfield, field, flag)       \
    if (merged->flags & flag) {                           \
        key->field = merged->mfield.field;                \
        memset(&mask->field, 0xFF, sizeof mask->field);   \
    }

static inline void
e2e_cache_attach_merged_set_action(struct ofpbuf *buf, size_t tnl_offset,
                                   struct e2e_cache_merged_set *merged)
{
    size_t offset;
    struct ofpbuf tmpbuf;

    ofpbuf_init(&tmpbuf, 0);
    offset = nl_msg_start_nested(&tmpbuf, OVS_ACTION_ATTR_SET_MASKED);
    if (merged->flags & E2E_SET_ETH) {
        struct ovs_key_ethernet *key = NULL;
        struct ovs_key_ethernet *mask = NULL;

        key = nl_msg_put_unspec_zero(&tmpbuf, OVS_KEY_ATTR_ETHERNET,
                                     2 * sizeof *key);
        mask = key + 1;
        e2e_construct_set_attr(eth, eth_src, E2E_SET_ETH_SRC);
        e2e_construct_set_attr(eth, eth_dst, E2E_SET_ETH_DST);
    }
    if (merged->flags & E2E_SET_IPV4) {
        struct ovs_key_ipv4 *key = NULL;
        struct ovs_key_ipv4 *mask = NULL;

        key = nl_msg_put_unspec_zero(&tmpbuf, OVS_KEY_ATTR_IPV4,
                                     2 * sizeof *key);
        mask = key + 1;
        e2e_construct_set_attr(ipv4, ipv4_src, E2E_SET_IPV4_SRC);
        e2e_construct_set_attr(ipv4, ipv4_dst, E2E_SET_IPV4_DST);
        e2e_construct_set_attr(ipv4, ipv4_ttl, E2E_SET_IPV4_TTL);
    }
    if (merged->flags & E2E_SET_IPV6) {
        struct ovs_key_ipv6 *key = NULL;
        struct ovs_key_ipv6 *mask = NULL;

        key = nl_msg_put_unspec_zero(&tmpbuf, OVS_KEY_ATTR_IPV6,
                                     2 * sizeof *key);
        mask = key + 1;
        e2e_construct_set_attr(ipv6, ipv6_src, E2E_SET_IPV6_SRC);
        e2e_construct_set_attr(ipv6, ipv6_dst, E2E_SET_IPV6_DST);
        e2e_construct_set_attr(ipv6, ipv6_hlimit, E2E_SET_IPV6_HLMT);
    }
    if (merged->flags & E2E_SET_TCP) {
        struct ovs_key_tcp *key = NULL;
        struct ovs_key_tcp *mask = NULL;

        key = nl_msg_put_unspec_zero(&tmpbuf, OVS_KEY_ATTR_TCP,
                                     2 * sizeof *key);
        mask = key + 1;
        e2e_construct_set_attr(tcp, tcp_src, E2E_SET_TCP_SRC);
        e2e_construct_set_attr(tcp, tcp_dst, E2E_SET_TCP_DST);
    }
    if (merged->flags & E2E_SET_UDP) {
        struct ovs_key_udp *key = NULL;
        struct ovs_key_udp *mask = NULL;

        key = nl_msg_put_unspec_zero(&tmpbuf, OVS_KEY_ATTR_UDP,
                                     2 * sizeof *key);
        mask = key + 1;
        e2e_construct_set_attr(udp, udp_src, E2E_SET_UDP_SRC);
        e2e_construct_set_attr(udp, udp_dst, E2E_SET_UDP_DST);
    }
    nl_msg_end_nested(&tmpbuf, offset);
    /* insert the set action after tnl_pop in the buf */
    ofpbuf_insert(buf, tnl_offset, tmpbuf.data, tmpbuf.size);
}

static void
e2e_cache_merge_actions(struct e2e_cache_ovs_flow **netdev_flows,
                        uint16_t num, struct ofpbuf *buf)
{
    uint16_t i = 0;
    unsigned int left;
    const struct nlattr *a;
    uint16_t num_set = 0;
    struct e2e_cache_merged_set merged_set;
    size_t tnl_offset = 0;

    memset(&merged_set, 0, sizeof merged_set);
    for (i = 0; i < num; i++) {
        if (i > 0 && netdev_flows[i]->offload_state != E2E_OL_STATE_FLOW &&
            netdev_flows[i - 1]->offload_state != E2E_OL_STATE_FLOW) {
            continue;
        }
        NL_ATTR_FOR_EACH (a, left, netdev_flows[i]->actions,
                          netdev_flows[i]->actions_size) {
            enum ovs_action_attr type = nl_attr_type(a);

            if (type == OVS_ACTION_ATTR_CT ||
                type == OVS_ACTION_ATTR_RECIRC) {
                continue;
            }
            if (type == OVS_ACTION_ATTR_SET ||
                type == OVS_ACTION_ATTR_SET_MASKED) {
                const struct nlattr *set_action = nl_attr_get(a);
                const size_t set_len = nl_attr_get_size(a);
                bool masked = (type == OVS_ACTION_ATTR_SET_MASKED);

                e2e_cache_save_set_actions(&merged_set, masked,
                                           set_action, set_len);
                num_set++;
                continue;
            }
            if (type == OVS_ACTION_ATTR_TUNNEL_POP) {
                tnl_offset = buf->size + a->nla_len;
            }
            ofpbuf_put(buf, a, a->nla_len);
        }
    }
    if (num_set) {
        e2e_cache_attach_merged_set_action(buf, tnl_offset, &merged_set);
    }
}

static inline void
e2e_cache_shift_tnl_fields(struct match *merged_match)
{
    struct eth_addr dl_src, dl_dst;
    struct eth_addr src_mask, dst_mask;
    bool merge_src = false;
    bool merge_dst = false;
    ovs_be16 dport, dport_mask;
    uint8_t proto, proto_mask;
    union flow_in_port in_port, inport_mask;

    if (!is_all_zeros(&merged_match->wc.masks.dl_src,
                      sizeof merged_match->wc.masks.dl_src)) {
         memcpy(&dl_src, &merged_match->flow.dl_src, sizeof dl_src);
         memcpy(&src_mask, &merged_match->wc.masks.dl_src,
                sizeof src_mask);
         merge_src = true;
    }
    if (!is_all_zeros(&merged_match->wc.masks.dl_dst,
                      sizeof merged_match->wc.masks.dl_dst)) {
         memcpy(&dl_dst, &merged_match->flow.dl_dst, sizeof dl_dst);
         memcpy(&dst_mask, &merged_match->wc.masks.dl_dst,
                sizeof dst_mask);
         merge_dst = true;
    }
    dport = merged_match->flow.tp_dst;
    dport_mask = merged_match->wc.masks.tp_dst;
    proto = merged_match->flow.nw_proto;
    proto_mask = merged_match->wc.masks.nw_proto;
    memcpy(&in_port, &merged_match->flow.in_port, sizeof in_port);
    memcpy(&inport_mask, &merged_match->wc.masks.in_port, sizeof inport_mask);
    /* clear match buffer */
    memset(merged_match, 0, sizeof *merged_match);
    /* restore tunnel match */
    if (merge_src) {
        memcpy(&merged_match->flow.tunnel.metadata.dl_src, &dl_src,
               sizeof dl_src);
        memcpy(&merged_match->wc.masks.tunnel.metadata.dl_src,
               &src_mask, sizeof src_mask);
    }
    if (merge_dst) {
        memcpy(&merged_match->flow.tunnel.metadata.dl_dst, &dl_dst,
               sizeof dl_dst);
        memcpy(&merged_match->wc.masks.tunnel.metadata.dl_dst,
               &dst_mask, sizeof dst_mask);
    }
    merged_match->flow.tunnel.tp_dst = dport;
    merged_match->wc.masks.tunnel.tp_dst = dport_mask;
    merged_match->flow.tunnel.metadata.nw_proto = proto;
    merged_match->wc.masks.tunnel.metadata.nw_proto = proto_mask;
    memcpy(&merged_match->flow.in_port, &in_port, sizeof in_port);
    memcpy(&merged_match->wc.masks.in_port, &inport_mask, sizeof inport_mask);
}

#define merge_flow_match(field, src, dst)                   \
    if (!is_all_zeros(&src->wc.masks.field,                 \
                      sizeof src->wc.masks.field) &&        \
        is_all_zeros(&dst->wc.masks.field,                  \
                     sizeof dst->wc.masks.field)) {         \
        memcpy(&dst->flow.field, &src->flow.field,          \
               sizeof src->flow.field);                     \
        memcpy(&dst->wc.masks.field, &src->wc.masks.field,  \
               sizeof src->wc.masks.field);                 \
    }

static void
e2e_cache_merge_match(struct e2e_cache_ovs_flow **netdev_flows,
                      uint16_t num, struct match *merged_match)
{
    struct e2e_cache_ovs_flow *flow;
    struct match match_on_stack;
    const struct match *match;
    uint16_t i = 0;
    bool tnl_saved = false;

    memset(merged_match, 0, sizeof *merged_match);

    for (i = 0; i < num; i++) {
        flow = netdev_flows[i];
        if (i > 0 && flow->offload_state != E2E_OL_STATE_FLOW &&
            netdev_flows[i - 1]->offload_state != E2E_OL_STATE_FLOW) {
            continue;
        }
        /* parse match */
        if (flow->offload_state == E2E_OL_STATE_FLOW) {
            match = &flow->match[0];
        } else {
            dp_netdev_fill_ct_match(&match_on_stack, &flow->ct_match[0]);
            match = &match_on_stack;
        }
        if (!tnl_saved && !is_all_zeros(&match->wc.masks.tunnel,
                                        sizeof match->wc.masks.tunnel)) {
            e2e_cache_shift_tnl_fields(merged_match);
            tnl_saved = true;
        }
        /* merge in_port */
        merge_flow_match(in_port, match, merged_match);

        /* merge tunnel outer */
        merge_flow_match(tunnel.ip_src, match, merged_match);
        merge_flow_match(tunnel.ip_dst, match, merged_match);
        merge_flow_match(tunnel.ipv6_src, match, merged_match);
        merge_flow_match(tunnel.ipv6_dst, match, merged_match);
        merge_flow_match(tunnel.tun_id, match, merged_match);
        merge_flow_match(tunnel.tp_dst, match, merged_match);

        /* merge inner/non-tnl */
        merge_flow_match(dl_src, match, merged_match);
        merge_flow_match(dl_dst, match, merged_match);
        merge_flow_match(dl_type, match, merged_match);
        merge_flow_match(nw_src, match, merged_match);
        merge_flow_match(nw_dst, match, merged_match);
        merge_flow_match(ipv6_src, match, merged_match);
        merge_flow_match(ipv6_dst, match, merged_match);
        merge_flow_match(nw_frag, match, merged_match);
        merge_flow_match(nw_proto, match, merged_match);
        merge_flow_match(tp_src, match, merged_match);
        merge_flow_match(tp_dst, match, merged_match);
    }
}

static int
e2e_cache_merge_flows(struct e2e_cache_ovs_flow **flows,
                      uint16_t num_flows,
                      struct e2e_cache_merged_flow *merged_flow,
                      struct ofpbuf *merged_actions)
{
    if (!e2e_cache_flows_are_valid(flows, num_flows)) {
        e2e_stats.merge_rej_flows++;
        return -1;
    }
    e2e_cache_merge_match(flows, num_flows, &merged_flow->match);
    dp_netdev_get_mega_ufid(&merged_flow->match, &merged_flow->ufid);
    uuid_set_bits_v4((struct uuid *) &merged_flow->ufid, UUID_ATTR_3);
    e2e_cache_merge_actions(flows, num_flows, merged_actions);
    if (OVS_UNLIKELY(merged_actions->size < sizeof(struct nlattr))) {
        e2e_stats.merge_rej_flows++;
        return -1;
    }
    e2e_stats.succ_merged_flows++;
    return 0;
}
#endif /* E2E_CACHE_ENABLED */
