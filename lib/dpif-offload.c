/*
 * Copyright (c) 2021, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#include <errno.h>

#include "dpif-provider.h"
#include "openvswitch/shash.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload);

static const struct dpif_offload_class *base_dpif_offload_classes[] = {
#if defined(__linux__)
    &dpif_offload_netlink_class,
#endif
    &dpif_offload_netdev_class,
};

struct registered_dpif_offload_class {
    const struct dpif_offload_class *offload_class;
    int refcount;
};
static struct shash dpif_offload_classes =
    SHASH_INITIALIZER(&dpif_offload_classes);

/* Protects 'dpif_offload_classes', including the refcount. */
static struct ovs_mutex dpif_offload_mutex = OVS_MUTEX_INITIALIZER;

void
dp_offload_initialize(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        for (int i = 0; i < ARRAY_SIZE(base_dpif_offload_classes); i++) {
            dp_offload_register_provider(base_dpif_offload_classes[i]);
        }
        ovsthread_once_done(&once);
    }
}

static int
dp_offload_register_provider__(const struct dpif_offload_class *new_class)
    OVS_REQUIRES(dpif_offload_mutex)
{
    struct registered_dpif_offload_class *registered_class;
    int error;

    if (shash_find(&dpif_offload_classes, new_class->type)) {
        VLOG_WARN("Attempted to register duplicate datapath offload "
                  "provider: %s", new_class->type);
        return EEXIST;
    }

    error = new_class->init ? new_class->init() : 0;
    if (error) {
        VLOG_WARN("Failed to initialize %s datapath offload class: %s",
                  new_class->type, ovs_strerror(error));
        return error;
    }

    registered_class = xmalloc(sizeof *registered_class);
    registered_class->offload_class = new_class;
    registered_class->refcount = 0;

    shash_add(&dpif_offload_classes, new_class->type, registered_class);

    return 0;
}

void dpif_offload_close(struct dpif *dpif)
{
    if (dpif->offload_class) {
        struct registered_dpif_offload_class *rc;

        rc = shash_find_data(&dpif_offload_classes, dpif->offload_class->type);
        dp_offload_class_unref(rc);
    }
}

int
dp_offload_register_provider(const struct dpif_offload_class *new_class)
{
    int error;

    ovs_mutex_lock(&dpif_offload_mutex);
    error = dp_offload_register_provider__(new_class);
    ovs_mutex_unlock(&dpif_offload_mutex);

    return error;
}

/* Unregisters an offload datapath provider.  'type' must have been previously
 * registered and not currently be in use by any dpifs.  After unregistration
 * new offload datapaths of that type cannot be opened using dpif_open(). */
static int
dp_offload_unregister_provider__(const char *type)
    OVS_REQUIRES(dpif_offload_mutex)
{
    struct shash_node *node;
    struct registered_dpif_offload_class *registered_class;

    node = shash_find(&dpif_offload_classes, type);
    if (!node) {
        return EAFNOSUPPORT;
    }

    registered_class = node->data;
    if (registered_class->refcount) {
        VLOG_WARN("Attempted to unregister in use offload datapath provider: "
                  "%s", type);
        return EBUSY;
    }

    if (registered_class->offload_class->destroy) {
        registered_class->offload_class->destroy();
    }
    shash_delete(&dpif_offload_classes, node);
    free(registered_class);

    return 0;
}

/* Unregisters an offload datapath provider.  'type' must have been previously
 * registered and not currently be in use by any dpifs.  After unregistration
 * new offload datapaths of that type cannot be opened using dpif_open(). */
int
dp_offload_unregister_provider(const char *type)
{
    int error;

    dp_offload_initialize();

    ovs_mutex_lock(&dpif_offload_mutex);
    error = dp_offload_unregister_provider__(type);
    ovs_mutex_unlock(&dpif_offload_mutex);

    return error;
}

void
dp_offload_class_unref(struct registered_dpif_offload_class *rc)
{
    ovs_mutex_lock(&dpif_offload_mutex);
    ovs_assert(rc->refcount);
    rc->refcount--;
    ovs_mutex_unlock(&dpif_offload_mutex);
}

struct registered_dpif_offload_class *
dp_offload_class_lookup(const char *type)
{
    struct registered_dpif_offload_class *rc;

    ovs_mutex_lock(&dpif_offload_mutex);
    rc = shash_find_data(&dpif_offload_classes, type);
    if (rc) {
        rc->refcount++;
    }
    ovs_mutex_unlock(&dpif_offload_mutex);

    return rc;
}

void
dpif_offload_sflow_recv_wait(const struct dpif *dpif)
{
    const struct dpif_offload_class *offload_class = dpif->offload_class;

    if (offload_class && offload_class->sflow_recv_wait) {
        offload_class->sflow_recv_wait();
    }
}

int
dpif_offload_sflow_recv(const struct dpif *dpif,
                        struct dpif_offload_sflow *sflow)
{
    const struct dpif_offload_class *offload_class = dpif->offload_class;

    if (offload_class && offload_class->sflow_recv) {
        return offload_class->sflow_recv(sflow);
    }

    return EOPNOTSUPP;
}

int dpif_offload_meter_set(const struct dpif *dpif, ofproto_meter_id meter_id,
                           struct ofputil_meter_config *config)
{
    const struct dpif_offload_class *offload_class = dpif->offload_class;

    if (offload_class && offload_class->meter_set) {
        return offload_class->meter_set(meter_id, config);
    }

    return EOPNOTSUPP;
}

int dpif_offload_meter_get(const struct dpif *dpif, ofproto_meter_id meter_id,
                           struct ofputil_meter_stats *stats,
                           uint16_t max_band)
{
    const struct dpif_offload_class *offload_class = dpif->offload_class;

    if (offload_class && offload_class->meter_get) {
        return offload_class->meter_get(meter_id, stats, max_band);
    }

    return EOPNOTSUPP;
}

int dpif_offload_meter_del(const struct dpif *dpif, ofproto_meter_id meter_id,
                           struct ofputil_meter_stats *stats,
                           uint16_t max_band)
{
    const struct dpif_offload_class *offload_class = dpif->offload_class;

    if (offload_class && offload_class->meter_del) {
        return offload_class->meter_del(meter_id, stats, max_band);
    }

    return EOPNOTSUPP;
}
