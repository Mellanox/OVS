/* Copyright (c) 2017 Red Hat, Inc.
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
#include "bfd.h"
#include "gchassis.h"
#include "lport.h"
#include "ovn-controller.h"

#include "lib/hash.h"
#include "lib/sset.h"
#include "lib/util.h"
#include "lib/vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn-controller.h"

VLOG_DEFINE_THIS_MODULE(ovn_bfd);

void
bfd_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    /* NOTE: this assumes that binding.c has added the
     * ovsrec_interface table */
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
}

void
bfd_calculate_active_tunnels(const struct ovsrec_bridge *br_int,
                             struct sset *active_tunnels)
{
    int i;

    if (!br_int) {
        /* Nothing to do if integration bridge doesn't exist. */
        return;
    }

    for (i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];

        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }

        int j;
        for (j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec;
            iface_rec = port_rec->interfaces[j];

            /* Check if this is a tunnel interface. */
            if (smap_get(&iface_rec->options, "remote_ip")) {
                /* Add ovn-chassis-id if the bfd_status of the tunnel
                 * is active */
                const char *bfd = smap_get(&iface_rec->bfd, "enable");
                if (bfd && !strcmp(bfd, "true")) {
                    const char *status = smap_get(&iface_rec->bfd_status,
                                                  "state");
                    if (status && !strcmp(status, "up")) {
                        const char *id = smap_get(&port_rec->external_ids,
                                                  "ovn-chassis-id");
                        if (id) {
                            char *chassis_name;
                            char *save_ptr = NULL;
                            char *tokstr = xstrdup(id);
                            chassis_name = strtok_r(tokstr, OVN_MVTEP_CHASSISID_DELIM, &save_ptr);
                            if (chassis_name && !sset_contains(active_tunnels, chassis_name)) {
                                sset_add(active_tunnels, chassis_name);
                            }
                            free(tokstr);
                        }
                    }
                }
            }
        }
    }
}

struct local_datapath_node {
    struct ovs_list node;
    const struct local_datapath *dp;
};

static void
bfd_travel_gw_related_chassis(
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    const struct local_datapath *dp,
    const struct hmap *local_datapaths,
    struct sset *bfd_chassis)
{
    struct ovs_list dp_list;
    const struct sbrec_port_binding *pb;
    struct sset visited_dp = SSET_INITIALIZER(&visited_dp);
    const char *dp_key;
    struct local_datapath_node *dp_binding;

    if (!(dp_key = smap_get(&dp->datapath->external_ids, "logical-router")) &&
        !(dp_key = smap_get(&dp->datapath->external_ids, "logical-switch"))) {
        VLOG_INFO("datapath has no uuid, cannot travel graph");
        return;
    }

    sset_add(&visited_dp, dp_key);

    ovs_list_init(&dp_list);
    dp_binding = xmalloc(sizeof *dp_binding);
    dp_binding->dp = dp;
    ovs_list_push_back(&dp_list, &dp_binding->node);

    struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
        sbrec_port_binding_by_datapath);

    /* Go through whole graph to figure out all chassis which may deliver
     * packets to gateway. */
    LIST_FOR_EACH_POP (dp_binding, node, &dp_list) {
        dp = dp_binding->dp;
        free(dp_binding);
        for (size_t i = 0; i < dp->n_peer_dps; i++) {
            const struct sbrec_datapath_binding *pdp = dp->peer_dps[i];
            if (!pdp) {
                continue;
            }

            if (!(dp_key = smap_get(&pdp->external_ids, "logical-router")) &&
                !(dp_key = smap_get(&pdp->external_ids, "logical-switch"))) {
                continue;
            }

            if (sset_contains(&visited_dp, dp_key)) {
                continue;
            }

            sset_add(&visited_dp, dp_key);

            struct hmap_node *node = hmap_first_with_hash(local_datapaths,
                                                          pdp->tunnel_key);
            if (!node) {
                continue;
            }

            dp_binding = xmalloc(sizeof *dp_binding);
            dp_binding->dp = CONTAINER_OF(node, struct local_datapath,
                                          hmap_node);
            ovs_list_push_back(&dp_list, &dp_binding->node);

            sbrec_port_binding_index_set_datapath(target, pdp);
            SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                               sbrec_port_binding_by_datapath) {
                if (pb->chassis) {
                    const char *chassis_name = pb->chassis->name;
                    if (chassis_name) {
                        sset_add(bfd_chassis, chassis_name);
                    }
                }
            }
        }
    }
    sbrec_port_binding_index_destroy_row(target);

    sset_destroy(&visited_dp);
}

static struct ovs_list *
bfd_find_ha_gateway_chassis(
    struct ovsdb_idl_index *sbrec_chassis_by_name,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    const struct sbrec_datapath_binding *datapath)
{
    struct sbrec_port_binding *target = sbrec_port_binding_index_init_row(
        sbrec_port_binding_by_datapath);
    sbrec_port_binding_index_set_datapath(target, datapath);

    struct ovs_list *ha_gateway_chassis = NULL;
    const struct sbrec_port_binding *pb;
    SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, target,
                                       sbrec_port_binding_by_datapath) {
        if (strcmp(pb->type, "chassisredirect")) {
            continue;
        }

        struct ovs_list *gateway_chassis = gateway_chassis_get_ordered(
            sbrec_chassis_by_name, pb);
        if (!gateway_chassis || ovs_list_is_short(gateway_chassis)) {
            /* We don't need BFD for non-HA chassisredirect. */
            gateway_chassis_destroy(gateway_chassis);
            continue;
        }

        ha_gateway_chassis = gateway_chassis;
        break;
    }
    sbrec_port_binding_index_destroy_row(target);
    return ha_gateway_chassis;
}

static void
bfd_calculate_chassis(
    struct ovsdb_idl_index *sbrec_chassis_by_name,
    struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
    const struct sbrec_chassis *our_chassis,
    const struct hmap *local_datapaths,
    struct sset *bfd_chassis)
{
    /* Identify all chassis nodes to which we need to enable bfd.
     * 1) Any chassis hosting the chassisredirect ports for known
     *    router datapaths.
     * 2) Chassis hosting peer datapaths (with ports) connected
     *    to a router datapath  when our chassis is hosting a router
     *    with a chassis redirect port. */

    const struct local_datapath *dp;
    HMAP_FOR_EACH (dp, hmap_node, local_datapaths) {
        const char *is_router = smap_get(&dp->datapath->external_ids,
                                         "logical-router");
        bool our_chassis_is_gw_for_dp = false;
        if (is_router) {
            struct ovs_list *ha_gateway_chassis
                = bfd_find_ha_gateway_chassis(sbrec_chassis_by_name,
                                              sbrec_port_binding_by_datapath,
                                              dp->datapath);
            if (ha_gateway_chassis) {
                our_chassis_is_gw_for_dp = gateway_chassis_contains(
                    ha_gateway_chassis, our_chassis);
                struct gateway_chassis *gwc;
                LIST_FOR_EACH (gwc, node, ha_gateway_chassis) {
                    if (gwc->db->chassis) {
                        sset_add(bfd_chassis, gwc->db->chassis->name);
                    }
                }
                gateway_chassis_destroy(ha_gateway_chassis);
            }
        }
        if (our_chassis_is_gw_for_dp) {
            bfd_travel_gw_related_chassis(sbrec_port_binding_by_datapath,
                                          dp, local_datapaths, bfd_chassis);
        }
    }
}

void
bfd_run(struct ovsdb_idl_index *sbrec_chassis_by_name,
        struct ovsdb_idl_index *sbrec_port_binding_by_datapath,
        const struct ovsrec_interface_table *interface_table,
        const struct ovsrec_bridge *br_int,
        const struct sbrec_chassis *chassis_rec,
        const struct sbrec_sb_global_table *sb_global_table,
        const struct hmap *local_datapaths)
{

    if (!chassis_rec) {
        return;
    }
    struct sset bfd_chassis = SSET_INITIALIZER(&bfd_chassis);
    bfd_calculate_chassis(sbrec_chassis_by_name,
                          sbrec_port_binding_by_datapath,
                          chassis_rec, local_datapaths, &bfd_chassis);
    /* Identify tunnels ports(connected to remote chassis id) to enable bfd */
    struct sset tunnels = SSET_INITIALIZER(&tunnels);
    struct sset bfd_ifaces = SSET_INITIALIZER(&bfd_ifaces);
    for (size_t k = 0; k < br_int->n_ports; k++) {
        const char *tunnel_id = smap_get(&br_int->ports[k]->external_ids,
                                          "ovn-chassis-id");
        if (tunnel_id) {
            char *chassis_name;
            char *save_ptr = NULL;
            char *tokstr = xstrdup(tunnel_id);
            char *port_name = br_int->ports[k]->name;

            sset_add(&tunnels, port_name);
            chassis_name = strtok_r(tokstr, OVN_MVTEP_CHASSISID_DELIM, &save_ptr);
            if (chassis_name && sset_contains(&bfd_chassis, chassis_name)) {
                sset_add(&bfd_ifaces, port_name);
            }
            free(tokstr);
        }
    }

    const struct sbrec_sb_global *sb
        = sbrec_sb_global_table_first(sb_global_table);
    struct smap bfd = SMAP_INITIALIZER(&bfd);
    smap_add(&bfd, "enable", "true");

    if (sb) {
        const char *min_rx = smap_get(&sb->options, "bfd-min-rx");
        const char *decay_min_rx = smap_get(&sb->options, "bfd-decay-min-rx");
        const char *min_tx = smap_get(&sb->options, "bfd-min-tx");
        const char *mult = smap_get(&sb->options, "bfd-mult");
        if (min_rx) {
            smap_add(&bfd, "min_rx", min_rx);
        }
        if (decay_min_rx) {
            smap_add(&bfd, "decay_min_rx", decay_min_rx);
        }
        if (min_tx) {
            smap_add(&bfd, "min_tx", min_tx);
        }
        if (mult) {
            smap_add(&bfd, "mult", mult);
        }
    }

    /* Enable or disable bfd */
    const struct ovsrec_interface *iface;
    OVSREC_INTERFACE_TABLE_FOR_EACH (iface, interface_table) {
        if (sset_contains(&tunnels, iface->name)) {
            if (sset_contains(&bfd_ifaces, iface->name)) {
                /* We need to enable BFD for this interface. Configure the
                 * BFD params if
                 *  - If BFD was disabled earlier
                 *  - Or if CMS has updated BFD config options.
                 */
                if (!smap_equal(&iface->bfd, &bfd)) {
                    ovsrec_interface_verify_bfd(iface);
                    ovsrec_interface_set_bfd(iface, &bfd);
                    VLOG_INFO("Enabled BFD on interface %s", iface->name);
                }
            } else {
                /* We need to disable BFD for this interface if it was enabled
                 * earlier. */
                if (smap_count(&iface->bfd)) {
                    ovsrec_interface_verify_bfd(iface);
                    ovsrec_interface_set_bfd(iface, NULL);
                    VLOG_INFO("Disabled BFD on interface %s", iface->name);
                }
            }
         }
    }

    smap_destroy(&bfd);
    sset_destroy(&tunnels);
    sset_destroy(&bfd_ifaces);
    sset_destroy(&bfd_chassis);
}
