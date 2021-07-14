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

#include "dpif.h"
#include "dpif-offload-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_netdev);

/* Currently, it is used only for dummy netdev to make tests pass. */
const struct dpif_offload_class dpif_offload_netdev_class = {
    .type = "netdev",
    .init = NULL,
    .destroy = NULL,
    .sflow_recv_wait = NULL,
    .sflow_recv = NULL,
};

void
dpif_offload_dummy_register(const char *type)
{
    struct dpif_offload_class *class;

    class = xmalloc(sizeof *class);
    *class = dpif_offload_netdev_class;
    class->type = xstrdup(type);
    dp_offload_register_provider(class);
}
