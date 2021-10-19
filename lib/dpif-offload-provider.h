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

#ifndef DPIF_OFFLOAD_PROVIDER_H
#define DPIF_OFFLOAD_PROVIDER_H

struct dpif;
struct dpif_offload_sflow;

/* Datapath interface offload structure, to be defined by each implementation
 * of a datapath interface.
 */
struct dpif_offload_class {
    /* Type of dpif offload in this class, e.g. "system", "netdev", etc.
     *
     * One of the providers should supply a "system" type, since this is
     * the type assumed if no type is specified when opening a dpif. */
    const char *type;

    /* Called when the dpif offload provider is registered. */
    int (*init)(void);

    /* Free all dpif offload resources. */
    void (*destroy)(void);

    /* Arranges for the poll loop for an upcall handler to wake up when psample
     * has a message queued to be received. */
    void (*sflow_recv_wait)(void);

    /* Polls for an upcall from psample for an upcall handler.
     * Return 0 for success. */
    int (*sflow_recv)(struct dpif_offload_sflow *sflow);
};

void dpif_offload_sflow_recv_wait(const struct dpif *dpif);
int dpif_offload_sflow_recv(const struct dpif *dpif,
                            struct dpif_offload_sflow *sflow);

#endif /* DPIF_OFFLOAD_PROVIDER_H */
