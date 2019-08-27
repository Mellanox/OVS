/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
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

#ifndef DPIF_NETDEV_H
#define DPIF_NETDEV_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "dpif.h"
#include "openvswitch/types.h"
#include "dp-packet.h"
#include "packets.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Enough headroom to add a vlan tag, plus an extra 2 bytes to allow IP
 * headers to be aligned on a 4-byte boundary.  */
enum { DP_NETDEV_HEADROOM = 2 + VLAN_HEADER_LEN };

bool dpif_is_netdev(const struct dpif *);

#define NR_QUEUE   1
#define NR_PMD_THREADS 1

#ifdef  __cplusplus
}
#endif

#define FLOW_MARK_UPPER_SHIFT    24
#define FLOW_MARK_UPPER_MASK     ((1 << FLOW_MARK_UPPER_SHIFT) - 1)
#define INVALID_FLOW_MARK        (UINT32_MAX)
#define MAX_FLOW_MARK            FLOW_MARK_UPPER_MASK
#define RESERVED_FLOW_MARK_SIZE  (64)
#define MIN_FLOW_MARK            RESERVED_FLOW_MARK_SIZE
#define AVAILABLE_FLOW_MARK_SIZE (MAX_FLOW_MARK - MIN_FLOW_MARK + 1)
#define MIN_RESERVED_MARK        1
#define MAX_RESERVED_MARK        (RESERVED_FLOW_MARK_SIZE - 1)

#endif /* netdev.h */
