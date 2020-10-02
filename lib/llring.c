/*
 * Copyright (c) 2020 NVIDIA Corporation.
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

#include "ovs-atomic.h"

#include "llring.h"

/* A queue element.
 * User must allocate an array of such elements, which must
 * have more than 2 elements and should be of a power-of-two
 * size.
 */
struct llring_node {
    atomic_uint32_t seq;
    uint32_t data;
};

/* A ring description.
 * The head and tail of the ring are padded to avoid false-sharing,
 * which improves slightly multi-thread performance, at the cost
 * of some memory.
 */
struct llring {
    PADDED_MEMBERS(CACHE_LINE_SIZE, atomic_uint32_t head;);
    PADDED_MEMBERS(CACHE_LINE_SIZE, atomic_uint32_t tail;);
    uint32_t mask;
    struct llring_node nodes[0];
};

struct llring *
llring_create(uint32_t size)
{
    struct llring *r;
    uint32_t i;

    if (size < 2 || !IS_POW2(size)) {
        return NULL;
    }

    r = xmalloc(sizeof *r + size * sizeof r->nodes[0]);

    r->mask = size - 1;
    for (i = 0; i < size; i++) {
        atomic_store_relaxed(&r->nodes[i].seq, i);
    }
    atomic_store_relaxed(&r->head, 0);
    atomic_store_relaxed(&r->tail, 0);

    return r;
}

void
llring_destroy(struct llring *r)
{
    free(r);
}

bool
llring_enqueue(struct llring *r, uint32_t data)
{
    struct llring_node *node;
    uint32_t pos;

    atomic_read_relaxed(&r->head, &pos);
    while (true) {
        int64_t diff;
        uint32_t seq;

        node = &r->nodes[pos & r->mask];
        atomic_read_explicit(&node->seq, &seq, memory_order_acquire);
        diff = (int64_t)seq - (int64_t)pos;

        if (diff < 0) {
            /* Current ring[head].seq is from previous ring generation,
             * ring is full and enqueue fails. */
            return false;
        }

        if (diff == 0) {
            /* If head == ring[head].seq, then the slot is free,
             * attempt to take it by moving the head, if no one moved it since.
             */
            if (atomic_compare_exchange_weak_explicit(&r->head, &pos, pos + 1,
                                                      memory_order_relaxed,
                                                      memory_order_relaxed)) {
                break;
            }
        } else {
            /* Someone changed the head since last read, retry. */
            atomic_read_relaxed(&r->head, &pos);
        }
    }

    node->data = data;
    atomic_store_explicit(&node->seq, pos + 1, memory_order_release);
    return true;
}

bool
llring_dequeue(struct llring *r, uint32_t *data)
{
    struct llring_node *node;
    uint32_t pos;

    atomic_read_relaxed(&r->tail, &pos);
    while (true) {
        int64_t diff;
        uint32_t seq;

        node = &r->nodes[pos & r->mask];
        atomic_read_explicit(&node->seq, &seq, memory_order_acquire);
        diff = (int64_t)seq - (int64_t)(pos + 1);

        if (diff < 0) {
            /* Current ring[tail + 1].seq is from previous ring generation,
             * ring is empty and dequeue fails. */
            return false;
        }

        if (diff == 0) {
            /* If tail + 1 == ring[tail + 1].seq, then the slot is allocated,
             * attempt to free it by moving the tail, if no one moved it since.
             */
            if (atomic_compare_exchange_weak_explicit(&r->tail, &pos, pos + 1,
                                                      memory_order_relaxed,
                                                      memory_order_relaxed)) {
                break;
            }
        } else {
            /* Someone changed the tail since last read, retry. */
            atomic_read_relaxed(&r->tail, &pos);
        }
    }

    *data = node->data;
    /* Advance the slot to next gen by add r->mask to its sequence. */
    atomic_store_explicit(&node->seq, pos + r->mask + 1, memory_order_release);
    return true;
}
