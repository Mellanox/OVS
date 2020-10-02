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

#include <stdint.h>
#include <stdbool.h>

#include "ovs-atomic.h"

/* Bounded lockless queue
 * ======================
 *
 * A lockless FIFO queue bounded to a known size.
 * Each operation (insert, remove) uses one CAS().
 *
 * The structure is:
 *
 *   Multi-producer: multiple threads can write to it
 *   concurrently.
 *
 *   Multi-consumer: multiple threads can read from it
 *   concurrently.
 *
 *   Bounded: the queue is backed by external memory.
 *   No new allocation is made on insertion, only the
 *   used elements in the queue are marked as such.
 *   The boundary of the queue is defined as the size given
 *   at init, which must be a power of two.
 *
 *   Failing: when an operation (enqueue, dequeue) cannot
 *   be performed due to the queue being full/empty, the
 *   operation immediately fails, instead of waiting on
 *   a state change.
 *
 *   Non-intrusive: queue elements are allocated prior to
 *   initialization.  Data is shallow-copied to those
 *   allocated elements.
 *
 * Thread safety
 * =============
 *
 * The queue is thread-safe for MPMC case.
 * No lock is taken by the queue.  The queue guarantees
 * lock-free forward progress for each of its operations.
 *
 */

/* Create a circular lockless ring.
 * The 'size' parameter must be a power-of-two higher than 2,
 * otherwise allocation will fail.
 */
struct llring;
struct llring *llring_create(uint32_t size);

/* Free a lockless ring. */
void llring_destroy(struct llring *r);

/* 'data' is copied to the latest free slot in the queue. */
bool llring_enqueue(struct llring *r, uint32_t data);

/* The value within the oldest slot taken in the queue is copied
 * to the address pointed by 'data'.
 */
bool llring_dequeue(struct llring *r, uint32_t *data);
