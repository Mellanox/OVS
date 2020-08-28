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

#ifndef MPSC_QUEUE_H
#define MPSC_QUEUE_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <openvswitch/thread.h>
#include <openvswitch/util.h>

#include "ovs-atomic.h"

/* Multi-producer, single-consumer queue
 * =====================================
 *
 * This data structure is a lockless queue implementation with
 * the following properties:
 *
 *  * Multi-producer: multiple threads can write concurrently.
 *    Insertion in the queue is thread-safe, no inter-thread
 *    synchronization is necessary.
 *
 *  * Single-consumer: only a single thread can safely remove
 *    nodes from the queue.  The queue must be 'acquired' using
 *    'mpsc_queue_acquire()' before removing nodes.
 *
 *  * Unbounded: the queue is backed by a linked-list and is not
 *    limited in number of elements.
 *
 *  * Intrusive: queue elements are allocated as part of larger
 *    objects.  Objects are retrieved by offset manipulation.
 *
 *  * per-producer FIFO: Elements in the queue are kept in the
 *    order their producer inserted them.  The consumer retrieves
 *    them in in the same insertion order.  When multiple
 *    producers insert at the same time, either will proceed.
 *
 * This queue is well-suited for message passing between threads,
 * where any number of thread can insert a message and a single
 * thread is meant to receive and process them.
 *
 * Thread-safety
 * =============
 *
 *  The consumer thread must acquire the queue using 'mpsc_queue_acquire()'.
 *  If no error is returned, the thread can call 'mpsc_queue_poll()'.
 *  When a thread is finished with reading the queue, it can release the
 *  reader lock using 'mpsc_queue_release()'.
 *
 *  Producers can always insert elements in the queue, even if no consumer
 *  acquired the reader lock.  No inter-producer synchronization (e.g. using a
 *  lock) is needed.
 *
 *  The consumer thread is also allowed to insert elements while it holds the
 *  reader lock.
 *
 *  Producer threads must never be cancelled while writing to the queue.
 *  This will block the consumer, that will then lose any subsequent writes
 *  to the queue.  Producers should ideally be cooperatively managed or
 *  the queue insertion should be within non-cancellable sections.
 *
 * Queue state
 * ===========
 *
 *  When polling the queue, three states can be observed: 'empty', 'non-empty',
 *  and 'inconsistent'.  Three polling results are defined, respectively:
 *
 *   * MPSC_QUEUE_EMPTY: the queue is empty.
 *   * MPSC_QUEUE_ITEM: an item was available and has been removed.
 *   * MPSC_QUEUE_RETRY: the queue is inconsistent.
 *
 *  If 'MPSC_QUEUE_RETRY' is returned, then a producer has not yet finished
 *  writing to the queue and the list of nodes is not coherent.  The consumer
 *  can retry shortly to check if the producer has finished.
 *
 *  This behavior is the reason the removal function is called
 *  'mpsc_queue_poll()'.
 *
 */

struct mpsc_queue_node {
    ATOMIC(struct mpsc_queue_node *) next;
};

struct mpsc_queue {
    ATOMIC(struct mpsc_queue_node *) head;
    ATOMIC(struct mpsc_queue_node *) tail;
    struct mpsc_queue_node stub;
    struct ovs_mutex read_lock;
};

#define MPSC_QUEUE_INITIALIZER(Q) { \
    .head = ATOMIC_VAR_INIT(&(Q)->stub), \
    .tail = ATOMIC_VAR_INIT(&(Q)->stub), \
    .stub = { .next = ATOMIC_VAR_INIT(NULL) }, \
    .read_lock = OVS_MUTEX_INITIALIZER, \
}

/* Consumer API. */

/* Initialize the queue. Not necessary is 'MPSC_QUEUE_INITIALIZER' was used. */
void mpsc_queue_init(struct mpsc_queue *queue);
/* The reader lock must be released prior to destroying the queue. */
void mpsc_queue_destroy(struct mpsc_queue *queue);
/* Acquire the reader lock if 1 is returned. */
int mpsc_queue_acquire(struct mpsc_queue *queue);
/* Release the reader lock. */
void mpsc_queue_release(struct mpsc_queue *queue);

enum mpsc_queue_poll_result {
    /* Queue is empty. */
    MPSC_QUEUE_EMPTY,
    /* Polling the queue returned an item. */
    MPSC_QUEUE_ITEM,
    /* Data has been enqueued but one or more producer thread have not
     * finished writing it. The queue is in an inconsistent state.
     * Retrying shortly, if the producer threads are still active, will
     * return the data.
     */
    MPSC_QUEUE_RETRY,
};

/* Set 'node' to a removed item from the queue if 'MPSC_QUEUE_ITEM' is
 * returned, otherwise 'node' is not set.
 */
enum mpsc_queue_poll_result
mpsc_queue_poll(struct mpsc_queue *queue, struct mpsc_queue_node **node);

/* Producer API. */

void mpsc_queue_insert(struct mpsc_queue *queue, struct mpsc_queue_node *node);

#endif /* MPSC_QUEUE_H */
