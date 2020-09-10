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

#include "openvswitch/list.h"
#include "openvswitch/thread.h"
#include "openvswitch/util.h"
#include "ovs-atomic.h"
#include "llring.h"
#include "seq-pool.h"

#define SEQPOOL_CACHE_SIZE 32
BUILD_ASSERT_DECL(IS_POW2(SEQPOOL_CACHE_SIZE));

struct seq_node {
    struct ovs_list list_node;
    uint32_t id;
};

struct seq_pool {
    uint32_t next_id;
    struct llring **cache; /* per-user id cache. */
    size_t nb_user; /* Number of user threads. */
    struct ovs_mutex lock; /* Protects free_ids access. */
    struct ovs_list free_ids; /* Set of currently free IDs. */
    uint32_t base; /* IDs in the range of [base, base + n_ids). */
    uint32_t n_ids; /* Total number of ids in the pool. */
};

struct seq_pool *
seq_pool_create(unsigned int nb_user, uint32_t base, uint32_t n_ids)
{
    struct seq_pool *pool;
    size_t i;

    ovs_assert(nb_user != 0);
    ovs_assert(base <= UINT32_MAX - n_ids);

    pool = xmalloc(sizeof *pool);

    pool->cache = xcalloc(nb_user, sizeof *pool->cache);
    for (i = 0; i < nb_user; i++) {
        pool->cache[i] = llring_create(SEQPOOL_CACHE_SIZE);
    }
    pool->nb_user = nb_user;

    pool->next_id = base;
    pool->base = base;
    pool->n_ids = n_ids;

    ovs_mutex_init(&pool->lock);
    ovs_list_init(&pool->free_ids);

    return pool;
}

void
seq_pool_destroy(struct seq_pool *pool)
{
    struct seq_node *node;
    struct seq_node *next;
    size_t i;

    if (!pool) {
        return;
    }

    ovs_mutex_lock(&pool->lock);
    LIST_FOR_EACH_SAFE (node, next, list_node, &pool->free_ids) {
        free(node);
    }
    ovs_list_poison(&pool->free_ids);
    ovs_mutex_unlock(&pool->lock);
    ovs_mutex_destroy(&pool->lock);

    for (i = 0; i < pool->nb_user; i++) {
        llring_destroy(pool->cache[i]);
    }
    free(pool->cache);

    free(pool);
}

bool
seq_pool_new_id(struct seq_pool *pool, unsigned int uid, uint32_t *id)
{
    struct llring *cache;
    struct ovs_list *front;
    struct seq_node *node;

    uid %= pool->nb_user;
    cache = pool->cache[uid];

    if (llring_dequeue(cache, id)) {
        return true;
    }

    ovs_mutex_lock(&pool->lock);

    while (!ovs_list_is_empty(&pool->free_ids)) {
        front = ovs_list_front(&pool->free_ids);
        node = CONTAINER_OF(front, struct seq_node, list_node);
        if (llring_enqueue(cache, node->id)) {
            ovs_list_remove(front);
            free(node);
        } else {
            break;
        }
    }

    while (pool->next_id < pool->base + pool->n_ids) {
        if (llring_enqueue(cache, pool->next_id)) {
            pool->next_id++;
        } else {
            break;
        }
    }

    ovs_mutex_unlock(&pool->lock);

    if (llring_dequeue(cache, id)) {
        return true;
    } else {
        struct llring *c2;
        size_t i;

        /* If no ID was available either from shared counter,
         * free-list or local cache, steal an ID from another
         * user cache.
         */
        for (i = 0; i < pool->nb_user; i++) {
            if (i == uid) {
                continue;
            }
            c2 = pool->cache[i];
            if (llring_dequeue(c2, id)) {
                return true;
            }
        }
    }

    return false;
}

void
seq_pool_free_id(struct seq_pool *pool, unsigned int uid, uint32_t id)
{
    struct seq_node *nodes[SEQPOOL_CACHE_SIZE + 1];
    struct llring *cache;
    uint32_t node_id;
    size_t i;

    if (id < pool->base || id >= pool->base + pool->n_ids) {
        return;
    }

    uid %= pool->nb_user;
    cache = pool->cache[uid];

    if (llring_enqueue(cache, id)) {
        return;
    }

    /* Flush the cache. */
    for (i = 0; llring_dequeue(cache, &node_id); i++) {
        nodes[i] = xmalloc(sizeof *nodes[i]);
        nodes[i]->id = node_id;
    }

    /* Finish with the last freed node. */
    nodes[i] = xmalloc(sizeof **nodes);
    nodes[i]->id = id;
    i++;

    if (i < ARRAY_SIZE(nodes)) {
        nodes[i] = NULL;
    }

    ovs_mutex_lock(&pool->lock);
    for (i = 0; i < ARRAY_SIZE(nodes) && nodes[i] != NULL; i++) {
        ovs_list_push_back(&pool->free_ids, &nodes[i]->list_node);
    }
    ovs_mutex_unlock(&pool->lock);
}
