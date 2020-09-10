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

#ifndef SEQ_POOL_H
#define SEQ_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Sequential ID pool.
 * ===================
 *
 * Pool of unique 32bits IDs.
 *
 * Multiple users are registered at initialization.  Each user uses a cache
 * of ID.  When each thread using the pool uses its own user ID, the pool
 * scales reasonably for concurrent allocation.
 *
 * New IDs are always in the range of '[base, next_id]', where 'next_id' is
 * in the range of '[last_alloc_ID + nb_user * cache_size + 1]'.
 * This means that a new ID is not always the smallest available ID, but it is
 * still from a limited range.
 *
 * Users should ensure that an ID is *never* freed twice.  Not doing so will
 * have the effect of double-allocating such ID afterward.
 *
 * Thread-safety
 * =============
 *
 * APIs are thread safe.
 *
 * Multiple threads can share the same user ID if necessary, but it can hurt
 * performance if threads are not otherwise synchronized.
 */

struct seq_pool;

/* nb_user is the number of expected users of the pool,
 * in terms of execution threads. */
struct seq_pool *seq_pool_create(unsigned int nb_user,
                                 uint32_t base, uint32_t n_ids);
void seq_pool_destroy(struct seq_pool *pool);

/* uid is the thread user-id. It should be within '[0, nb_user['. */
bool seq_pool_new_id(struct seq_pool *pool, unsigned int uid, uint32_t *id);

/* uid is the thread user-id. It should be within '[0, nb_user['.
 * An allocated ID must *never* be freed twice.
 */
void seq_pool_free_id(struct seq_pool *pool, unsigned int uid, uint32_t id);
#endif  /* seq-pool.h */
