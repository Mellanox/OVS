/*
 * Copyright (c) 2021 NVIDIA Corporation.
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

#ifndef SALLOC_H
#define SALLOC_H 1

#include <errno.h>
#include <stdlib.h>

#include "util.h"

/* Scratch allocator.
 *
 * Transform a block of memory into an allocator.
 * The allocator is dead-simple and meant only for short flexible building
 * of objects. There is only one way to free the allocated memory, which is to
 * reset the whole allocator.
 *
 * It can be used to replace a number of transient memory allocations
 * previously using a global persistent allocator. The overhead is lower due to
 * simplicity and the memory can be isolated, helping multi-thread workload.
 *
 * Usage:
 *
 * Declare or allocate a block of memory, then transform it into an allocator:
 *
 * {
 *    char scratch[4096];
 *    struct salloc *s = salloc_init(scratch, sizeof scratch);
 *    int *entries;
 *
 *    entries = xsalloc(s, 10 * sizeof *entries);
 *    entries[0] = 42;
 *    entries[9] = -1;
 *
 *    // Memory is allocated within 'scratch'.
 *    // It can be used until 'salloc_reset(s)' is called.
 *
 *    salloc_reset(s);
 *
 *    // The allocator can be re-used.
 *    entries = xsalloc(s, 20 * sizeof *entries);
 * }
 */

struct salloc {
    size_t sz;
    size_t pos;
    size_t prev_len;
    char mem[0];
};

#define SALLOC_ALIGNMENT (sizeof(void *))

struct salloc *salloc_init(void *mem, size_t sz);
void salloc_reset(struct salloc *s);

void *salloc(struct salloc *s, size_t n);
void *szalloc(struct salloc *s, size_t n);
void *scalloc(struct salloc *s, size_t n, size_t sz);
void *srealloc(struct salloc *s, void *p, size_t n);

static inline void
out_of_scratch_memory(struct salloc *s, size_t n)
{
    ovs_abort(ENOMEM, "scratch memory exhausted: requested %"
              PRIuSIZE ", has %" PRIuSIZE,
              s->pos + ROUND_UP(n, SALLOC_ALIGNMENT),
              s->sz);
}

static inline void *
xsalloc(struct salloc *s, size_t n)
{
    void *p = salloc(s, n ? n : 1);

    if (p == NULL) {
        out_of_scratch_memory(s, n);
    }
    return p;
}

static inline void *
xszalloc(struct salloc *s, size_t n)
{
    void *p = szalloc(s, n ? n : 1);

    if (p == NULL) {
        out_of_scratch_memory(s, n);
    }
    return p;
}

static inline void *
xscalloc(struct salloc *s, size_t n, size_t sz)
{
    void *p = n && sz ? scalloc(s, n, sz) : salloc(s, 1);

    if (p == NULL) {
        out_of_scratch_memory(s, n);
    }
    return p;
}

static inline void *
xsrealloc(struct salloc *s, void *p, size_t n)
{
    p = srealloc(s, p, n ? n : 1);
    if (p == NULL) {
        out_of_scratch_memory(s, n);
    }
    return p;
}

#endif /* SALLOC_H */
