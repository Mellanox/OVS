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

#include <limits.h>
#include <string.h>
#include <stdint.h>

#include <config.h>

#include "openvswitch/util.h"
#include "salloc.h"

struct salloc *
salloc_init(void *mem, size_t sz)
{
    struct salloc *s = mem;

    /* If this triggers, the scratch buffer is too small. */
    ovs_assert(sz > sizeof *s);
    s->sz = sz - sizeof *s;
    salloc_reset(s);
    return s;
}

void
salloc_reset(struct salloc *s)
{
    uintptr_t start = (uintptr_t)s->mem;
    size_t aligned;

    start = ROUND_UP((uintptr_t) s->mem, SALLOC_ALIGNMENT);
    aligned = (start - (uintptr_t) s->mem);
    /* If this triggers, the scratch buffer is too small. */
    ovs_assert(aligned < s->sz);
    s->pos = aligned;
    s->prev_len = 0;
}

void *
srealloc(struct salloc *s, void *prev, size_t n)
{
    char *p = prev;
    size_t next;

    n = ROUND_UP(n, SALLOC_ALIGNMENT);
    next = s->pos + n;
    /* Do not overflow. */
    ovs_assert(s->pos <= next);

    if (p != NULL && &p[s->prev_len] == &s->mem[s->pos]) {
        /* p was the last allocated chunk. It can grow or shrink. */
        s->pos -= s->prev_len;
        next = s->pos + n;
    } else {
        p = &s->mem[s->pos];
    }

    if (n == 0 || next > s->sz) {
        return NULL;
    }

    s->prev_len = n;
    if (prev != NULL && prev != p) {
        /* Copying 'n' bytes from 'prev' would be incorrect if it wasn't
         * coming from a known space that we are certain that we can read.
         * If 'n' is larger than the size of 'prev', it still has been
         * allocated further in the scratch memory, meaning that 'prev'
         * distance from the end of the scratch is more than 'n'.
         * Copying the whole length should be fine, some extra data might
         * be appended to 'p'.
         */
        memcpy(p, prev, n);
    }

    s->pos = next;
    return p;
}

void *
salloc(struct salloc *s, size_t n)
{
    return srealloc(s, NULL, n);
}

void *
szalloc(struct salloc *s, size_t n)
{
    void *m = salloc(s, n);

    if (m != NULL) {
        memset(m, 0, n);
    }
    return m;
}

void *
scalloc(struct salloc *s, size_t n, size_t sz)
{
    if (sz && n > (size_t) -1 / sz) {
        return NULL;
    }
    return szalloc(s, n * sz);
}
