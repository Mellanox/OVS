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

#include <stdint.h>

#include <config.h>

#include "ovstest.h"
#include "salloc.h"
#include "util.h"

/* Return X rounded up to the nearest multiple of Y.
 * A specialized version of ROUND_UP, limited to power-of-twos.
 */
#define ALIGNED(X, Y) (((X) + ((Y)-1)) & ~((Y)-1))
#define ALIGNED_PTR(X) ((void *) ALIGNED((uintptr_t) (X), SALLOC_ALIGNMENT))
#define MAGIC 0xabcdabcd

static void
test_salloc_basic(void)
{
    char scratch[200];
    struct salloc *s = salloc_init(scratch, sizeof scratch);
    char *ptrs[10];
    size_t i;

    ovs_assert(salloc(s, 0) == NULL);
    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ptrs[i] = xsalloc(s, 1);
        ovs_assert(salloc_contains(s, ptrs[i]));
        ovs_assert(ALIGNED_PTR(ptrs[i]) == ptrs[i]);
        ovs_assert(ptrs[i] >= &scratch[0]);
        ovs_assert(ptrs[i] < &scratch[sizeof scratch]);
    }

    salloc_reset(s);

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ovs_assert(ptrs[i] == xsalloc(s, 1));
    }
}

static void
test_salloc_oom(void)
{
    struct {
        uint32_t before;
        char scratch[100];
        uint32_t after;
    } mem = {
        .before = MAGIC,
        .after = MAGIC,
    };
    struct salloc *s = salloc_init(mem.scratch, sizeof mem.scratch);
    char *ptrs[20];
    size_t i, nb_alloc;

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ptrs[i] = salloc(s, 1);
        if (ptrs[i] == NULL) {
            break;
        }
        ovs_assert(ptrs[i] >= &mem.scratch[0]);
        ovs_assert(ptrs[i] < &mem.scratch[sizeof mem.scratch]);
    }
    /* We should get OOM before the end of the array. */
    ovs_assert(i < ARRAY_SIZE(ptrs));
    nb_alloc = i;

    salloc_reset(s);

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ptrs[i] = salloc(s, 1);
        if (ptrs[i] == NULL) {
            break;
        }
    }
    /* Same number of allocations possible. */
    ovs_assert(i == nb_alloc);

    salloc_reset(s);

    for (i = sizeof(mem.scratch); i > 0; i--) {
        ptrs[0] = salloc(s, i);
        if (ptrs[0] != NULL) {
            break;
        }
    }
    ovs_assert(i != 0);
    memset(ptrs[0], 0xaa, i);
    ovs_assert(mem.before == MAGIC);
    ovs_assert(mem.after == MAGIC);
}

static void
test_salloc_unaligned(void)
{
    struct {
        char pad[1];
        char scratch[200];
    } unaligned;
    struct salloc *s = salloc_init(unaligned.scratch,
                                   sizeof unaligned.scratch);
    char *ptrs[10];
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ptrs[i] = xsalloc(s, 10);
        ovs_assert(ALIGNED_PTR(ptrs[i]) == ptrs[i]);
    }

    salloc_reset(s);

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ovs_assert(ptrs[i] == xsalloc(s, 10));
    }
}

static void
test_salloc(void)
{
    test_salloc_basic();
    test_salloc_oom();
    test_salloc_unaligned();
}

static void
test_szalloc(void)
{
    struct {
        uint32_t before;
        char scratch[200];
        uint32_t after;
    } mem = {
        .before = MAGIC,
        .after = MAGIC,
    };
    struct salloc *s = salloc_init(mem.scratch, sizeof mem.scratch);
    char zeroes[10] = {0};
    char *ptrs[10];
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ptrs[i] = xszalloc(s, 10);
        ovs_assert(ALIGNED_PTR(ptrs[i]) == ptrs[i]);
        ovs_assert(ptrs[i] >= &mem.scratch[0]);
        ovs_assert(ptrs[i] < &mem.scratch[sizeof mem.scratch]);
        ovs_assert(memcmp(ptrs[i], zeroes, 10) == 0);
        memset(ptrs[i], 0x5a, 10);
    }

    salloc_reset(s);

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ovs_assert(ptrs[i] == xszalloc(s, 10));
        ovs_assert(memcmp(ptrs[i], zeroes, 10) == 0);
    }

    ovs_assert(mem.before == MAGIC);
    ovs_assert(mem.after == MAGIC);
}

static void
test_scalloc(void)
{
    struct {
        uint32_t before;
        char scratch[200];
        uint32_t after;
    } mem = {
        .before = MAGIC,
        .after = MAGIC,
    };
    struct salloc *s = salloc_init(mem.scratch, sizeof mem.scratch);
    char zeroes[10] = {0};
    char *ptrs[10];
    size_t i;

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ptrs[i] = xscalloc(s, 1, sizeof zeroes);
        ovs_assert(ALIGNED_PTR(ptrs[i]) == ptrs[i]);
        ovs_assert(ptrs[i] >= &mem.scratch[0]);
        ovs_assert(ptrs[i] < &mem.scratch[sizeof mem.scratch]);
        ovs_assert(memcmp(ptrs[i], zeroes, 10) == 0);
        memset(ptrs[i], 0x5a, 10);
    }

    salloc_reset(s);

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ovs_assert(ptrs[i] == xscalloc(s, 1, sizeof zeroes));
        ovs_assert(memcmp(ptrs[i], zeroes, 10) == 0);
    }

    ovs_assert(mem.before == MAGIC);
    ovs_assert(mem.after == MAGIC);
}

static void
test_srealloc(void)
{
    char scratch[200];
    struct salloc *s = salloc_init(scratch, sizeof scratch);
    char *ptrs[10];
    char ones[8];
    size_t i;

    ovs_assert(srealloc(s, NULL, 0) == NULL);
    memset(ptrs, 0, sizeof ptrs);
    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        ptrs[i] = xsrealloc(s, ptrs[i], 1);
        ovs_assert(xsrealloc(s, ptrs[i], 2) == ptrs[i]);
        ovs_assert(xsrealloc(s, ptrs[i], 9) == ptrs[i]);
        /* Realloc can shrink. */
        ovs_assert(xsrealloc(s, ptrs[i], 1) == ptrs[i]);
        ovs_assert(xsrealloc(s, ptrs[i], 8) == ptrs[i]);
    }

    for (i = 0; i < ARRAY_SIZE(ptrs); i++) {
        memset(ptrs[i], (i + 1) & 0xff, 8);
    }
    memset(ones, 0x01, sizeof ones);

    ptrs[0] = xsrealloc(s, ptrs[0], 10);
    ovs_assert(memcmp(ptrs[0], ones, sizeof ones) == 0);
}

static void
test_salloc_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    test_salloc();
    test_szalloc();
    test_scalloc();
    test_srealloc();
}

OVSTEST_REGISTER("test-salloc", test_salloc_main);
