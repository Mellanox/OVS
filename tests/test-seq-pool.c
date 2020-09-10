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

#undef NDEBUG
#include <assert.h>
#include <getopt.h>
#include <string.h>

#include <config.h>

#include "command-line.h"
#include "id-pool.h"
#include "openvswitch/util.h"
#include "ovs-thread.h"
#include "ovs-rcu.h"
#include "ovstest.h"
#include "random.h"
#include "seq-pool.h"
#include "timeval.h"
#include "util.h"

#define SEQ_POOL_CACHE_SIZE 32

#define N_IDS 100

static void
test_seq_pool_alloc_full_range(void)
{
    bool ids[N_IDS];
    struct seq_pool *pool;
    size_t i;

    memset(ids, 0, sizeof ids);
    pool = seq_pool_create(1, 0, N_IDS);

    for (i = 0; i < N_IDS; i++) {
        uint32_t id;

        ovs_assert(seq_pool_new_id(pool, 0, &id));
        /* No double alloc.*/
        ovs_assert(ids[id] == false);
        ids[id] = true;
    }

    for (i = 0; i < N_IDS; i++) {
        ovs_assert(ids[i]);
    }

    seq_pool_destroy(pool);
    printf(".");
}

static void
test_seq_pool_alloc_steal(void)
{
    /* N must be less than a pool cache size to force the second user
     * to steal from the first.
     */
    const unsigned int N = SEQ_POOL_CACHE_SIZE / 4;
    bool ids[N];
    struct seq_pool *pool;
    uint32_t id;
    size_t i;

    memset(ids, 0, sizeof ids);
    pool = seq_pool_create(2, 0, N);

    /* Fill up user 0 cache. */
    ovs_assert(seq_pool_new_id(pool, 0, &id));
    for (i = 0; i < N - 1; i++) {
        /* Check that user 1 can still alloc from user 0 cache. */
        ovs_assert(seq_pool_new_id(pool, 1, &id));
    }

    seq_pool_destroy(pool);
    printf(".");
}

static void
test_seq_pool_alloc_monotonic(void)
{
    uint32_t ids[N_IDS];
    struct seq_pool *pool;
    size_t i;

    memset(ids, 0, sizeof ids);
    pool = seq_pool_create(1, 0, N_IDS);

    for (i = 0; i < N_IDS; i++) {
        ovs_assert(seq_pool_new_id(pool, 0, &ids[i]));
        ovs_assert(ids[i] == i);
    }

    seq_pool_destroy(pool);
    printf(".");
}

static void
test_seq_pool_alloc_under_limit(void)
{
    uint32_t ids[N_IDS];
    unsigned int limit;
    struct seq_pool *pool;
    size_t i;

    memset(ids, 0, sizeof ids);
    pool = seq_pool_create(1, 0, N_IDS);

    for (limit = 1; limit < N_IDS; limit++) {
        /* Allocate until arbitrary limit then free allocated ids. */
        for (i = 0; i < limit; i++) {
            ovs_assert(seq_pool_new_id(pool, 0, &ids[i]));
        }
        for (i = 0; i < limit; i++) {
            seq_pool_free_id(pool, 0, ids[i]);
        }
        /* Verify that the N='limit' next allocations are under limit. */
        for (i = 0; i < limit; i++) {
            ovs_assert(seq_pool_new_id(pool, 0, &ids[i]));
            ovs_assert(ids[i] < limit + SEQ_POOL_CACHE_SIZE);
        }
        for (i = 0; i < limit; i++) {
            seq_pool_free_id(pool, 0, ids[i]);
        }
    }

    seq_pool_destroy(pool);
    printf(".");
}

static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Check that all ids can be allocated. */
    test_seq_pool_alloc_full_range();
    /* Check that all ids can be allocated with multiple users. */
    test_seq_pool_alloc_steal();
    /* Check that id allocation is always increasing. */
    test_seq_pool_alloc_monotonic();
    /* Check that id allocation stays under some limit. */
    test_seq_pool_alloc_under_limit();
    printf(" success\n");
}

static uint32_t *ids;
static uint64_t *thread_working_ms; /* Measured work time. */

static unsigned int n_threads;
static unsigned int n_ids;

static struct ovs_barrier barrier;

#define TIMEOUT_MS (10 * 1000) /* 10 sec timeout */
static int running_time_ms;
volatile bool stop = false;

static int
elapsed(int *start)
{
    return running_time_ms - *start;
}

static void
swap_u32(uint32_t *a, uint32_t *b)
{
    uint32_t t;
    t = *a;
    *a = *b;
    *b = t;
}

static void
shuffle(uint32_t *p, size_t n)
{
    for (; n > 1; n--, p++) {
        uint32_t *q = &p[random_range(n)];
        swap_u32(p, q);
    }
}

static void
print_result(const char *prefix)
{
    uint64_t avg;
    size_t i;

    avg = 0;
    for (i = 0; i < n_threads; i++) {
        avg += thread_working_ms[i];
    }
    avg /= n_threads;
    printf("%s: ", prefix);
    for (i = 0; i < n_threads; i++) {
        if (thread_working_ms[i] >= TIMEOUT_MS) {
            printf("%6" PRIu64 "+", thread_working_ms[i]);
        } else {
            printf(" %6" PRIu64, thread_working_ms[i]);
        }
    }
    if (avg >= TIMEOUT_MS) {
        printf(" ****** ms\n");
    } else {
        printf(" %6" PRIu64 " ms\n", avg);
    }
}

struct seq_pool_aux {
    struct seq_pool *pool;
    atomic_uint thread_id;
};

static void *
seq_pool_thread(void *aux_)
{
    unsigned int n_ids_per_thread;
    struct seq_pool_aux *aux = aux_;
    uint32_t *th_ids;
    unsigned int tid;
    int start;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &tid);
    n_ids_per_thread = n_ids / n_threads;
    th_ids = &ids[tid * n_ids_per_thread];

    /* NEW / ALLOC */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ignore(seq_pool_new_id(aux->pool, tid, &th_ids[i]));
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* DEL */

    shuffle(th_ids, n_ids_per_thread);

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        seq_pool_free_id(aux->pool, tid, th_ids[i]);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* MIX */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ignore(seq_pool_new_id(aux->pool, tid, &th_ids[i]));
        seq_pool_free_id(aux->pool, tid, th_ids[i]);
        ignore(seq_pool_new_id(aux->pool, tid, &th_ids[i]));
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* MIX SHUFFLED */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        if (elapsed(&start) >= TIMEOUT_MS) {
            break;
        }
        ignore(seq_pool_new_id(aux->pool, tid, &th_ids[i]));
        swap_u32(&th_ids[i], &th_ids[random_range(i + 1)]);
        seq_pool_free_id(aux->pool, tid, th_ids[i]);
        ignore(seq_pool_new_id(aux->pool, tid, &th_ids[i]));
    }
    thread_working_ms[tid] = elapsed(&start);

    return NULL;
}

static void
benchmark_seq_pool(void)
{
    pthread_t *threads;
    struct seq_pool_aux aux;
    size_t i;

    memset(ids, 0, n_ids & sizeof *ids);
    memset(thread_working_ms, 0, n_threads & sizeof *thread_working_ms);

    aux.pool = seq_pool_create(n_threads, 0, n_ids);
    atomic_store(&aux.thread_id, 0);

    for (i = n_ids - (n_ids % n_threads); i < n_ids; i++) {
        uint32_t id;

        seq_pool_new_id(aux.pool, 0, &id);
        ids[i] = id;
    }

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads + 1);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("seq_pool_alloc",
                                       seq_pool_thread, &aux);
    }

    ovs_barrier_block(&barrier);

    print_result("seq-pool new");

    ovs_barrier_block(&barrier);

    print_result("seq-pool del");

    ovs_barrier_block(&barrier);

    print_result("seq-pool mix");

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    print_result("seq-pool rnd");

    seq_pool_destroy(aux.pool);
    ovs_barrier_destroy(&barrier);
    free(threads);
}

struct id_pool_aux {
    struct id_pool *pool;
    struct ovs_mutex *lock;
    atomic_uint thread_id;
};

static void *
id_pool_thread(void *aux_)
{
    unsigned int n_ids_per_thread;
    struct id_pool_aux *aux = aux_;
    uint32_t *th_ids;
    unsigned int tid;
    int start;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &tid);
    n_ids_per_thread = n_ids / n_threads;
    th_ids = &ids[tid * n_ids_per_thread];

    /* NEW */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ovs_mutex_lock(aux->lock);
        ovs_assert(id_pool_alloc_id(aux->pool, &th_ids[i]));
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* DEL */

    shuffle(th_ids, n_ids_per_thread);

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ovs_mutex_lock(aux->lock);
        id_pool_free_id(aux->pool, th_ids[i]);
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* MIX */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        ovs_mutex_lock(aux->lock);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        id_pool_free_id(aux->pool, th_ids[i]);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    ovs_barrier_block(&barrier);

    /* MIX SHUFFLED */

    start = running_time_ms;
    for (i = 0; i < n_ids_per_thread; i++) {
        if (elapsed(&start) >= TIMEOUT_MS) {
            break;
        }
        ovs_mutex_lock(aux->lock);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        swap_u32(&th_ids[i], &th_ids[random_range(i + 1)]);
        id_pool_free_id(aux->pool, th_ids[i]);
        ignore(id_pool_alloc_id(aux->pool, &th_ids[i]));
        ovs_mutex_unlock(aux->lock);
    }
    thread_working_ms[tid] = elapsed(&start);

    return NULL;
}

static void
benchmark_id_pool(void)
{
    pthread_t *threads;
    struct id_pool_aux aux;
    struct ovs_mutex lock;
    size_t i;

    memset(ids, 0, n_ids & sizeof *ids);
    memset(thread_working_ms, 0, n_threads & sizeof *thread_working_ms);

    aux.pool = id_pool_create(0, n_ids);
    aux.lock = &lock;
    ovs_mutex_init(&lock);
    atomic_store(&aux.thread_id, 0);

    for (i = n_ids - (n_ids % n_threads); i < n_ids; i++) {
        id_pool_alloc_id(aux.pool, &ids[i]);
    }

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads + 1);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("id_pool_alloc", id_pool_thread, &aux);
    }

    ovs_barrier_block(&barrier);

    print_result(" id-pool new");

    ovs_barrier_block(&barrier);

    print_result(" id-pool del");

    ovs_barrier_block(&barrier);

    print_result(" id-pool mix");

    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
    }

    print_result(" id-pool rnd");

    id_pool_destroy(aux.pool);
    ovs_barrier_destroy(&barrier);
    free(threads);
}

static void *
clock_main(void *arg OVS_UNUSED)
{
    struct timeval start;
    struct timeval end;

    xgettimeofday(&start);
    while (!stop) {
        xgettimeofday(&end);
        running_time_ms = timeval_to_msec(&end) - timeval_to_msec(&start);
        xnanosleep(1000);
    }

    return NULL;
}

static void
run_benchmarks(struct ovs_cmdl_context *ctx)
{
    pthread_t clock;
    long int l_threads;
    long int l_ids;
    size_t i;

    l_ids = strtol(ctx->argv[1], NULL, 10);
    l_threads = strtol(ctx->argv[2], NULL, 10);
    ovs_assert(l_ids > 0 && l_threads > 0);

    n_ids = l_ids;
    n_threads = l_threads;

    ids = xcalloc(n_ids, sizeof *ids);
    thread_working_ms = xcalloc(n_threads, sizeof *thread_working_ms);

    clock = ovs_thread_create("clock", clock_main, NULL);

    printf("Benchmarking n=%u on %u thread%s.\n", n_ids, n_threads,
           n_threads > 1 ? "s" : "");

    printf(" type\\thread:  ");
    for (i = 0; i < n_threads; i++) {
        printf("   %3" PRIuSIZE " ", i + 1);
    }
    printf("   Avg\n");

    benchmark_seq_pool();
    benchmark_id_pool();

    stop = true;

    free(thread_working_ms);
    xpthread_join(clock, NULL);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 0, run_tests, OVS_RO},
    {"benchmark", "<nb elem> <nb threads>", 2, 2, run_benchmarks, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_seq_pool_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-seq-pool", test_seq_pool_main);
