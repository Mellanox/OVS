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
#include "guarded-list.h"
#include "mpsc-queue.h"
#include "openvswitch/list.h"
#include "openvswitch/util.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "timeval.h"
#include "util.h"

struct element {
    union {
        struct mpsc_queue_node mpscq;
        struct ovs_list list;
    } node;
    uint64_t mark;
};

static void
test_mpsc_queue_mark_element(struct mpsc_queue_node *node,
                             uint64_t mark,
                             unsigned int *counter)
{
    struct element *elem;

    elem = CONTAINER_OF(node, struct element, node.mpscq);
    elem->mark = mark;
    *counter += 1;
}

static void
test_mpsc_queue_insert(void)
{
    struct element elements[100];
    struct mpsc_queue_node *node;
    struct mpsc_queue queue;
    unsigned int counter;
    size_t i;

    memset(elements, 0, sizeof(elements));
    mpsc_queue_init(&queue);
    ignore(mpsc_queue_acquire(&queue));

    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        mpsc_queue_insert(&queue, &elements[i].node.mpscq);
    }

    counter = 0;
    while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
        test_mpsc_queue_mark_element(node, 1, &counter);
    }

    mpsc_queue_release(&queue);
    mpsc_queue_destroy(&queue);

    ovs_assert(counter == ARRAY_SIZE(elements));
    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        ovs_assert(elements[i].mark == 1);
    }

    printf(".");
}

static void
test_mpsc_queue_flush_is_fifo(void)
{
    struct element elements[100];
    struct mpsc_queue_node *node;
    struct mpsc_queue queue;
    unsigned int counter;
    size_t i;

    memset(elements, 0, sizeof(elements));

    mpsc_queue_init(&queue);
    ignore(mpsc_queue_acquire(&queue));

    for (i = 0; i < ARRAY_SIZE(elements); i++) {
        mpsc_queue_insert(&queue, &elements[i].node.mpscq);
    }

    /* Elements are in the same order in the list as they
     * were declared / initialized.
     */
    counter = 0;
    while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
        test_mpsc_queue_mark_element(node, counter, &counter);
    }

    /* The list is valid once extracted from the queue,
     * the queue can be destroyed here.
     */
    mpsc_queue_release(&queue);
    mpsc_queue_destroy(&queue);

    for (i = 0; i < ARRAY_SIZE(elements) - 1; i++) {
        struct element *e1, *e2;

        e1 = &elements[i];
        e2 = &elements[i + 1];

        ovs_assert(e1->mark < e2->mark);
    }

    printf(".");
}

static void
run_tests(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    /* Verify basic insertion worked. */
    test_mpsc_queue_insert();
    /* Verify flush() happens in FIFO if configured. */
    test_mpsc_queue_flush_is_fifo();
    printf(" success\n");
}

static struct element *elements;
static uint64_t *thread_working_ms; /* Measured work time. */

static unsigned int n_threads;
static unsigned int n_elems;

static struct ovs_barrier barrier;
static volatile bool working;

static int
elapsed(const struct timeval *start)
{
    struct timeval end;

    xgettimeofday(&end);
    return timeval_to_msec(&end) - timeval_to_msec(start);
}

struct mpscq_aux {
    struct mpsc_queue *queue;
    atomic_uint thread_id;
};

static void *
mpsc_queue_insert_thread(void *aux_)
{
    unsigned int n_elems_per_thread;
    struct element *th_elements;
    struct mpscq_aux *aux = aux_;
    struct timeval start;
    unsigned int id;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &id);
    n_elems_per_thread = n_elems / n_threads;
    th_elements = &elements[id * n_elems_per_thread];

    ovs_barrier_block(&barrier);
    xgettimeofday(&start);

    for (i = 0; i < n_elems_per_thread; i++) {
        mpsc_queue_insert(aux->queue, &th_elements[i].node.mpscq);
    }

    thread_working_ms[id] = elapsed(&start);
    ovs_barrier_block(&barrier);

    working = false;

    return NULL;
}

static void
benchmark_mpsc_queue(void)
{
    struct mpsc_queue_node *node;
    struct mpsc_queue queue;
    struct timeval start;
    unsigned int counter;
    bool work_complete;
    pthread_t *threads;
    struct mpscq_aux aux;
    uint64_t epoch;
    uint64_t avg;
    size_t i;

    memset(elements, 0, n_elems & sizeof *elements);
    memset(thread_working_ms, 0, n_threads & sizeof *thread_working_ms);

    mpsc_queue_init(&queue);

    aux.queue = &queue;
    atomic_store(&aux.thread_id, 0);

    for (i = n_elems - (n_elems % n_threads); i < n_elems; i++) {
        mpsc_queue_insert(&queue, &elements[i].node.mpscq);
    }

    working = true;

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("sc_queue_insert",
                                       mpsc_queue_insert_thread, &aux);
    }

    ignore(mpsc_queue_acquire(&queue));
    xgettimeofday(&start);

    counter = 0;
    epoch = 1;
    do {
        while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
            test_mpsc_queue_mark_element(node, epoch, &counter);
        }
        if (epoch == UINT64_MAX) {
            epoch = 0;
        }
        epoch++;
    } while (working);

    avg = 0;
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
        avg += thread_working_ms[i];
    }
    avg /= n_threads;

    /* Elements might have been inserted before threads were joined. */
    while (mpsc_queue_poll(&queue, &node) == MPSC_QUEUE_ITEM) {
        test_mpsc_queue_mark_element(node, epoch, &counter);
    }

    printf("  mpsc-queue:  %6d", elapsed(&start));
    for (i = 0; i < n_threads; i++) {
        printf(" %6" PRIu64, thread_working_ms[i]);
    }
    printf(" %6" PRIu64 " ms\n", avg);

    mpsc_queue_release(&queue);
    mpsc_queue_destroy(&queue);
    ovs_barrier_destroy(&barrier);
    free(threads);

    work_complete = true;
    for (i = 0; i < n_elems; i++) {
        if (elements[i].mark == 0) {
            printf("Element %" PRIuSIZE " was never consumed.\n", i);
            work_complete = false;
        }
    }
    ovs_assert(work_complete);
    ovs_assert(counter == n_elems);
}

struct list_aux {
    struct ovs_list *list;
    struct ovs_mutex *lock;
    atomic_uint thread_id;
};

static void *
locked_list_insert_thread(void *aux_)
{
    unsigned int n_elems_per_thread;
    struct element *th_elements;
    struct list_aux *aux = aux_;
    struct timeval start;
    unsigned int id;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &id);
    n_elems_per_thread = n_elems / n_threads;
    th_elements = &elements[id * n_elems_per_thread];

    ovs_barrier_block(&barrier);
    xgettimeofday(&start);

    for (i = 0; i < n_elems_per_thread; i++) {
        ovs_mutex_lock(aux->lock);
        ovs_list_push_front(aux->list, &th_elements[i].node.list);
        ovs_mutex_unlock(aux->lock);
    }

    thread_working_ms[id] = elapsed(&start);
    ovs_barrier_block(&barrier);

    working = false;

    return NULL;
}

static void
benchmark_list(void)
{
    struct ovs_mutex lock;
    struct ovs_list list;
    struct element *elem;
    struct timeval start;
    unsigned int counter;
    bool work_complete;
    pthread_t *threads;
    struct list_aux aux;
    uint64_t epoch;
    uint64_t avg;
    size_t i;

    memset(elements, 0, n_elems * sizeof *elements);
    memset(thread_working_ms, 0, n_threads * sizeof *thread_working_ms);

    ovs_mutex_init(&lock);
    ovs_list_init(&list);

    aux.list = &list;
    aux.lock = &lock;
    atomic_store(&aux.thread_id, 0);

    ovs_mutex_lock(&lock);
    for (i = n_elems - (n_elems % n_threads); i < n_elems; i++) {
        ovs_list_push_front(&list, &elements[i].node.list);
    }
    ovs_mutex_unlock(&lock);

    working = true;

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("locked_list_insert",
                                       locked_list_insert_thread, &aux);
    }

    xgettimeofday(&start);

    counter = 0;
    epoch = 1;
    do {
        ovs_mutex_lock(&lock);
        LIST_FOR_EACH_POP (elem, node.list, &list) {
            elem->mark = epoch;
            counter++;
        }
        ovs_mutex_unlock(&lock);
        if (epoch == UINT64_MAX) {
            epoch = 0;
        }
        epoch++;
    } while (working);

    avg = 0;
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
        avg += thread_working_ms[i];
    }
    avg /= n_threads;

    /* Elements might have been inserted before threads were joined. */
    ovs_mutex_lock(&lock);
    LIST_FOR_EACH_POP (elem, node.list, &list) {
        elem->mark = epoch;
        counter++;
    }
    ovs_mutex_unlock(&lock);

    printf("        list:  %6d", elapsed(&start));
    for (i = 0; i < n_threads; i++) {
        printf(" %6" PRIu64, thread_working_ms[i]);
    }
    printf(" %6" PRIu64 " ms\n", avg);
    ovs_barrier_destroy(&barrier);
    free(threads);

    work_complete = true;
    for (i = 0; i < n_elems; i++) {
        if (elements[i].mark == 0) {
            printf("Element %" PRIuSIZE " was never consumed.\n", i);
            work_complete = false;
        }
    }
    ovs_assert(work_complete);
    ovs_assert(counter == n_elems);
}

struct guarded_list_aux {
    struct guarded_list *glist;
    atomic_uint thread_id;
};

static void *
guarded_list_insert_thread(void *aux_)
{
    unsigned int n_elems_per_thread;
    struct element *th_elements;
    struct guarded_list_aux *aux = aux_;
    struct timeval start;
    unsigned int id;
    size_t i;

    atomic_add(&aux->thread_id, 1u, &id);
    n_elems_per_thread = n_elems / n_threads;
    th_elements = &elements[id * n_elems_per_thread];

    ovs_barrier_block(&barrier);
    xgettimeofday(&start);

    for (i = 0; i < n_elems_per_thread; i++) {
        guarded_list_push_back(aux->glist, &th_elements[i].node.list, n_elems);
    }

    thread_working_ms[id] = elapsed(&start);
    ovs_barrier_block(&barrier);

    working = false;

    return NULL;
}

static void
benchmark_guarded_list(void)
{
    struct guarded_list_aux aux;
    struct ovs_list extracted;
    struct guarded_list glist;
    struct element *elem;
    struct timeval start;
    unsigned int counter;
    bool work_complete;
    pthread_t *threads;
    uint64_t epoch;
    uint64_t avg;
    size_t i;

    memset(elements, 0, n_elems * sizeof *elements);
    memset(thread_working_ms, 0, n_threads * sizeof *thread_working_ms);

    guarded_list_init(&glist);
    ovs_list_init(&extracted);

    aux.glist = &glist;
    atomic_store(&aux.thread_id, 0);

    for (i = n_elems - (n_elems % n_threads); i < n_elems; i++) {
        guarded_list_push_back(&glist, &elements[i].node.list, n_elems);
    }

    working = true;

    threads = xmalloc(n_threads * sizeof *threads);
    ovs_barrier_init(&barrier, n_threads);

    for (i = 0; i < n_threads; i++) {
        threads[i] = ovs_thread_create("guarded_list_insert",
                                       guarded_list_insert_thread, &aux);
    }

    xgettimeofday(&start);

    counter = 0;
    epoch = 1;
    do {
        guarded_list_pop_all(&glist, &extracted);
        LIST_FOR_EACH_POP (elem, node.list, &extracted) {
            elem->mark = epoch;
            counter++;
        }
        if (epoch == UINT64_MAX) {
            epoch = 0;
        }
        epoch++;
    } while (working);

    avg = 0;
    for (i = 0; i < n_threads; i++) {
        xpthread_join(threads[i], NULL);
        avg += thread_working_ms[i];
    }
    avg /= n_threads;

    /* Elements might have been inserted before threads were joined. */
    guarded_list_pop_all(&glist, &extracted);
    LIST_FOR_EACH_POP (elem, node.list, &extracted) {
        elem->mark = epoch;
        counter++;
    }

    printf("guarded list:  %6d", elapsed(&start));
    for (i = 0; i < n_threads; i++) {
        printf(" %6" PRIu64, thread_working_ms[i]);
    }
    printf(" %6" PRIu64 " ms\n", avg);
    ovs_barrier_destroy(&barrier);
    free(threads);
    guarded_list_destroy(&glist);

    work_complete = true;
    for (i = 0; i < n_elems; i++) {
        if (elements[i].mark == 0) {
            printf("Element %" PRIuSIZE " was never consumed.\n", i);
            work_complete = false;
        }
    }
    ovs_assert(work_complete);
    ovs_assert(counter == n_elems);
}

static void
run_benchmarks(struct ovs_cmdl_context *ctx)
{
    long int l_threads;
    long int l_elems;
    size_t i;

    l_elems = strtol(ctx->argv[1], NULL, 10);
    l_threads = strtol(ctx->argv[2], NULL, 10);
    ovs_assert(l_elems > 0 && l_threads > 0);

    n_elems = l_elems;
    n_threads = l_threads;

    elements = xcalloc(n_elems, sizeof *elements);
    thread_working_ms = xcalloc(n_threads, sizeof *thread_working_ms);

    printf("Benchmarking n=%u on 1 + %u threads.\n", n_elems, n_threads);

    printf(" type\\thread:  Reader ");
    for (i = 0; i < n_threads; i++) {
        printf("   %3" PRIuSIZE " ", i + 1);
    }
    printf("   Avg\n");

    benchmark_mpsc_queue();
    benchmark_list();
    benchmark_guarded_list();

    free(thread_working_ms);
    free(elements);
}

static const struct ovs_cmdl_command commands[] = {
    {"check", NULL, 0, 0, run_tests, OVS_RO},
    {"benchmark", "<nb elem> <nb threads>", 2, 2, run_benchmarks, OVS_RO},
    {NULL, NULL, 0, 0, NULL, OVS_RO},
};

static void
test_mpsc_queue_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - optind,
        .argv = argv + optind,
    };

    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-mpsc-queue", test_mpsc_queue_main);
