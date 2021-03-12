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

#include <config.h>
#undef NDEBUG
#include "openvswitch/poll-loop.h"
#include "ovs-rcu.h"
#include "ovs-thread.h"
#include "ovstest.h"
#include "seq.h"
#include "timeval.h"
#include "util.h"

struct element {
    struct ovsrcu_gc_node gc_node;
    struct seq *trigger;
    volatile bool wait;
};

static void
do_gc(struct element *e)
{
    seq_change(e->trigger);
}

static void *
wait_main(void *aux)
{
    struct element *e = aux;

    while (e->wait) {
        ;
    }

    seq_wait(e->trigger, seq_read(e->trigger));
    poll_block();

    return NULL;
}

static void
test_rcu_gc_main(bool multithread)
{
    long long int timeout;
    pthread_t waiter;
    struct element e;
    uint64_t seqno;

    e.wait = true;

    if (multithread) {
        waiter = ovs_thread_create("waiter", wait_main, &e);
    }

    e.trigger = seq_create();
    seqno = seq_read(e.trigger);

    ovsrcu_gc(do_gc, &e, gc_node);

    /* Check that GC holds out until all threads quiesced. */
    timeout = time_msec();
    if (multithread) {
        timeout += 200;
    }
    while (time_msec() <= timeout) {
        ovs_assert(seq_read(e.trigger) == seqno);
    }

    e.wait = false;

    seq_wait(e.trigger, seqno);
    poll_timer_wait_until(time_msec() + 200);
    poll_block();

    /* Verify that GC executed. */
    ovs_assert(seq_read(e.trigger) != seqno);
    seq_destroy(e.trigger);

    if (multithread) {
        xpthread_join(waiter, NULL);
    }
}

static void
test_rcu_gc(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const bool multithread = true;

    test_rcu_gc_main(!multithread);
    test_rcu_gc_main(multithread);
}

OVSTEST_REGISTER("test-rcu-gc", test_rcu_gc);
