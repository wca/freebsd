/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Will Andrews
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kthread.h>
#include <sys/counter.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/smr.h>
#include <sys/turnstile.h>
#include <machine/vmparam.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_phys.h>

#include <ck_epoch.h>

#define container_of(p, stype, field) \
	((stype *)(((uint8_t *)(p)) - offsetof(stype, field)))

static MALLOC_DEFINE(M_SMR, "smr", "smr");

struct smr_td_state;
struct smr_pcpu_state {
	smr_record_t sps_record;
	unsigned int sps_critnest;
	unsigned int sps_waiters;
} __aligned(CACHE_LINE_SIZE);

struct smr_domain {
	struct ck_epoch sd_epoch;
	struct smr_pcpu_state *sd_dom[MAXMEMDOM];
	smr_domain_notify_cb_t *sd_notify_cb;
	struct smr_pcpu_state *sd_pcpu[0];
};

static struct smr_domain *smr_global;
static __read_mostly struct lock_object smr_ts = {
	.lo_name = "smrts",
};

static struct cv smr_cv;
static struct mtx smr_mtx;
static struct proc *smr_global_proc;
static void sched_smr(void);
static struct kproc_desc smr_kp = {
	"smr_gc",
	sched_smr,
	&smr_global_proc,
};

/*
 * Sysctls for visibility.
 *
 * TODO Improve by including per-domain state, DTrace probes, etc.
 */
SYSCTL_NODE(_kern, OID_AUTO, smr, CTLFLAG_RW, 0, "smr information");
SYSCTL_NODE(_kern_smr, OID_AUTO, stats, CTLFLAG_RW, 0, "smr stats");
static counter_u64_t wait_count;
SYSCTL_COUNTER_U64(_kern_smr_stats, OID_AUTO, preemption_waits, CTLFLAG_RW,
    &wait_count, "# of times waited due to preemption");
static counter_u64_t yield_count;
SYSCTL_COUNTER_U64(_kern_smr_stats, OID_AUTO, yields, CTLFLAG_RW,
    &yield_count, "# of times yielded to other cpu");

struct smr_domain *
smr_global_domain(void)
{

	return smr_global;
}

static void
smr_global_notify(struct smr_domain *sd)
{

	/* Let the GC thread know there's work to do. */
	cv_broadcast(&smr_cv);
}

static void
sched_smr(void)
{
	struct timeval tv;
	struct smr_domain *sd;

	/* Wait at most 5 seconds between synchronizes. */
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	sd = smr_global_domain();
	for (;;) {
		smr_barrier(sd);

		mtx_lock(&smr_mtx);
		(void) cv_timedwait(&smr_cv, &smr_mtx, tvtohz(&tv));
		mtx_unlock(&smr_mtx);
	}
}

void
smr_begin(smr_domain_t *sd, smr_section_t *section)
{
	struct smr_pcpu_state *sps;

	critical_enter();
	sched_pin();
	sps = sd->sd_pcpu[curcpu];
	sps->sps_critnest++;
	ck_epoch_begin(&sps->sps_record, section);
	critical_exit();
}

void
smr_begin_nopreempt(smr_domain_t *sd, smr_section_t *section)
{
	struct smr_pcpu_state *sps;

	critical_enter();
	sps = sd->sd_pcpu[curcpu];
	ck_epoch_begin(&sps->sps_record, section);
}

static void
smr_turnstile_exit(struct smr_pcpu_state *sps)
{
	struct turnstile *ts;

	MPASS(curthread->td_critnest);
	if (__predict_true(sps->sps_waiters == 0))
		return;

	turnstile_chain_lock(&smr_ts);
	ts = turnstile_lookup(&smr_ts);
	if (ts != NULL) {
		turnstile_broadcast(ts, TS_SHARED_QUEUE);
		turnstile_unpend(ts, TS_SHARED_LOCK);
	}
	turnstile_chain_unlock(&smr_ts);
}

void
smr_end(smr_domain_t *sd, smr_section_t *section)
{
	struct smr_pcpu_state *sps;
	bool done;

	critical_enter();
	sps = sd->sd_pcpu[curcpu];
	MPASS(sps->sps_critnest);
	sched_unpin();
	done = ck_epoch_end(&sps->sps_record, section);
	sps->sps_critnest--;
	smr_turnstile_exit(sps);
	critical_exit();

	if (done && sd->sd_notify_cb != NULL)
		sd->sd_notify_cb(sd);
}

void
smr_end_nopreempt(smr_domain_t *sd, smr_section_t *section)
{
	struct smr_pcpu_state *sps;
	bool done;

	MPASS(curthread->td_critnest);
	sps = sd->sd_pcpu[curcpu];
	done = ck_epoch_end(&sps->sps_record, section);
	critical_exit();

	if (done && sd->sd_notify_cb != NULL)
		sd->sd_notify_cb(sd);
}

void
smr_call(smr_domain_t *sd, smr_entry_t *entry, smr_cb_t *fn)
{
	struct smr_pcpu_state *sps;

	/* This call requires pcpu association. */
	KASSERT(curthread->td_pinned > 0, ("curthread not pinned"));
	sps = sd->sd_pcpu[curcpu];
	ck_epoch_call(&sps->sps_record, entry, fn);
}

static void
smr_synchronize_cb(ck_epoch_t *epoch __unused, ck_epoch_record_t *record,
    void *arg __unused)
{
	struct smr_pcpu_state *sps;
	struct turnstile *ts;
	int yielded;

	sps = container_of(record, struct smr_pcpu_state, sps_record);
	while (ck_pr_load_uint(&sps->sps_critnest)) {
		counter_u64_add(wait_count, 1);
		ts = turnstile_trywait(&smr_ts);
		turnstile_wait(ts, NULL, TS_SHARED_QUEUE);
		yielded = 1;
	}
	if (!yielded) {
		counter_u64_add(yield_count, 1);
		kern_yield(PRI_UNCHANGED);
	}
}

void
smr_synchronize_wait(struct smr_domain *sd)
{
	struct smr_pcpu_state *sps;
	struct turnstile *ts;

	critical_enter();
	sched_pin();
	sps = sd->sd_pcpu[curcpu];
	ck_pr_inc_uint(&sps->sps_waiters);
	critical_exit();

	while (ck_pr_load_uint(&sps->sps_critnest))  {
		counter_u64_add(wait_count, 1);
		ts = turnstile_trywait(&smr_ts);
		turnstile_wait(ts, NULL, TS_SHARED_QUEUE);
	}
	ck_epoch_synchronize_wait(&sd->sd_epoch, smr_synchronize_cb, NULL);

	critical_enter();
	sched_unpin();
	ck_pr_dec_uint(&sps->sps_waiters);
	critical_exit();
}

static void
epoch_record_reclaims(struct ck_epoch_record *record, unsigned int n_reclaims)
{
	unsigned int n_peak;

	n_peak = ck_pr_load_uint(&record->n_peak);

	/* We don't require accuracy around peak calculation. */
	if (n_reclaims > n_peak)
		ck_pr_store_uint(&record->n_peak, n_peak);

	if (n_reclaims > 0) {
		ck_pr_add_uint(&record->n_dispatch, n_reclaims);
		ck_pr_sub_uint(&record->n_pending, n_reclaims);
	}

	return;
}

CK_STACK_CONTAINER(struct ck_epoch_entry, stack_entry,
    ck_epoch_entry_container)
static void
epoch_stack_dispatch(ck_stack_t *pending)
{
	ck_stack_entry_t *cursor, *next;
	unsigned int reclaims = 0;

	CK_STACK_FOREACH_SAFE(pending, cursor, next) {
		struct ck_epoch_entry *entry = ck_epoch_entry_container(cursor);

		next = CK_STACK_NEXT(cursor);
		entry->function(entry);
		reclaims++;
	}

	return;
}

static void
stack_batch_push_upmc(ck_stack_t *target, ck_stack_entry_t *head,
    unsigned int *n_entries)
{
	ck_stack_entry_t *last, *stack, *next;

	last = NULL;
	*n_entries = 0;
	for (next = head; next != NULL; next = CK_STACK_NEXT(next), (*n_entries)++)
		last = next;

	stack = ck_pr_load_ptr(&target->head);
	last->next = stack;
	ck_pr_fence_store();

	while (ck_pr_cas_ptr_value(&target->head, stack, head, &stack) == false) {
		last->next = stack;
		ck_pr_fence_store();
	}
}

static unsigned int
epoch_stack_pop(struct ck_epoch_record *record, ck_stack_t *pending)
{
	unsigned int epoch, reclaims, total;
	ck_stack_entry_t *cursor;

	for (total = epoch = 0; epoch < CK_EPOCH_LENGTH; epoch++) {
		reclaims = 0;
		cursor = ck_stack_batch_pop_upmc(&record->pending[epoch]);
		if (cursor == NULL)
			continue;
		stack_batch_push_upmc(pending, cursor, &reclaims);
		total += reclaims;
		epoch_record_reclaims(record, reclaims);
	}
	return total;
}

void
smr_barrier(smr_domain_t *sd)
{
	struct smr_pcpu_state *sps;
	ck_stack_t pending;
	int i, reclaims;

	/*
	 * Pop off every pending deferred object requested, synchronize,
	 * then dispatch all seen deferrals.
	 */
	ck_stack_init(&pending);
	CPU_FOREACH(i) {
		sps = sd->sd_pcpu[i];
		reclaims = epoch_stack_pop(&sps->sps_record, &pending);
	}

	smr_synchronize_wait(sd);

	epoch_stack_dispatch(&pending);
}

void
smr_domain_set_notify(struct smr_domain *sd, smr_domain_notify_cb_t *cb)
{

	sd->sd_notify_cb = cb;
}

struct smr_domain *
smr_domain_create(int flags)
{
	struct smr_domain *sd;
	struct smr_pcpu_state *sps = NULL;
	int dom, i;

	flags |= M_ZERO;
	if ((flags & M_NOWAIT) == 0)
		flags |= M_WAITOK;

	sd = malloc(sizeof(*sd) + mp_ncpus * sizeof(void *), M_SMR, flags);
	if (sd == NULL)
		return NULL;

	ck_epoch_init(&sd->sd_epoch);
	for (dom = 0; dom < vm_ndomains; dom++) {
		sps = malloc_domain(sizeof(*sps) * cpuset_domcount[dom],
		    M_SMR, dom, flags);
		if (sps == NULL)
			break;
		sd->sd_dom[dom] = sps;
	}

	if (sps == NULL) {
		for (dom = 0; dom < vm_ndomains; dom++)
			free(sd->sd_dom[dom], M_SMR);
		free(sd, M_SMR);
		return (NULL);
	}

	for (dom = 0; dom < vm_ndomains; dom++) {
		sps = sd->sd_dom[dom];
		for (i = 0; i < cpuset_domcount[dom]; i++, sps++) {
			sd->sd_pcpu[cpuset_domoffsets[dom] + i] = sps;
			ck_epoch_register(&sd->sd_epoch, &sps->sps_record, NULL);
		}
	}
	return (sd);
}

void
smr_domain_destroy(struct smr_domain *sd)
{
	int domain;
#ifdef INVARIANTS
	struct smr_pcpu_state *sps;
	int cpu;
	CPU_FOREACH(cpu) {
		sps = sd->sd_pcpu[cpu];
		MPASS(ck_pr_load_uint(&sps->sps_critnest) == 0);
	}
#endif

	for (domain = 0; domain < vm_ndomains; domain++)
		free(sd->sd_dom[domain], M_SMR);
	free(sd, M_SMR);
}

static void
smr_init(void *arg __unused)
{

	smr_global = smr_domain_create(0);
	MPASS(smr_global != NULL);
	smr_domain_set_notify(smr_global, smr_global_notify);
	mtx_init(&smr_mtx, "SMR mtx", NULL, MTX_DEF);
	cv_init(&smr_cv, "smr");
	wait_count = counter_u64_alloc(M_WAITOK);
	yield_count = counter_u64_alloc(M_WAITOK);
}
SYSINIT(smr, SI_SUB_CPUSET + 1, SI_ORDER_ANY, smr_init, NULL);

static void
smr_finalize(void *arg __unused)
{

	kproc_start(&smr_kp);
}
SYSINIT(smr_finalize, SI_SUB_KTHREAD_IDLE, SI_ORDER_ANY, smr_finalize, NULL);
