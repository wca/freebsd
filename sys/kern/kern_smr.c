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

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/smr.h>

#include <ck_epoch.h>

#define container_of(p, stype, field) \
	((stype *)(((uint8_t *)(p)) - offsetof(stype, field)))

struct smr_td_state;
struct smr_pcpu_state {
	smr_section_t sps_section;
	smr_record_t sps_record;
	TAILQ_HEAD(, smr_td_state) sps_head;
	int sps_cpuid;
};

static ck_epoch_t kern_epoch;
static DPCPU_DEFINE(struct smr_pcpu_state, smr_state);

static struct cv smr_cv;
static struct mtx smr_mtx;
static struct proc *smrproc;
static void sched_smr(void);
static struct kproc_desc smr_kp = {
	"smr_gc",
	sched_smr,
	&smrproc,
};

static void
sched_smr(void)
{
	struct timeval tv;

	/* Wait at most 5 seconds between synchronizes. */
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	for (;;) {
		smr_barrier(SMR_BARRIER_T_ALL);

		mtx_lock(&smr_mtx);
		(void) cv_timedwait(&smr_cv, &smr_mtx, tvtohz(&tv));
		mtx_unlock(&smr_mtx);
	}
}

void
smr_begin(smr_record_t *record, smr_section_t *section)
{

	ck_epoch_begin(record, section);
}

void
smr_pcpu_begin(smr_section_t *section)
{
	struct smr_pcpu_state *sps;
	struct smr_td_state *ts = &curthread->td_smr;

	/*
	 * Pin thread to current CPU, so the unlock gets the same per-CPU
	 * epoch record.
	 */
	sched_pin();
	sps = &DPCPU_GET(smr_state);

	if (section == NULL)
		section = &sps->sps_section;

	/*
	 * Threads need to be registered here, so the epoch records can be
	 * pcpu rather than per-thread.  Use a critical section to prevent
	 * recursion within ck_epoch_begin().
	 */
	critical_enter();
	smr_begin(&sps->sps_record, section);
	ts->ts_recurse++;
	if (ts->ts_recurse == 1)
		TAILQ_INSERT_TAIL(&sps->sps_head, ts, ts_entry);
	critical_exit();
	kdb_backtrace();
}

void
smr_end(smr_record_t *record, smr_section_t *section)
{

	ck_epoch_end(record, section);
}

void
smr_pcpu_end(smr_section_t *section)
{
	struct smr_pcpu_state *sps;
	struct smr_td_state *ts = &curthread->td_smr;

	sps = &DPCPU_GET(smr_state);

	if (section == NULL)
		section = &sps->sps_section;

	/*
	 * Use a critical section to prevent recursion within
	 * ck_epoch_end().
	 */
	critical_enter();
	smr_end(&sps->sps_record, section);
	ts->ts_recurse--;
	if (ts->ts_recurse == 0)
		TAILQ_REMOVE(&sps->sps_head, ts, ts_entry);
	critical_exit();

	sched_unpin();
}

void
smr_call(smr_entry_t *entry, smr_cb_t *fn)
{
	struct smr_pcpu_state *sps;

	/* This call requires pcpu association. */
	KASSERT(curthread->td_pinned > 0, ("curthread not pinned"));
	sps = &DPCPU_GET(smr_state);
	ck_epoch_call(&sps->sps_record, entry, fn);

	/* Wakeup the SMR GC thread. */
	cv_broadcast(&smr_cv);
}

static void
smr_synchronize_cb(ck_epoch_t *epoch __unused, ck_epoch_record_t *record,
    void *arg __unused)
{
	struct smr_pcpu_state *sps;
	struct thread *td;
	struct smr_td_state *ts;

	sps = container_of(record, struct smr_pcpu_state, sps_record);

	/* Check if blocked on the current CPU */
	if (sps->sps_cpuid == PCPU_GET(cpuid)) {
		bool is_sleeping = false;
		u_char prio = 0;

		/*
		 * Find the lowest priority or sleeping thread which
		 * is blocking synchronization on this CPU core. All
		 * the threads in the queue are CPU-pinned and cannot
		 * go anywhere while the current thread is locked.
		 */
		TAILQ_FOREACH(ts, &sps->sps_head, ts_entry) {
			td = container_of(ts, struct thread, td_smr);
			if (td->td_priority > prio)
				prio = td->td_priority;
			is_sleeping |= (td->td_inhibitors != 0);
		}

		if (is_sleeping) {
			thread_unlock(curthread);
			pause("W", 1);
			thread_lock(curthread);
		} else {
			/* set new thread priority */
			sched_prio(curthread, prio);
			/* task switch */
			mi_switch(SW_VOL | SWT_RELINQUISH, NULL);

			/*
			 * Release the thread lock while yielding to
			 * allow other threads to acquire the lock
			 * pointed to by TDQ_LOCKPTR(curthread). Else a
			 * deadlock like situation might happen.
			 */
			thread_unlock(curthread);
			thread_lock(curthread);
		}
	} else {
		/*
		 * To avoid spinning move execution to the other CPU
		 * which is blocking synchronization. Set highest
		 * thread priority so that code gets run. The thread
		 * priority will be restored later.
		 */
		sched_prio(curthread, 0);
		sched_bind(curthread, sps->sps_cpuid);
	}
}

void
smr_synchronize_wait(void)
{
	struct thread *td;
	int was_bound;
	int old_cpu;
	int old_pinned;
	u_char old_prio;

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,
	    "smr_synchronize_wait() can sleep");

	td = curthread;

	DROP_GIANT();

	/*
	 * Synchronizing might change the CPU core this function is
	 * running on. Save current values:
	 */
	thread_lock(td);

	old_cpu = PCPU_GET(cpuid);
	old_pinned = td->td_pinned;
	old_prio = td->td_priority;
	was_bound = sched_is_bound(td);
	sched_unbind(td);
	td->td_pinned = 0;
	sched_bind(td, old_cpu);

	ck_epoch_synchronize_wait(&kern_epoch, smr_synchronize_cb, NULL);

	/* restore CPU binding, if applicable */
	if (was_bound != 0) {
		sched_bind(td, old_cpu);
	} else {
		/* get thread back to initial CPU, if applicable */
		if (old_pinned != 0)
			sched_bind(td, old_cpu);
		sched_unbind(td);
	}
	/* restore pinned after bind */
	td->td_pinned = old_pinned;

	/* restore thread priority */
	sched_prio(td, old_prio);
	thread_unlock(td);

	PICKUP_GIANT();
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

	CK_STACK_FOREACH_SAFE(pending, cursor, next) {
		struct ck_epoch_entry *entry = ck_epoch_entry_container(cursor);

		next = CK_STACK_NEXT(cursor);
		entry->function(entry);
	}

	return;
}

static void
epoch_stack_pop(struct ck_epoch_record *record, ck_stack_t *pending)
{
	unsigned int epoch, reclaims;
	ck_stack_entry_t *e_pending, *cursor;

	for (epoch = 0; epoch < CK_EPOCH_LENGTH; epoch++) {
		reclaims = 0;
		e_pending = ck_stack_batch_pop_upmc(&record->pending[epoch]);
		if (e_pending == NULL)
			continue;
		for (cursor = e_pending; cursor != NULL;
		    cursor = CK_STACK_NEXT(cursor), reclaims++);
		epoch_record_reclaims(record, reclaims);
		ck_stack_push_upmc(pending, e_pending);
	}
	return;
}

void
smr_barrier(unsigned int which)
{
	struct smr_pcpu_state *sps;
	ck_stack_t pending;
	int i;

	/*
	 * Pop off every pending deferred object requested, synchronize,
	 * then dispatch all seen deferrals.
	 */
	ck_stack_init(&pending);
	switch (which) {
	case SMR_BARRIER_T_PCPU:
		sps = &DPCPU_GET(smr_state);
		epoch_stack_pop(&sps->sps_record, &pending);
		break;
	case SMR_BARRIER_T_ALL:
		CPU_FOREACH(i) {
			sps = &DPCPU_ID_GET(i, smr_state);
			epoch_stack_pop(&sps->sps_record, &pending);
		}
		break;
	default:
		panic("unhandled smr_barrier which case");
		/* NOTREACHED */
	}

	smr_synchronize_wait();

	epoch_stack_dispatch(&pending);
}

static void
smr_init(void *arg __unused)
{
	int i;
	struct smr_pcpu_state *sps;

	ck_epoch_init(&kern_epoch);
	mtx_init(&smr_mtx, "SMR mtx", NULL, MTX_DEF);
	cv_init(&smr_cv, "smr");

	CPU_FOREACH(i) {
		sps = &DPCPU_ID_GET(i, smr_state);
		sps->sps_cpuid = i;
		TAILQ_INIT(&sps->sps_head);
		ck_epoch_register(&kern_epoch, &sps->sps_record, NULL);
	}

	kproc_start(&smr_kp);
}
SYSINIT(smr, SI_SUB_KTHREAD_INIT, SI_ORDER_ANY, smr_init, NULL);
