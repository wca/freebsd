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

#ifndef _SYS_SMR_H_
#define _SYS_SMR_H_

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/queue.h>

#include <ck_epoch.h>

/*
 * SMR subsystem users are expected to use the smr_* aliases.
 * These exist to represent generic handles in terms of visibility
 * management, and do not necessarily need to be epoch-based.
 */
#define	SMR_CONTAINER CK_EPOCH_CONTAINER
typedef ck_epoch_section_t smr_section_t;
typedef ck_epoch_entry_t smr_entry_t;
typedef ck_epoch_record_t smr_record_t;
typedef ck_epoch_cb_t smr_cb_t;

struct smr_domain;
typedef struct smr_domain smr_domain_t;

/**
 * @brief Create a SMR visibility domain.
 * All operations that use such handle are taken with respect to each other.
 * By default, this performs blocking allocations.
 * Returns the domain on success, NULL otherwise.
 */
struct smr_domain *smr_domain_create(int flags);

/**
 * @brief Destroy a SMR visibility domain.
 */
void smr_domain_destroy(struct smr_domain *);

/**
 * @brief Obtain the global shared SMR visibility domain.
 */
struct smr_domain *smr_global_domain(void);

/**
 * @brief Set the notification callback for a SMR domain.
 */
typedef void smr_domain_notify_cb_t(struct smr_domain *);
void smr_domain_set_notify(struct smr_domain *sd, smr_domain_notify_cb_t *cb);

/**
 * @brief Begin a SMR read-side section for a given domain.
 */
void smr_begin(smr_domain_t *, smr_section_t *);

/**
 * @brief Begin a non-preemptible SMR read-side section for a given domain.
 */
void smr_begin_nopreempt(smr_domain_t *, smr_section_t *);

/**
 * @brief End a SMR read-side section for a given domain.
 */
void smr_end(smr_domain_t *, smr_section_t *);

/**
 * @brief End a non-preemptible SMR read-side section for a given domain.
 */
void smr_end_nopreempt(smr_domain_t *, smr_section_t *);

/**
 * @brief Call a reclamation callback once the object is no longer reachable.
 */
void smr_call(smr_domain_t *, smr_entry_t *, smr_cb_t *);

/**
 * @brief Wait until all currently-unreachable objects are reclaimed.
 */
void smr_synchronize_wait(smr_domain_t *);

/**
 * @brief Reclaim currently-unreachable objects for the given domain.
 */
void smr_barrier(smr_domain_t *);

#endif /* _SYS_CALLOUT_H_ */
