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

#define	SMR_CONTAINER CK_EPOCH_CONTAINER
typedef ck_epoch_entry_t smr_entry_t;
typedef ck_epoch_cb_t smr_cb_t;

/**
 * @brief Begin a SMR read-side section.
 */
void smr_begin(void);

/**
 * @brief End a SMR read-side section.
 */
void smr_end(void);

/**
 * @brief Call a reclamation callback once the object is no longer reachable.
 */
void smr_call(smr_entry_t *, smr_cb_t *);

/**
 * @brief Wait until all currently-unreachable objects are reclaimed.
 */
void smr_synchronize_wait(void);

/**
 * @brief Reclaim currently-unreachable objects for the given CPU.
 *
 * @param which		Barrier type to perform.
 */
#define	SMR_BARRIER_T_PCPU	(0)
#define	SMR_BARRIER_T_ALL	(1)
void smr_barrier(unsigned int which);

#endif /* _SYS_CALLOUT_H_ */
