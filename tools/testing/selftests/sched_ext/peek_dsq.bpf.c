// SPDX-License-Identifier: GPL-2.0
/*
 * A BPF program for testing DSQ operations including create, destroy,
 * and peek operations. Uses a hybrid approach:
 * - Syscall program for DSQ lifecycle (create/destroy)
 * - Struct ops scheduler for task insertion/dequeue testing
 *
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Ryan Newton <ryan.newton@alum.mit.edu>
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>

char _license[] SEC("license") = "GPL";

/* Global variables to store test results */
int dsq_create_result = -1;
int dsq_destroy_result = -1;
int dsq_insert_result = -1;
int dsq_peek_result1 = -1;
int dsq_peek_result2 = -1;
long dsq_peek_result2_expected = -1;
int test_dsq_id = 1234; /* Use a simple ID like create_dsq example */
int enqueue_count = -1;
int debug_iter_ret = -1;
int debug_ksym_exists = -1;

/* Shared state for coordination between syscall and struct_ops */
bool scheduler_enabled;
bool insert_test_done;
bool dsq_created;

/* Test if we're actually using the native or compat version */
int check_dsq_insert_ksym(void)
{
	return bpf_ksym_exists(scx_bpf_dsq_insert) ? 1 : 0;
}

int check_dsq_peek_ksym(void)
{
	return bpf_ksym_exists(scx_bpf_dsq_peek) ? 1 : 0;
}

/* Use the compat version of scx_bpf_dsq_peek with debugging info */
static inline struct task_struct *debug_dsq_peek(u64 dsq_id)
{
	/* Always set debug values so we can see which version we're using */
	debug_ksym_exists = check_dsq_peek_ksym();

	if (debug_ksym_exists)
		debug_iter_ret = -3; /* Mark that we used native */
	else
		debug_iter_ret = -4; /* Mark that we used compat fallback */

	/* Use the compat.bpf.h version which handles fallback automatically */
	return scx_bpf_dsq_peek(dsq_id);
}

/* Struct_ops scheduler for testing DSQ peek operations */
void BPF_STRUCT_OPS(peek_dsq_enqueue, struct task_struct *p, u64 enq_flags)
{
	// bpf_printk("peek_dsq_enqueue called for pid %d\n", p->pid);
	enqueue_count++;

	/* On the first task, just do the empty DSQ test and insert into test DSQ */
	if (!insert_test_done) {
		/* Test 1: Peek empty DSQ - should return NULL */
		struct task_struct *peek_result = debug_dsq_peek(test_dsq_id);

		dsq_peek_result1 = (int)peek_result; /* Should be 0 (NULL) */

		/* Test 2: Insert task into test DSQ for testing in dispatch callback */
		scx_bpf_dsq_insert(p, test_dsq_id, 0, enq_flags);
		// flush_dispatch_buf()?
		// empty DSQ, move_to_local() for NOOP, for global flush.

		dsq_insert_result = 1; /* Mark that we inserted */
		dsq_peek_result2_expected = (long)p; /* Expected the task we just inserted */

		insert_test_done = true;
	} else {
		/* Normal path: dispatch other tasks to global DSQ */
		scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, 0, enq_flags);
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(peek_dsq_init)
{
	s32 err;

	bpf_printk("peek_dsq_init called\n");

	/* Initialize state first */
	scheduler_enabled = true;
	insert_test_done = false;
	enqueue_count = 0;
	dsq_created = false;
	dsq_create_result = 0; /* Reset to 0 before attempting */

	/* Create a DSQ */
	err = scx_bpf_create_dsq(test_dsq_id, -1);
	if (err) {
		dsq_create_result = err;
		scx_bpf_error("Failed to create DSQ %d: %d", test_dsq_id, err);
		return err;
	}

	dsq_create_result = 1; /* Success */
	dsq_created = true;

	return 0;
}

void BPF_STRUCT_OPS(peek_dsq_dispatch, s32 cpu, struct task_struct *prev)
{
	bpf_printk("peek_dsq_dispatch called on CPU %d, global dsq %d, test dsq %d\n", cpu, SCX_DSQ_GLOBAL, test_dsq_id);
	/* Complete the peek test if we inserted a task but haven't tested peek yet */
	if (insert_test_done && dsq_insert_result == 1 && dsq_peek_result2 == -1) {
		/* Test 3: Peek DSQ after insert - should return the task we inserted */
		struct task_struct *peek_result = debug_dsq_peek(test_dsq_id);

		dsq_peek_result2 = (int)peek_result;

		/* Now we can consume the task since we've peeked at it */
		scx_bpf_dsq_move_to_local(test_dsq_id);
	}

	/* Normal operation: move tasks from global to local */
	scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL);

	/* Consume remaining tasks from test DSQ (if any) */
	scx_bpf_dsq_move_to_local(test_dsq_id);
}

void BPF_STRUCT_OPS(peek_dsq_exit, struct scx_exit_info *ei)
{
	bpf_printk("peek_dsq_exit called\n");
	scx_bpf_destroy_dsq(test_dsq_id);
	dsq_destroy_result = 1;

	scheduler_enabled = false;
}

SEC(".struct_ops.link")
struct sched_ext_ops peek_dsq_ops = {
	.enqueue = (void *)peek_dsq_enqueue,
	.dispatch = (void *)peek_dsq_dispatch,
	.init = (void *)peek_dsq_init,
	.exit = (void *)peek_dsq_exit,
	.name = "peek_dsq",
};
