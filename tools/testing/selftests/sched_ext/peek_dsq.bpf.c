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

char _license[] SEC("license") = "GPL";

/* Global variables to store test results */
int dsq_create_result = -1;
int dsq_destroy_result = -1;
int dsq_insert_result = -1;
int dsq_peek_result1 = -1;
int dsq_peek_result2 = -1;
int dsq_peek_result2_expected = -1;
int test_dsq_id = 1234;
int enqueue_count = -1;

/* Shared state for coordination between syscall and struct_ops */
bool scheduler_enabled = true;
bool insert_test_done = true;

SEC("syscall")
int BPF_PROG(peek_dsq_test)
{
	s32 err;

	/* Test 1: Create a DSQ */
	err = scx_bpf_create_dsq(test_dsq_id, -1);
	if (err) {
		dsq_create_result = err;
		return -1;
	}
	dsq_create_result = 1; /* Success */

	/* Finish initializing global state: */
	scheduler_enabled = false;
	insert_test_done = false;
	enqueue_count = 0;

	/* The actual task insertion testing will happen in the struct_ops
	 * scheduler when it's enabled and tasks are being scheduled
	 */
	return 0;
}

/* Minimal struct_ops scheduler for testing DSQ task operations */
void BPF_STRUCT_OPS(peek_dsq_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_struct *peek;

	/* If we haven't done the insert test yet, try it now */
	if (!insert_test_done) {
		/* First peek - should be empty */
		peek = scx_bpf_dsq_peek(test_dsq_id);
		dsq_peek_result1 = (int)peek;

		/* Try to insert the task into our test DSQ */
		scx_bpf_dsq_insert(p, test_dsq_id, 0, enq_flags);
		dsq_insert_result = 1; /* Success */

		if (peek != NULL)
			scx_bpf_error("Initial peek unempty!");

		/* No concurrent access to our test DSQ, so we know its
		 * exact contents.
		 */
		peek = scx_bpf_dsq_peek(test_dsq_id);
		dsq_peek_result2 = (int)peek;
		dsq_peek_result2_expected = (int)p;

		// scx_bpf_error("ERROR TEST");

		/* Immediately dispatch to local DSQ so task can run normally */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, 0, enq_flags);
		insert_test_done = true;
	} else {
		/* Normal scheduling: dispatch to local DSQ */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, 0, enq_flags);
	}
}

s32 BPF_STRUCT_OPS(peek_dsq_init)
{
	scheduler_enabled = true;
	return 0;
}

s32 BPF_STRUCT_OPS(peek_dsq_exit, struct scx_exit_info *ei)
{
	scx_bpf_destroy_dsq(test_dsq_id);
	dsq_destroy_result = 1;

	scheduler_enabled = false;
	return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops peek_dsq_ops = {
	.enqueue		= (void *)peek_dsq_enqueue,
	.init			= (void *)peek_dsq_init,
	.exit			= (void *)peek_dsq_exit,
	.name			= "peek_dsq",
};
