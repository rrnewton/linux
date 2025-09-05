// SPDX-License-Identifier: GPL-2.0
/*
 * Test for DSQ operations including create, destroy, and peek operations.
 *
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2025 Ryan Newton <ryan.newton@alum.mit.edu>
 */
#include <bpf/bpf.h>
#include <scx/common.h>
#include <sys/wait.h>
#include <unistd.h>
#include "peek_dsq.bpf.skel.h"
#include "scx_test.h"

static enum scx_test_status setup(void **ctx)
{
	struct peek_dsq *skel;

	skel = peek_dsq__open();
	SCX_FAIL_IF(!skel, "Failed to open");
	SCX_ENUM_INIT(skel);
	SCX_FAIL_IF(peek_dsq__load(skel), "Failed to load skel");

	*ctx = skel;

	return SCX_TEST_PASS;
}

static enum scx_test_status run(void *ctx)
{
	struct peek_dsq *skel = ctx;
	int prog_fd, err = 0;
	bool failed = false;

	prog_fd = bpf_program__fd(skel->progs.peek_dsq_test);
	if (prog_fd < 0) {
		SCX_ERR("Failed to get BPF_PROG_RUN prog");
		return SCX_TEST_FAIL;
	}

	LIBBPF_OPTS(bpf_test_run_opts, topts);

	/* Call the BPF program directly with BPF_PROG_RUN */
	err = bpf_prog_test_run_opts(prog_fd, &topts);
	if (err != 0) {
		SCX_ERR("Failed to execute BPF program: %d", err);
		return SCX_TEST_FAIL;
	}

	/* Check if DSQ creation succeeded */
	if (skel->data->dsq_create_result != 1) {
		SCX_ERR("DSQ create failed: got %d, expected 1",
			skel->data->dsq_create_result);
		return SCX_TEST_FAIL;
	}

	/* Now enable the scheduler briefly to test DSQ insert operations */
	printf("Enabling scheduler to test DSQ insert operations...\n");

	struct bpf_link *link = bpf_map__attach_struct_ops(skel->maps.peek_dsq_ops);

	if (!link) {
		SCX_ERR("Failed to attach struct_ops");
		return SCX_TEST_FAIL;
	}

	/* Give it a moment for tasks to be enqueued and tested */
	sleep(2);

	/* Detach the scheduler */
	bpf_link__destroy(link);

	/* Check DSQ insert result */
	printf("DSQ insert result: %d\n", skel->data->dsq_insert_result);
	if (skel->data->dsq_insert_result == 1)
		printf("✓ DSQ insert succeeded - task was inserted into DSQ!\n");
	else {
		printf("✗ DSQ insert failed or not attempted\n");
		failed = true;
	}

	/* Check DSQ peek results */
	printf("  DSQ peek result 1 (before insert): %d\n", skel->data->dsq_peek_result1);
	if (skel->data->dsq_peek_result1 == 0)
		printf("✓ DSQ peek verification succeeded - peek returned NULL!\n");
	else {
		printf("✗ DSQ peek verification failed\n");
		failed = true;
	}

	printf("  DSQ peek result 2 (after insert): %d\n", skel->data->dsq_peek_result2);
	printf("  DSQ peek result 2, expected: %d\n", skel->data->dsq_peek_result2_expected);
	if (skel->data->dsq_peek_result2 == skel->data->dsq_peek_result2_expected)
		printf("✓ DSQ peek verification succeeded - peek returned the inserted task!\n");
	else {
		printf("✗ DSQ peek verification failed\n");
		failed = true;
	}

	if (skel->data->dsq_destroy_result != 1) {
		printf("✗ DSQ destroy failed: got %d, expected 1\n",
			skel->data->dsq_destroy_result);
		failed = true;
	}

	if (failed)
		return SCX_TEST_FAIL;
	else
		return SCX_TEST_PASS;
}

static void cleanup(void *ctx)
{
	struct peek_dsq *skel = ctx;

	peek_dsq__destroy(skel);
}

struct scx_test peek_dsq = {
	.name = "peek_dsq",
	.description = "Test DSQ create/destroy operations and future peek functionality",
	.setup = setup,
	.run = run,
	.cleanup = cleanup,
};
REGISTER_SCX_TEST(&peek_dsq)
