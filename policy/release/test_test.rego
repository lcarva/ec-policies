package policy.release.test_test

import data.lib
import data.lib_test
import data.policy.release.test

# Because TEST_OUTPUT isn't in the task results, the lib.results_from_tests will be empty
mock_empty_data := [lib_test.att_mock_helper_ref("NOT_TEST_OUTPUT", {}, "task1", _bundle)]

test_needs_non_empty_data {
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_data_found",
		"msg": "No test data found",
	}}) with input.attestations as mock_empty_data
}

# There is a test result, but the data inside it doesn't include the "result" key
mock_without_results_data := [lib_test.att_mock_helper_ref(
	lib.task_test_result_name, {"rezult": "SUCCESS"},
	"task1", _bundle,
)]

test_needs_tests_with_results {
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_results_found",
		"msg": "Found tests without results",
	}}) with input.attestations as mock_without_results_data
}

mock_without_results_data_mixed := [
	lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "task1", _bundle),
	lib_test.att_mock_helper_ref(lib.task_test_result_name, {"rezult": "SUCCESS"}, "task2", _bundle),
]

test_needs_tests_with_results_mixed {
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_results_found",
		"msg": "Found tests without results",
	}}) with input.attestations as mock_without_results_data_mixed
}

mock_a_passing_test := [lib_test.att_mock_helper_ref(
	lib.task_test_result_name,
	{"result": "SUCCESS"}, "task1", _bundle,
)]

test_success_data {
	lib.assert_empty(test.deny) with input.attestations as mock_a_passing_test
}

mock_a_failing_test := [lib_test.att_mock_helper_ref(
	lib.task_test_result_name,
	{"result": "FAILURE"}, "failed_1", _bundle,
)]

test_failure_data {
	lib.assert_equal_results(test.deny, {{
		"code": "test.required_tests_passed",
		"msg": "Test \"failed_1\" did not complete successfully",
		"term": "failed_1",
	}}) with input.attestations as mock_a_failing_test
}

mock_an_errored_test := [lib_test.att_mock_helper_ref(
	lib.task_test_result_name,
	{"result": "ERROR"}, "errored_1", _bundle,
)]

test_error_data {
	lib.assert_equal_results(test.deny, {{
		"code": "test.required_tests_passed",
		"msg": "Test \"errored_1\" did not complete successfully",
		"term": "errored_1",
	}}) with input.attestations as mock_an_errored_test
}

mock_mixed_data := array.concat(mock_a_failing_test, mock_an_errored_test)

test_mix_data {
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.required_tests_passed",
			"msg": "Test \"failed_1\" did not complete successfully",
			"term": "failed_1",
		},
		{
			"code": "test.required_tests_passed",
			"msg": "Test \"errored_1\" did not complete successfully",
			"term": "errored_1",
		},
	}) with input.attestations as mock_mixed_data
}

test_skipped_is_not_deny {
	skipped_test := [lib_test.att_mock_helper_ref(
		lib.task_test_result_name,
		{"result": "SKIPPED"}, "skipped_1", _bundle,
	)]
	lib.assert_empty(test.deny) with input.attestations as skipped_test
}

test_skipped_is_warning {
	skipped_test := [lib_test.att_mock_helper_ref(
		lib.task_test_result_name,
		{"result": "SKIPPED"}, "skipped_1", _bundle,
	)]
	lib.assert_equal_results(test.warn, {{
		"code": "test.no_skipped_tests",
		"msg": "Test \"skipped_1\" was skipped",
		"term": "skipped_1",
	}}) with input.attestations as skipped_test
}

test_warning_is_warning {
	warning_test := [lib_test.att_mock_helper_ref(
		lib.task_test_result_name,
		{"result": "WARNING"}, "warning_1", _bundle,
	)]
	lib.assert_equal_results(test.warn, {{
		"code": "test.no_test_warnings",
		"msg": "Test \"warning_1\" returned a warning",
		"term": "warning_1",
	}}) with input.attestations as warning_test
}

test_mixed_statuses {
	test_results := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "error_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "success_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAILURE"}, "failure_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPPED"}, "skipped_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAILURE"}, "failure_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPPED"}, "skipped_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "WARNING"}, "warning_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "error_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "WARNING"}, "warning_2", _bundle),
	]

	lib.assert_equal_results(test.deny, {
		{
			"code": "test.required_tests_passed",
			"msg": "Test \"error_1\" did not complete successfully",
			"term": "error_1",
		},
		{
			"code": "test.required_tests_passed",
			"msg": "Test \"error_2\" did not complete successfully",
			"term": "error_2",
		},
		{
			"code": "test.required_tests_passed",
			"msg": "Test \"failure_1\" did not complete successfully",
			"term": "failure_1",
		},
		{
			"code": "test.required_tests_passed",
			"msg": "Test \"failure_2\" did not complete successfully",
			"term": "failure_2",
		},
	}) with input.attestations as test_results

	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_skipped_tests",
			"msg": "Test \"skipped_1\" was skipped",
			"term": "skipped_1",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "Test \"skipped_2\" was skipped",
			"term": "skipped_2",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "Test \"warning_1\" returned a warning",
			"term": "warning_1",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "Test \"warning_2\" returned a warning",
			"term": "warning_2",
		},
	}) with input.attestations as test_results
}

test_unsupported_test_result {
	test_results := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "EROR"}, "error_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCESS"}, "success_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAIL"}, "failure_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPED"}, "skipped_1", _bundle),
	]

	lib.assert_equal_results(test.deny, {
		{
			"code": "test.test_results_known",
			"msg": "Test 'error_1' has unsupported result 'EROR'", "term": "error_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "Test 'failure_1' has unsupported result 'FAIL'", "term": "failure_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "Test 'skipped_1' has unsupported result 'SKIPED'", "term": "skipped_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "Test 'success_1' has unsupported result 'SUCESS'", "term": "success_1",
		},
	}) with input.attestations as test_results
}

test_missing_wrong_attestation_type {
	pr := lib_test.att_mock_helper_ref("some-result", {"result": "value"}, "task1", _bundle)
	tr := object.union(pr, {"statement": {"predicate": {"buildType": lib.tekton_task_run}}})
	lib.assert_empty(test.deny) with input.attestations as [tr]
}

test_wrong_attestation_type {
	pr := lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "errored_1", _bundle)
	tr := object.union(pr, {"statement": {"predicate": {"buildType": lib.tekton_task_run}}})
	lib.assert_empty(test.deny) with input.attestations as [tr]
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
