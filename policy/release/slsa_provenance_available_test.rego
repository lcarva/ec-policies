package policy.release.slsa_provenance_available

import future.keywords.in

import data.lib

test_expected_predicate_type {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])
	lib.assert_empty(deny) with input.attestations as attestations
}

test_att_predicate_type {
	attestations := _mock_attestations(["spam"])
	expected_deny := {{
		"code": "slsa_provenance_available.attestation_predicate_type_accepted",
		"collections": ["minimal", "slsa1", "slsa2", "slsa3"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Attestation predicate type \"spam\" is not an expected type (https://slsa.dev/provenance/v0.2)",
	}}
	lib.assert_equal(deny, expected_deny) with input.attestations as attestations
}

_mock_attestations(types) = attestations {
	attestations := [attestation |
		some type in types
		attestation := {"predicateType": type, "predicate": {"buildType": lib.pipelinerun_att_build_types[0]}}
	]
}
