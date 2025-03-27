#
# METADATA
# title: InferenceService
# description: Verify attributes on an InferenceService Kubernetes resource.
#
package inferenceservice

import rego.v1

import data.lib

# METADATA
# title: Trusted Model URI
# description: Verify the InferenceService resource uses a model signed by Red Hat.
# custom:
#   short_name: trusted_model_uri
#   failure_msg: "%s"
#
deny contains result if {
	lower(input.kind) == "inferenceservice"
	some err in _model_errors
	result := lib.result_helper(rego.metadata.chain(), [err])
}

_model_errors contains err if {
	not _storage_uri
	err := sprintf("Model storage URI not found for %q InferenceService", [_name])
}

_model_errors contains err if {
	not contains(_storage_uri, "@")
	err := sprintf("Model reference is not pinned: %s", [_storage_uri])
}

_model_errors contains err if {
	not startswith(_storage_uri, "oci://")
	err := sprintf("Model storage must be OCI: %s", [_storage_uri])
}

_model_errors contains err if {
	startswith(_storage_uri, "oci://")
	contains(_storage_uri, "@")
	result := ec.sigstore.verify_image(
		replace(_storage_uri, "oci://", ""),
		object.union(lib.sigstore_opts, {
			"ignore_rekor": false,
			"public_key": _rh_release_key,
		}),
	)

	some raw_err in result.errors

	err := sprintf("Model is not signed: %s: %s", [_storage_uri, raw_err])
}

_storage_uri := input.spec.predictor.model.storageUri

_name := object.get(input, ["metadata", "name"], "UNKNOWN")

# https://security.access.redhat.com/data/63405576.txt
# pub 4096R/E60D446E63405576 2024-09-20
# uid Red Hat, Inc. (release key 3) <security@redhat.com>
_rh_release_key := `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0ASyuH2TLWvBUqPHZ4Ip
75g7EncBkgQHdJnjzxAW5KQTMh/siBoB/BoSrtiPMwnChbTCnQOIQeZuDiFnhuJ7
M/D3b7JoX0m123NcCSn67mAdjBa6Bg6kukZgCP4ZUZeESajWX/EjylFcRFOXW57p
RDCEN42J/jYlVqt+g9+Grker8Sz86H3l0tbqOdjbz/VxHYhwF0ctUMHsyVRDq2QP
tqzNXlmlMhS/PoFr6R4u/7HCn/K+LegcO2fAFOb40KvKSKKVD6lewUZErhop1CgJ
XjDtGmmO9dGMF71mf6HEfaKSdy+EE6iSF2A2Vv9QhBawMiq2kOzEiLg4nAdJT8wg
ZrMAmPCqGIsXNGZ4/Q+YTwwlce3glqb5L9tfNozEdSR9N85DESfQLQEdY3CalwKM
BT1OEhEX1wHRCU4drMOej6BNW0VtscGtHmCrs74jPezhwNT8ypkyS+T0zT4Tsy6f
VXkJ8YSHyenSzMB2Op2bvsE3grY+s74WhG9UIA6DBxcTie15NSzKwfzaoNWODcLF
p7BY8aaHE2MqFxYFX+IbjpkQRfaeQQsouDFdCkXEFVfPpbD2dk6FleaMTPuyxtIT
gjVEtGQK2qGCFGiQHFd4hfV+eCA63Jro1z0zoBM5BbIIQ3+eVFwt3AlZp5UVwr6d
secqki/yrmv3Y0dqZ9VOn3UCAwEAAQ==
-----END PUBLIC KEY-----
`
