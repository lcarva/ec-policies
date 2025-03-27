package inferenceservice_test

import rego.v1

import data.inferenceservice
import data.lib

test_success if {
	lib.assert_empty(inferenceservice.deny) with input as _good_resource
		with ec.sigstore.verify_image as _mock_verify_image
}

test_image_not_signed if {
	resource := json.patch(_good_resource, [{
		"op": "replace",
		"path": "/spec/predictor/model/storageUri",
		"value": _with_oci_prefix(_unsigned_uri),
	}])
	expected := {{
		"code": "inferenceservice.trusted_model_uri",
		"msg": sprintf("Model is not signed: %s: spam", [_with_oci_prefix(_unsigned_uri)]),
	}}
	lib.assert_equal_results(expected, inferenceservice.deny) with input as resource
		with ec.sigstore.verify_image as _mock_verify_image
}

test_non_oci_storage if {
	resource := json.patch(_good_resource, [{
		"op": "replace",
		"path": "/spec/predictor/model/storageUri",
		"value": _unsigned_uri,
	}])
	expected := {{
		"code": "inferenceservice.trusted_model_uri",
		"msg": sprintf("Model storage must be OCI: %s", [_unsigned_uri]),
	}}
	lib.assert_equal_results(expected, inferenceservice.deny) with input as resource
		with ec.sigstore.verify_image as _mock_verify_image
}

test_non_pinned_reference if {
	without_digest := _with_oci_prefix(split(_signed_uri, "@")[0])
	resource := json.patch(_good_resource, [{
		"op": "replace",
		"path": "/spec/predictor/model/storageUri",
		"value": without_digest,
	}])
	expected := {{
		"code": "inferenceservice.trusted_model_uri",
		"msg": sprintf("Model reference is not pinned: %s", [without_digest]),
	}}
	lib.assert_equal_results(expected, inferenceservice.deny) with input as resource
		with ec.sigstore.verify_image as _mock_verify_image
}

test_incomplete_resource if {
	resource := json.patch(_good_resource, [{
		"op": "remove",
		"path": "/spec/predictor/model/storageUri",
	}])
	expected := {{
		"code": "inferenceservice.trusted_model_uri",
		"msg": `Model storage URI not found for "my-service" InferenceService`,
	}}
	lib.assert_equal_results(expected, inferenceservice.deny) with input as resource
		with ec.sigstore.verify_image as _mock_verify_image
}

_good_resource := {
	"kind": "InferenceService",
	"metadata": {"name": "my-service"},
	"spec": {"predictor": {"model": {"storageUri": _with_oci_prefix(_signed_uri)}}},
}

# regal ignore:line-length
_signed_uri := "registry.redhat.io/rhelai1/modelcar-granite-8b-code-instruct:latest@sha256:e23eafe347ecdcaf219da6b573f3ef9f526f86543f7bad8e7d3329b36f0bc631"

# regal ignore:line-length
_unsigned_uri := "registry.redhat.io/rhelai1/modelcar-granite-8b-code-instruct:latest@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

_with_oci_prefix(uri) := sprintf("oci://%s", [uri])

_mock_verify_image(uri, _) := result if {
	uri == _signed_uri
	result := {"errors": []}
} else := {"errors": ["spam"]}
