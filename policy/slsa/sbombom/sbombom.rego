package ec.slsa.sbombom

import rego.v1

import data.lib
import data.release.sbom as _sbom

# METADATA
# title: Found
# description: Confirm an SBOM attestation exists.
# custom:
#   short_name: found
#   failure_msg: No SBOM attestations found
#   solution: >-
#     Make sure the build process produces an SBOM attestation.
#   collections:
#   - minimal
#   - redhat
#   - spam
#
deny contains result if {
    some original in _sbom.deny
    lib.matches_rule_name(rego.metadata.chain(), original)
    result := lib.with_long_pkg_name(rego.metadata.chain(), original)
}

# METADATA
# title: Disallowed packages list is provided
# description: >-
#   Confirm the `disallowed_packages` and `disallowed_attributes` rule data were
#   provided, since they are required by the policy rules in this package.
# custom:
#   short_name: disallowed_packages_provided
#   failure_msg: "%s"
#   solution: >-
#     Provide a list of disallowed packages or package attributes in the
#     expected format.
#   collections:
#   - redhat
#   - policy_data
#   - spam
#
deny contains result if {
    some original in _sbom.deny
    lib.matches_rule_name(rego.metadata.chain(), original)
    result := lib.with_long_pkg_name(rego.metadata.chain(), original)
}
