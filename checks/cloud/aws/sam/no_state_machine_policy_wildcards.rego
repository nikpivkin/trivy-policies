# METADATA
# title: State machine policies should avoid use of wildcards and instead apply the principle of least privilege
# description: |
#   You should use the principle of least privilege when defining your IAM policies.
#   This means you should specify each exact permission required without using wildcards, as this could cause the granting of access to certain undesired actions, resources and principals.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - "https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-statemachine.html#sam-statemachine-policies"
# custom:
#   id: AVD-AWS-0120
#   avd_id: AVD-AWS-0120
#   provider: aws
#   service: sam
#   severity: HIGH
#   short_code: no-state-machine-policy-wildcards
#   deprecated: true
#   recommended_action: Specify the exact permissions required, and to which resources they should apply instead of using wildcards.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sam
#             provider: aws
#   cloud_formation:
#     good_examples: checks/cloud/aws/sam/no_state_machine_policy_wildcards.yaml
#     bad_examples: checks/cloud/aws/sam/no_state_machine_policy_wildcards.yaml
package builtin.aws.sam.aws0120

import rego.v1

deny contains res if {
	some table in input.aws.sam.simpletables
	not table.ssespecification.enabled.value
	res := result.new(
		"Domain name is configured with an outdated TLS policy.",
		table.ssespecification.enabled,
	)
}
