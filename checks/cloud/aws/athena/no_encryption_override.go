package athena

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckNoEncryptionOverride = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0007",
		Provider:    providers.AWSProvider,
		Service:     "athena",
		ShortCode:   "no-encryption-override",
		Summary:     "Athena workgroups should enforce configuration to prevent client disabling encryption",
		Impact:      "Clients can ignore encryption requirements",
		Resolution:  "Enforce the configuration to prevent client overrides",
		Explanation: `Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.`,
		Links: []string{
			"https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoEncryptionOverrideGoodExamples,
			BadExamples:         terraformNoEncryptionOverrideBadExamples,
			Links:               terraformNoEncryptionOverrideLinks,
			RemediationMarkdown: terraformNoEncryptionOverrideRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoEncryptionOverrideGoodExamples,
			BadExamples:         cloudFormationNoEncryptionOverrideBadExamples,
			Links:               cloudFormationNoEncryptionOverrideLinks,
			RemediationMarkdown: cloudFormationNoEncryptionOverrideRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, workgroup := range s.AWS.Athena.Workgroups {
			if workgroup.Metadata.IsUnmanaged() {
				continue
			}
			if workgroup.EnforceConfiguration.IsFalse() {
				results.Add(
					"The workgroup configuration is not enforced.",
					workgroup.EnforceConfiguration,
				)
			}
		}
		return
	},
)
