package neptune

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckEnableStorageEncryption = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0076",
		Provider:    providers.AWSProvider,
		Service:     "neptune",
		ShortCode:   "enable-storage-encryption",
		Summary:     "Neptune storage must be encrypted at rest",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable encryption of Neptune storage",
		Explanation: `Encryption of Neptune storage ensures that if their is compromise of the disks, the data is still protected.`,
		Links: []string{
			"https://docs.aws.amazon.com/neptune/latest/userguide/encrypt.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableStorageEncryptionGoodExamples,
			BadExamples:         terraformEnableStorageEncryptionBadExamples,
			Links:               terraformEnableStorageEncryptionLinks,
			RemediationMarkdown: terraformEnableStorageEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableStorageEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableStorageEncryptionBadExamples,
			Links:               cloudFormationEnableStorageEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableStorageEncryptionRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.Neptune.Clusters {
			if cluster.StorageEncrypted.IsFalse() {
				results.Add(
					"Cluster does not have storage encryption enabled.",
					cluster.StorageEncrypted,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
