package ecr

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckEnforceImmutableRepository = cheks.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0031",
		Provider:   providers.AWSProvider,
		Service:    "ecr",
		ShortCode:  "enforce-immutable-repository",
		Summary:    "ECR images tags shouldn't be mutable.",
		Impact:     "Image tags could be overwritten with compromised images",
		Resolution: "Only use immutable images in ECR",
		Explanation: `ECR images should be set to IMMUTABLE to prevent code injection through image mutation.

This can be done by setting <code>image_tab_mutability</code> to <code>IMMUTABLE</code>`,
		Links: []string{
			"https://sysdig.com/blog/toctou-tag-mutability/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnforceImmutableRepositoryGoodExamples,
			BadExamples:         terraformEnforceImmutableRepositoryBadExamples,
			Links:               terraformEnforceImmutableRepositoryLinks,
			RemediationMarkdown: terraformEnforceImmutableRepositoryRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnforceImmutableRepositoryGoodExamples,
			BadExamples:         cloudFormationEnforceImmutableRepositoryBadExamples,
			Links:               cloudFormationEnforceImmutableRepositoryLinks,
			RemediationMarkdown: cloudFormationEnforceImmutableRepositoryRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, repo := range s.AWS.ECR.Repositories {
			if repo.ImageTagsImmutable.IsFalse() {
				results.Add(
					"Repository tags are mutable.",
					repo.ImageTagsImmutable,
				)
			} else {
				results.AddPassed(&repo)
			}
		}
		return
	},
)
