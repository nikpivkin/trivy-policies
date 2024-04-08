package apigateway

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckEnableTracing = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0003",
		Provider:    providers.AWSProvider,
		Service:     "api-gateway",
		ShortCode:   "enable-tracing",
		Summary:     "API Gateway must have X-Ray tracing enabled",
		Impact:      "Without full tracing enabled it is difficult to trace the flow of logs",
		Resolution:  "Enable tracing",
		Explanation: `X-Ray tracing enables end-to-end debugging and analysis of all API Gateway HTTP requests.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableTracingGoodExamples,
			BadExamples:         terraformEnableTracingBadExamples,
			Links:               terraformEnableTracingLinks,
			RemediationMarkdown: terraformEnableTracingRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, api := range s.AWS.APIGateway.V1.APIs {
			if api.Metadata.IsUnmanaged() {
				continue
			}
			for _, stage := range api.Stages {
				if stage.Metadata.IsUnmanaged() {
					continue
				}
				if stage.XRayTracingEnabled.IsFalse() {
					results.Add(
						"X-Ray tracing is not enabled,",
						stage.XRayTracingEnabled,
					)
				} else {
					results.AddPassed(&stage)
				}
			}
		}
		return
	},
)
