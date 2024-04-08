package appservice

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckEnableHttp2 = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0005",
		Provider:    providers.AzureProvider,
		Service:     "appservice",
		ShortCode:   "enable-http2",
		Summary:     "Web App uses the latest HTTP version",
		Impact:      "Outdated versions of HTTP has security vulnerabilities",
		Resolution:  "Use the latest version of HTTP",
		Explanation: `Use the latest version of HTTP to ensure you are benefiting from security fixes`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableHttp2GoodExamples,
			BadExamples:         terraformEnableHttp2BadExamples,
			Links:               terraformEnableHttp2Links,
			RemediationMarkdown: terraformEnableHttp2RemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, service := range s.Azure.AppService.Services {
			if service.Metadata.IsUnmanaged() {
				continue
			}
			if service.Site.EnableHTTP2.IsFalse() {
				results.Add(
					"App service does not have HTTP/2 enabled.",
					service.Site.EnableHTTP2,
				)
			} else {
				results.AddPassed(&service)
			}
		}
		return
	},
)
