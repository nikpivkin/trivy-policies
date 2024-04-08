package database

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckNoPublicAccess = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0022",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "no-public-access",
		Summary:     "Ensure databases are not publicly accessible",
		Impact:      "Publicly accessible database could lead to compromised data",
		Resolution:  "Disable public access to database when not required",
		Explanation: `Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.MariaDBServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MSSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.MySQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.EnablePublicNetworkAccess.IsTrue() {
				results.Add(
					"Database server has public network access enabled.",
					server.EnablePublicNetworkAccess,
				)
			} else {
				results.AddPassed(&server)
			}
		}
		return
	},
)
