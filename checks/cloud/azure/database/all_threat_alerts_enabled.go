package database

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckAllThreatAlertsEnabled = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0028",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "all-threat-alerts-enabled",
		Summary:     "No threat detections are set",
		Impact:      "Disabling threat alerts means you are not getting the full benefit of server security protection",
		Resolution:  "Use all provided threat alerts",
		Explanation: `SQL Server can alert for security issues including SQL Injection, vulnerabilities, access anomalies and data exfiltration. Ensure none of these are disabled to benefit from the best protection`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAllThreatAlertsEnabledGoodExamples,
			BadExamples:         terraformAllThreatAlertsEnabledBadExamples,
			Links:               terraformAllThreatAlertsEnabledLinks,
			RemediationMarkdown: terraformAllThreatAlertsEnabledRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.MSSQLServers {
			for _, policy := range server.SecurityAlertPolicies {
				if len(policy.DisabledAlerts) > 0 {
					results.Add(
						"Server has a security alert policy which disables alerts.",
						policy.DisabledAlerts[0],
					)
				} else {
					results.AddPassed(&policy)
				}
			}
		}
		return
	},
)
