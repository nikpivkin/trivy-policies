package sql

import (
	"github.com/aquasecurity/trivy-policies/internal/cheks"
	"github.com/aquasecurity/trivy-policies/pkg/providers"
	"github.com/aquasecurity/trivy-policies/pkg/providers/google/sql"
	"github.com/aquasecurity/trivy-policies/pkg/scan"
	"github.com/aquasecurity/trivy-policies/pkg/severity"
	"github.com/aquasecurity/trivy-policies/pkg/state"
)

var CheckNoCrossDbOwnershipChaining = cheks.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0019",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-cross-db-ownership-chaining",
		Summary:     "Cross-database ownership chaining should be disabled",
		Impact:      "Unintended access to sensitive data",
		Resolution:  "Disable cross database ownership chaining",
		Explanation: `Cross-database ownership chaining, also known as cross-database chaining, is a security feature of SQL Server that allows users of databases access to other databases besides the one they are currently using.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option?view=sql-server-ver15",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoCrossDbOwnershipChainingGoodExamples,
			BadExamples:         terraformNoCrossDbOwnershipChainingBadExamples,
			Links:               terraformNoCrossDbOwnershipChainingLinks,
			RemediationMarkdown: terraformNoCrossDbOwnershipChainingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilySQLServer {
				continue
			}
			if instance.Settings.Flags.CrossDBOwnershipChaining.IsTrue() {
				results.Add(
					"Database instance has cross database ownership chaining enabled.",
					instance.Settings.Flags.CrossDBOwnershipChaining,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
