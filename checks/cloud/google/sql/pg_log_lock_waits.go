package sql

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckPgLogLockWaits = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0020",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-lock-waits",
		Summary:     "Ensure that logging of lock waits is enabled.",
		Impact:      "Issues leading to denial of service may not be identified.",
		Resolution:  "Enable lock wait logging.",
		Explanation: `Lock waits are often an indication of poor performance and often an indicator of a potential denial of service vulnerability, therefore occurrences should be logged for analysis.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-LOCK-WAITS",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPgLogLockWaitsGoodExamples,
			BadExamples:         terraformPgLogLockWaitsBadExamples,
			Links:               terraformPgLogLockWaitsLinks,
			RemediationMarkdown: terraformPgLogLockWaitsRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogLockWaits.IsFalse() {
				results.Add(
					"Database instance is not configured to log lock waits.",
					instance.Settings.Flags.LogLockWaits,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
