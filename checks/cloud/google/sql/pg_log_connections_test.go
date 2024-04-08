package sql

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/google/sql"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPgLogConnections(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance connections logging disabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogConnections: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance connections logging enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       trivyTypes.NewTestMetadata(),
								LogConnections: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.SQL = test.input
			results := CheckPgLogConnections.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPgLogConnections.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
