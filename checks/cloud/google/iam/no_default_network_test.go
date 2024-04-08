package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/google/iam"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoDefaultNetwork(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Project automatic network creation enabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata:          trivyTypes.NewTestMetadata(),
								AutoCreateNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Project automatic network creation enabled #2",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),

						Folders: []iam.Folder{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Projects: []iam.Project{
									{
										Metadata:          trivyTypes.NewTestMetadata(),
										AutoCreateNetwork: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
									},
								},
								Folders: []iam.Folder{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Projects: []iam.Project{
											{
												Metadata:          trivyTypes.NewTestMetadata(),
												AutoCreateNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Project automatic network creation disabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata:          trivyTypes.NewTestMetadata(),
								AutoCreateNetwork: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
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
			testState.Google.IAM = test.input
			results := CheckNoDefaultNetwork.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoDefaultNetwork.LongID() {
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
