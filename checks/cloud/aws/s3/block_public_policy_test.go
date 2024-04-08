package s3

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy-policies/pkg/types"

	"github.com/aquasecurity/trivy-policies/pkg/state"

	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/s3"
	"github.com/aquasecurity/trivy-policies/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPublicPoliciesAreBlocked(t *testing.T) {
	tests := []struct {
		name     string
		input    s3.S3
		expected bool
	}{
		{
			name: "Public access block missing",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			},
			expected: true,
		},
		{
			name: "Public access block blocks public policies",
			input: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:          trivyTypes.NewTestMetadata(),
							BlockPublicPolicy: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.AWS.S3 = test.input
			results := CheckPublicPoliciesAreBlocked.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPublicPoliciesAreBlocked.LongID() {
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
