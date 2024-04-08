package compute

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type SSLPolicy struct {
	Metadata          iacTypes.Metadata
	Name              iacTypes.StringValue
	Profile           iacTypes.StringValue
	MinimumTLSVersion iacTypes.StringValue
}
