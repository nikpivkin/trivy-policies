package nas

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type NASSecurityGroup struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDRs       []iacTypes.StringValue
}
