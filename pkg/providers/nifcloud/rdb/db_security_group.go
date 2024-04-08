package rdb

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type DBSecurityGroup struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
	CIDRs       []iacTypes.StringValue
}
