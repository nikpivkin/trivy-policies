package ec2

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Subnet struct {
	Metadata            iacTypes.Metadata
	MapPublicIpOnLaunch iacTypes.BoolValue
}
