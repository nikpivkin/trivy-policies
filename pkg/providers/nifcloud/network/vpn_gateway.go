package network

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type VpnGateway struct {
	Metadata      iacTypes.Metadata
	SecurityGroup iacTypes.StringValue
}
