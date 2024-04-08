package network

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Router struct {
	Metadata          iacTypes.Metadata
	SecurityGroup     iacTypes.StringValue
	NetworkInterfaces []NetworkInterface
}
