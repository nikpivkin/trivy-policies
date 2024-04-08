package compute

import (
	"github.com/aquasecurity/trivy-policies/pkg/types"
)

type Network struct {
	Metadata    types.Metadata
	Firewall    *Firewall
	Subnetworks []SubNetwork
}
