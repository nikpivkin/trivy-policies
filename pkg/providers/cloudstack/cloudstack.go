package cloudstack

import (
	"github.com/aquasecurity/trivy-policies/pkg/providers/cloudstack/compute"
)

type CloudStack struct {
	Compute compute.Compute
}
