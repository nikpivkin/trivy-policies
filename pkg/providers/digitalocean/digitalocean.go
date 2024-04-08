package digitalocean

import (
	"github.com/aquasecurity/trivy-policies/pkg/providers/digitalocean/compute"
	"github.com/aquasecurity/trivy-policies/pkg/providers/digitalocean/spaces"
)

type DigitalOcean struct {
	Compute compute.Compute
	Spaces  spaces.Spaces
}
