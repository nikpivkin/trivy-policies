package compute

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type ProjectMetadata struct {
	Metadata      iacTypes.Metadata
	EnableOSLogin iacTypes.BoolValue
}
