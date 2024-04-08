package nas

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type NASInstance struct {
	Metadata  iacTypes.Metadata
	NetworkID iacTypes.StringValue
}
