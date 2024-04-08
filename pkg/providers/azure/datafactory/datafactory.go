package datafactory

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	Metadata            iacTypes.Metadata
	EnablePublicNetwork iacTypes.BoolValue
}
