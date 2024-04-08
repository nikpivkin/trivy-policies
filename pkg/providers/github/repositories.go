package github

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Repository struct {
	Metadata            iacTypes.Metadata
	Public              iacTypes.BoolValue
	VulnerabilityAlerts iacTypes.BoolValue
	Archived            iacTypes.BoolValue
}

func (r Repository) IsArchived() bool {
	return r.Archived.IsTrue()
}
