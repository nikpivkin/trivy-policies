package bigquery

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type BigQuery struct {
	Datasets []Dataset
}

type Dataset struct {
	Metadata     iacTypes.Metadata
	ID           iacTypes.StringValue
	AccessGrants []AccessGrant
}

const (
	SpecialGroupAllAuthenticatedUsers = "allAuthenticatedUsers"
)

type AccessGrant struct {
	Metadata     iacTypes.Metadata
	Role         iacTypes.StringValue
	Domain       iacTypes.StringValue
	SpecialGroup iacTypes.StringValue
}
