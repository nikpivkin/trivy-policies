package datalake

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type DataLake struct {
	Stores []Store
}

type Store struct {
	Metadata         iacTypes.Metadata
	EnableEncryption iacTypes.BoolValue
}
