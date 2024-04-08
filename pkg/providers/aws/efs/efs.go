package efs

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type EFS struct {
	FileSystems []FileSystem
}

type FileSystem struct {
	Metadata  iacTypes.Metadata
	Encrypted iacTypes.BoolValue
}
