package authorization

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Authorization struct {
	RoleDefinitions []RoleDefinition
}

type RoleDefinition struct {
	Metadata         iacTypes.Metadata
	Permissions      []Permission
	AssignableScopes []iacTypes.StringValue
}

type Permission struct {
	Metadata iacTypes.Metadata
	Actions  []iacTypes.StringValue
}
