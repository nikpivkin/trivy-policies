package config

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Config struct {
	ConfigurationAggregrator ConfigurationAggregrator
}

type ConfigurationAggregrator struct {
	Metadata         iacTypes.Metadata
	SourceAllRegions iacTypes.BoolValue
}
