package sam

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type HttpAPI struct {
	Metadata             iacTypes.Metadata
	Name                 iacTypes.StringValue
	AccessLogging        AccessLogging
	DefaultRouteSettings RouteSettings
	DomainConfiguration  DomainConfiguration
}

type RouteSettings struct {
	Metadata               iacTypes.Metadata
	LoggingEnabled         iacTypes.BoolValue
	DataTraceEnabled       iacTypes.BoolValue
	DetailedMetricsEnabled iacTypes.BoolValue
}
