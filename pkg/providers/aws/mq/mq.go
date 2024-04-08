package mq

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type MQ struct {
	Brokers []Broker
}

type Broker struct {
	Metadata     iacTypes.Metadata
	PublicAccess iacTypes.BoolValue
	Logging      Logging
}

type Logging struct {
	Metadata iacTypes.Metadata
	General  iacTypes.BoolValue
	Audit    iacTypes.BoolValue
}
