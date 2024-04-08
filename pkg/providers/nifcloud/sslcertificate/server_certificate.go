package sslcertificate

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type ServerCertificate struct {
	Metadata   iacTypes.Metadata
	Expiration iacTypes.TimeValue
}
