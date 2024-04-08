package compute

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Disk struct {
	Metadata   iacTypes.Metadata
	Name       iacTypes.StringValue
	Encryption DiskEncryption
}

type DiskEncryption struct {
	Metadata   iacTypes.Metadata
	RawKey     iacTypes.BytesValue
	KMSKeyLink iacTypes.StringValue
}
