package storage

import (
	"github.com/aquasecurity/trivy-policies/pkg/providers/google/iam"
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Storage struct {
	Buckets []Bucket
}

type Bucket struct {
	Metadata                       iacTypes.Metadata
	Name                           iacTypes.StringValue
	Location                       iacTypes.StringValue
	EnableUniformBucketLevelAccess iacTypes.BoolValue
	Members                        []iam.Member
	Bindings                       []iam.Binding
	Encryption                     BucketEncryption
}

type BucketEncryption struct {
	Metadata          iacTypes.Metadata
	DefaultKMSKeyName iacTypes.StringValue
}
