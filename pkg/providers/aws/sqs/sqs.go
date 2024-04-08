package sqs

import (
	"github.com/aquasecurity/trivy-policies/pkg/providers/aws/iam"
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type SQS struct {
	Queues []Queue
}

type Queue struct {
	Metadata   iacTypes.Metadata
	QueueURL   iacTypes.StringValue
	Encryption Encryption
	Policies   []iam.Policy
}

type Encryption struct {
	Metadata          iacTypes.Metadata
	KMSKeyID          iacTypes.StringValue
	ManagedEncryption iacTypes.BoolValue
}
