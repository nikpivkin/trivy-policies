package compute

import (
	iacTypes "github.com/aquasecurity/trivy-policies/pkg/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	Metadata iacTypes.Metadata
	UserData iacTypes.StringValue // not b64 encoded pls
}
