package accessanalyzer

import "github.com/aquasecurity/trivy-policies/pkg/types"

type AccessAnalyzer struct {
	Analyzers []Analyzer
}

type Analyzer struct {
	Metadata types.Metadata
	ARN      types.StringValue
	Name     types.StringValue
	Active   types.BoolValue
	Findings []Findings
}

type Findings struct {
	Metadata types.Metadata
}
