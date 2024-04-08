package cheks

import (
	"github.com/aquasecurity/trivy-policies/pkg/scan"
)

var rules []scan.Rule

func Register(r scan.Rule, f scan.CheckFunc) scan.Rule {
	r.Check = f
	rules = append(rules, r)

	return r
}

func GetCheks() []scan.Rule {
	return rules
}
