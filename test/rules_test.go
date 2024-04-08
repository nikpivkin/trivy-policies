package test

import (
	"testing"

	"github.com/aquasecurity/trivy-policies/pkg/framework"
	"github.com/aquasecurity/trivy-policies/pkg/registry"
)

func TestAVDIDs(t *testing.T) {
	existing := make(map[string]struct{})
	for _, rule := range registry.GetRegistered(framework.ALL) {
		t.Run(rule.LongID(), func(t *testing.T) {
			if rule.GetRule().AVDID == "" {
				t.Errorf("Rule has no AVD ID: %#v", rule)
				return
			}
			if _, ok := existing[rule.GetRule().AVDID]; ok {
				t.Errorf("Rule detected with duplicate AVD ID: %s", rule.GetRule().AVDID)
			}
		})
		existing[rule.GetRule().AVDID] = struct{}{}
	}
}
