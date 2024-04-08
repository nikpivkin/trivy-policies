package main

import (
	"fmt"
	"os"

	_ "github.com/aquasecurity/trivy-policies/pkg/rego" // register Built-in Functions
	"github.com/open-policy-agent/opa/cmd"
)

func main() {
	// runs: opa test lib/ checks/
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
