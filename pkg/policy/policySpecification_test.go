package policy

import (
	"path/filepath"
	"testing"
)

func TestEmptyPolicy(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/empty_policy.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	isEmpty := IsPolicyEmpty(policySpecification)
	if !isEmpty {
		t.Fatalf("Policy in policy specification is not empty")
	}

	isEmpty = IsPolicyEmpty(policySpecification)
	if !isEmpty {
		t.Fatalf("Default in policy specification is not empty")
	}
}

func TestGetZoneInfo(t *testing.T) {
	originalAPP := "DevOps"
	originalCit := "Open Source"
	zone := originalAPP + "\\" + originalCit
	app := GetApplicationName(zone)
	cit := GetCitName(zone)

	if originalAPP != app {
		t.Fatalf("app name is different, expected: %s but get: %s", originalAPP, app)
	}

	if originalCit != cit {
		t.Fatalf("cit name is different, expected: %s but get: %s", originalCit, cit)
	}
}

func TestGetEmptyPolicySpec(t *testing.T) {
	//get the policy specification template
	spec := GetPolicySpec()
	if spec == nil {
		t.Fatal("policy specification is nil")
	}

	isEmpty := IsPolicyEmpty(spec)
	//policy spec shouldn't be empty, should have attributes.
	if isEmpty {
		t.Fatal("policy specification is empty")
	}
}
