package tpp_validate

import (
	"path/filepath"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/policy"
)

func TestValidateTPPPolicyData(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := policy.GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	err = validateDefaultKeyPair(policySpecification)
	if err != nil {
		t.Fatalf("Error validating default \nError: %s", err)
	}

	err = validatePolicySubject(policySpecification)
	if err != nil {
		t.Fatalf("Error validating policy subject\nError: %s", err)
	}

}

func TestValidateTppPolicySpecification(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_tpp.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := policy.GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	err = ValidateTppPolicySpecification(policySpecification)
	if err != nil {
		t.Fatalf("Error validating policy specification\nError: %s", err)
	}
}
