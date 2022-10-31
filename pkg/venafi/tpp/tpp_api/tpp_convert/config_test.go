package tpp_convert

import (
	"path/filepath"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
	"github.com/smartystreets/assertions"
)

func TestBuildTppPolicy(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_cloud.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := policy.GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	tppPol := BuildTppPolicy(policySpecification)

	if tppPol.Country == nil {
		t.Fatal("country property is nil")
	}

	if tppPol.State == nil {
		t.Fatal("state property is nil")
	}

	if tppPol.OrganizationalUnit == nil {
		t.Fatal("ou property is nil")
	}

	if tppPol.City == nil {
		t.Fatal("city property is nil")
	}

	if tppPol.KeyAlgorithm == nil {
		t.Fatal("key algorithm property is nil")
	}

}

func TestBuildTppPolicyWithDefaults(t *testing.T) {
	absPath, err := filepath.Abs("../../test-files/policy_specification_tpp_management.json")

	if err != nil {
		t.Fatalf("Error opening policy specification\nError: %s", err)
	}

	policySpecification, err := policy.GetPolicySpecificationFromFile(absPath, true)
	if err != nil {
		t.Fatalf("Error loading specification \nError: %s", err)
	}

	tppPol := BuildTppPolicy(policySpecification)

	assertions.ShouldNotBeEmpty(tppPol)

}

func TestBuildPolicySpecificationForTPP(t *testing.T) {

	policy := getPolicyResponse(false)

	policyResp := tpp_structs.CheckPolicyResponse{
		Error:  "",
		Policy: &policy,
	}

	_, err := BuildPolicySpecificationForTPP(policyResp)
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}
}
func TestBuildPolicySpecificationForTPPLocked(t *testing.T) {

	policy := getPolicyResponse(true)

	policyResp := tpp_structs.CheckPolicyResponse{
		Error:  "",
		Policy: &policy,
	}

	_, err := BuildPolicySpecificationForTPP(policyResp)
	if err != nil {
		t.Fatalf("Error building policy specification \nError: %s", err)
	}
}

func getPolicyResponse(lockedAttribute bool) tpp_structs.PolicyResponse {
	return tpp_structs.PolicyResponse{
		CertificateAuthority: tpp_structs.LockedAttribute{
			Value:  "test ca",
			Locked: lockedAttribute,
		},
		CsrGeneration: tpp_structs.LockedAttribute{
			Value:  "0",
			Locked: lockedAttribute,
		},
		KeyGeneration: tpp_structs.LockedAttribute{
			Value:  "",
			Locked: lockedAttribute,
		},
		KeyPair: tpp_structs.KeyPairResponse{
			KeyAlgorithm: tpp_structs.LockedAttribute{
				Value:  "RSA",
				Locked: lockedAttribute,
			},
			KeySize: tpp_structs.LockedIntAttribute{
				Value:  2048,
				Locked: lockedAttribute,
			},
		},
		ManagementType: tpp_structs.LockedAttribute{
			Value:  "Provisioning",
			Locked: lockedAttribute,
		},
		PrivateKeyReuseAllowed:  false,
		SubjAltNameDnsAllowed:   false,
		SubjAltNameEmailAllowed: false,
		SubjAltNameIpAllowed:    false,
		SubjAltNameUpnAllowed:   false,
		SubjAltNameUriAllowed:   false,
		Subject: tpp_structs.SubjectResponse{
			City: tpp_structs.LockedAttribute{
				Value:  "Merida",
				Locked: lockedAttribute,
			},
			Country: tpp_structs.LockedAttribute{
				Value:  "MX",
				Locked: lockedAttribute,
			},
			Organization: tpp_structs.LockedAttribute{
				Value:  "Venafi",
				Locked: lockedAttribute,
			},
			OrganizationalUnit: tpp_structs.LockedArrayAttribute{
				Value:  []string{"DevOps", "QA"},
				Locked: lockedAttribute,
			},
			State: tpp_structs.LockedAttribute{
				Value:  "Yucatan",
				Locked: lockedAttribute,
			},
		},
		UniqueSubjectEnforced: false,
		WhitelistedDomains:    []string{"venafi.com", "kwantec.com"},
		WildcardsAllowed:      false,
	}
}
