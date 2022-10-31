package tpp_validate

import (
	"fmt"

	"github.com/Venafi/vcert/v4/pkg/policy"
)

// there is no way for creating an array as constant, so creating a variable
// this is the nearest to a constant on arrays.
var TppKeyType = []string{"RSA", "ECDSA"}
var TppRsaKeySize = []int{512, 1024, 2048, 3072, 4096}
var TppEllipticCurves = []string{"P256", "P384", "P521"}

func existStringInArray(userValue []string, supportedValues []string) bool {
	for _, uv := range userValue {
		match := false
		for _, sv := range supportedValues {
			if uv == sv {
				match = true
			}
		}
		if !match {
			return false
		}
	}
	return true
}

func existIntInArray(userValue []int, supportedValues []int) bool {
	for _, uv := range userValue {
		match := false
		for _, sv := range supportedValues {
			if uv == sv {
				match = true
			}
		}
		if !match {
			return false
		}
	}

	return true
}

func ValidateTppPolicySpecification(ps *policy.PolicySpecification) error {
	if ps.Policy != nil {
		err := validatePolicySubject(ps)
		if err != nil {
			return err
		}

		err = validateKeyPair(ps)
		if err != nil {
			return err
		}
	}

	err := validateDefaultSubject(ps)
	if err != nil {
		return err
	}

	err = validateDefaultKeyPairWithPolicySubject(ps)
	if err != nil {
		return err
	}

	err = validateDefaultKeyPair(ps)
	if err != nil {
		return err
	}

	if ps.Default != nil && ps.Default.AutoInstalled != nil && ps.Policy != nil && ps.Policy.AutoInstalled != nil {
		if *(ps.Default.AutoInstalled) != *(ps.Policy.AutoInstalled) {
			return fmt.Errorf("default autoInstalled attribute value doesn't match with policy's autoInstalled attribute value")
		}
	}

	return nil
}

func validatePolicySubject(ps *policy.PolicySpecification) error {
	if ps.Policy.Subject == nil {
		return nil
	}
	subject := ps.Policy.Subject

	if len(subject.Orgs) > 1 {
		return fmt.Errorf("attribute orgs has more than one value")
	}
	if len(subject.Localities) > 1 {
		return fmt.Errorf("attribute localities has more than one value")
	}
	if len(subject.States) > 1 {
		return fmt.Errorf("attribute states has more than one value")
	}
	if len(subject.Countries) > 1 {
		return fmt.Errorf("attribute countries has more than one value")
	}

	if len(subject.Countries) > 0 {
		if len(subject.Countries[0]) != 2 {
			return fmt.Errorf("number of country's characters, doesn't match to two characters")
		}
	}

	return nil
}

func validateKeyPair(ps *policy.PolicySpecification) error {
	if ps.Policy.KeyPair == nil {
		return nil
	}
	keyPair := ps.Policy.KeyPair

	//validate algorithm
	if len(keyPair.KeyTypes) > 1 {
		return fmt.Errorf("attribute keyTypes has more than one value")
	}
	if len(keyPair.KeyTypes) > 0 && !existStringInArray(keyPair.KeyTypes, TppKeyType) {
		return fmt.Errorf("specified keyTypes doesn't match with the supported ones")
	}

	//validate key bit strength
	if len(keyPair.RsaKeySizes) > 1 {
		return fmt.Errorf("attribute rsaKeySizes has more than one value")
	}
	if len(keyPair.RsaKeySizes) > 0 && !existIntInArray(keyPair.RsaKeySizes, TppRsaKeySize) {
		return fmt.Errorf("specified rsaKeySizes doesn't match with the supported ones")
	}

	//validate elliptic curve
	if len(keyPair.EllipticCurves) > 1 {
		return fmt.Errorf("attribute ellipticCurves has more than one value")
	}
	if len(keyPair.EllipticCurves) > 0 && !existStringInArray(keyPair.EllipticCurves, TppEllipticCurves) {
		return fmt.Errorf("specified ellipticCurves doesn't match with the supported ones")
	}

	return nil
}

func validateDefaultSubject(ps *policy.PolicySpecification) error {
	if ps.Default != nil && ps.Default.Subject != nil {

		defaultSubject := ps.Default.Subject

		if ps.Policy != nil && ps.Policy.Subject != nil {

			policySubject := ps.Policy.Subject

			if policySubject.Orgs != nil && policySubject.Orgs[0] != "" && defaultSubject.Org != nil && *(defaultSubject.Org) != "" {
				if policySubject.Orgs[0] != *(defaultSubject.Org) {
					return fmt.Errorf("policy default org doesn't match with policy's orgs value")
				}
			}

			if len(policySubject.OrgUnits) > 0 && len(defaultSubject.OrgUnits) > 0 {
				if !existStringInArray(defaultSubject.OrgUnits, policySubject.OrgUnits) {
					return fmt.Errorf("policy default orgUnits doesn't match with policy's orgUnits value")
				}
			}

			if policySubject.Localities != nil && policySubject.Localities[0] != "" && defaultSubject.Locality != nil && *(defaultSubject.Locality) != "" {
				if policySubject.Localities[0] != *(defaultSubject.Locality) {
					return fmt.Errorf("policy default locality doesn't match with policy's localities value")
				}
			}
			if policySubject.States != nil && policySubject.States[0] != "" && defaultSubject.State != nil && *(defaultSubject.State) != "" {
				if policySubject.States[0] != *(defaultSubject.State) {
					return fmt.Errorf("policy default state doesn't match with policy's states value")
				}
			}
			if policySubject.Countries != nil && policySubject.Countries[0] != "" && defaultSubject.Country != nil && *(defaultSubject.Country) != "" {
				if policySubject.Countries[0] != *(defaultSubject.Country) {
					return fmt.Errorf("policy default country doesn't match with policy's countries value")
				}
			}
			if defaultSubject.Country != nil && *(defaultSubject.Country) != "" {
				if len(*(defaultSubject.Country)) != 2 {
					return fmt.Errorf("number of defualt country's characters, doesn't match to two characters")
				}
			}
		} else {
			//there is nothing to validate
			return nil
		}
	}

	return nil
}

func validateDefaultKeyPairWithPolicySubject(ps *policy.PolicySpecification) error {
	if ps.Default == nil || ps.Default.KeyPair == nil || ps.Policy == nil || ps.Policy.KeyPair == nil {
		return nil
	}
	defaultKeyPair := ps.Default.KeyPair
	policyKeyPair := ps.Policy.KeyPair

	if policyKeyPair.KeyTypes != nil && policyKeyPair.KeyTypes[0] != "" && defaultKeyPair.KeyType != nil && *(defaultKeyPair.KeyType) != "" {
		if policyKeyPair.KeyTypes[0] != *(defaultKeyPair.KeyType) {
			return fmt.Errorf("policy default keyType doesn't match with policy's keyType value")
		}
	}

	if policyKeyPair.RsaKeySizes != nil && policyKeyPair.RsaKeySizes[0] != 0 && defaultKeyPair.RsaKeySize != nil && *(defaultKeyPair.RsaKeySize) != 0 {
		if policyKeyPair.RsaKeySizes[0] != *(defaultKeyPair.RsaKeySize) {
			return fmt.Errorf("policy default rsaKeySize doesn't match with policy's rsaKeySize value")
		}
	}

	if policyKeyPair.EllipticCurves != nil && policyKeyPair.EllipticCurves[0] != "" && defaultKeyPair.EllipticCurve != nil && *(defaultKeyPair.EllipticCurve) != "" {
		if policyKeyPair.EllipticCurves[0] != *(defaultKeyPair.EllipticCurve) {
			return fmt.Errorf("policy default ellipticCurve doesn't match with policy's ellipticCurve value")
		}
	}

	if policyKeyPair.ServiceGenerated != nil && defaultKeyPair.ServiceGenerated != nil {
		if *(policyKeyPair.ServiceGenerated) != *(defaultKeyPair.ServiceGenerated) {
			return fmt.Errorf("policy default serviceGenerated generated doesn't match with policy's serviceGenerated value")
		}
	}

	return nil
}

func validateDefaultKeyPair(ps *policy.PolicySpecification) error {
	if ps.Default == nil {
		return nil
	}

	if ps.Default.KeyPair == nil {
		return nil
	}

	keyPair := ps.Default.KeyPair

	if keyPair.KeyType != nil && *(keyPair.KeyType) != "" && !existStringInArray([]string{*(keyPair.KeyType)}, TppKeyType) {
		return fmt.Errorf("specified default keyType doesn't match with the supported ones")
	}

	//validate key bit strength
	if keyPair.RsaKeySize != nil && *(keyPair.RsaKeySize) > 0 && !existIntInArray([]int{*(keyPair.RsaKeySize)}, TppRsaKeySize) {
		return fmt.Errorf("specified default rsaKeySize doesn't match with the supported ones")
	}

	//validate elliptic curve
	if keyPair.EllipticCurve != nil && *(keyPair.EllipticCurve) != "" && !existStringInArray([]string{*(keyPair.EllipticCurve)}, TppEllipticCurves) {
		return fmt.Errorf("specified default ellipticCurve doesn't match with the supported ones")
	}

	return nil
}
