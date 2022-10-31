package tpp_convert

import (
	"fmt"
	"strconv"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func BuildTppPolicy(ps *policy.PolicySpecification) tpp_structs.TppPolicy {
	/*
		"owners": string[],					(permissions only)	prefixed name/universal
		"userAccess": string,					(permissions)	prefixed name/universal
		}
	*/
	var tppPolicy tpp_structs.TppPolicy

	tppPolicy.Contact = ps.Users
	tppPolicy.Approver = ps.Approvers

	//policy attributes
	if ps.Policy != nil {
		tppPolicy.DomainSuffixWhitelist = ps.Policy.Domains
	}

	if ps.Policy != nil && ps.Policy.WildcardAllowed != nil {

		if *(ps.Policy.WildcardAllowed) { //this is true so we revert it to false(0)
			intValZero := 0
			tppPolicy.ProhibitWildcard = &intValZero
		} else {
			intValOne := 1
			tppPolicy.ProhibitWildcard = &intValOne
		}

	}

	if ps.Policy != nil && ps.Policy.CertificateAuthority != nil {
		tppPolicy.CertificateAuthority = ps.Policy.CertificateAuthority
	}

	managementType := tpp_structs.TppManagementTypeEnrollment
	if ps.Policy != nil && ps.Policy.AutoInstalled != nil {
		if *(ps.Policy.AutoInstalled) {
			managementType = tpp_structs.TppManagementTypeProvisioning
		}
		tppPolicy.ManagementType = createLockedAttribute(managementType, true)
	} else if ps.Default != nil && ps.Default.AutoInstalled != nil {
		if *(ps.Default.AutoInstalled) {
			managementType = tpp_structs.TppManagementTypeProvisioning
		}
		tppPolicy.ManagementType = createLockedAttribute(managementType, false)
	}

	//policy subject attributes
	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Orgs) > 0 && ps.Policy.Subject.Orgs[0] != "" {
		tppPolicy.Organization = createLockedAttribute(ps.Policy.Subject.Orgs[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && *(ps.Default.Subject.Org) != "" {
		tppPolicy.Organization = createLockedAttribute(*(ps.Default.Subject.Org), false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.OrgUnits) > 0 && ps.Policy.Subject.OrgUnits[0] != "" {
		tppPolicy.OrganizationalUnit = createLockedArrayAttribute(ps.Policy.Subject.OrgUnits, true)
	} else if ps.Default != nil && ps.Default.Subject != nil && len(ps.Default.Subject.OrgUnits) > 0 && ps.Default.Subject.OrgUnits[0] != "" {
		tppPolicy.OrganizationalUnit = createLockedArrayAttribute(ps.Default.Subject.OrgUnits, false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Localities) > 0 && ps.Policy.Subject.Localities[0] != "" {
		tppPolicy.City = createLockedAttribute(ps.Policy.Subject.Localities[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && (ps.Default.Subject.Locality != nil) && (*(ps.Default.Subject.Locality) != "") {
		tppPolicy.City = createLockedAttribute(*(ps.Default.Subject.Locality), false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.States) > 0 && ps.Policy.Subject.States[0] != "" {
		tppPolicy.State = createLockedAttribute(ps.Policy.Subject.States[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && (ps.Default.Subject.State != nil) && (*(ps.Default.Subject.State) != "") {
		tppPolicy.State = createLockedAttribute(*(ps.Default.Subject.State), false)
	}

	if ps.Policy != nil && ps.Policy.Subject != nil && len(ps.Policy.Subject.Countries) > 0 && ps.Policy.Subject.Countries[0] != "" {
		tppPolicy.Country = createLockedAttribute(ps.Policy.Subject.Countries[0], true)
	} else if ps.Default != nil && ps.Default.Subject != nil && (ps.Default.Subject.Country != nil) && (*(ps.Default.Subject.Country) != "") {
		tppPolicy.Country = createLockedAttribute(*(ps.Default.Subject.Country), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.KeyTypes) > 0 && ps.Policy.KeyPair.KeyTypes[0] != "" {
		tppPolicy.KeyAlgorithm = createLockedAttribute(ps.Policy.KeyPair.KeyTypes[0], true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.KeyType != nil) && (*(ps.Default.KeyPair.KeyType) != "") {
		tppPolicy.KeyAlgorithm = createLockedAttribute(*(ps.Default.KeyPair.KeyType), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.RsaKeySizes) > 0 && ps.Policy.KeyPair.RsaKeySizes[0] != 0 {
		rsaKey := ps.Policy.KeyPair.RsaKeySizes[0]
		tppPolicy.KeyBitStrength = createLockedAttribute(strconv.Itoa(rsaKey), true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.RsaKeySize != nil) && *(ps.Default.KeyPair.RsaKeySize) != 0 {
		tppPolicy.KeyBitStrength = createLockedAttribute(strconv.Itoa(*(ps.Default.KeyPair.RsaKeySize)), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && len(ps.Policy.KeyPair.EllipticCurves) > 0 && ps.Policy.KeyPair.EllipticCurves[0] != "" {
		tppPolicy.EllipticCurve = createLockedAttribute(ps.Policy.KeyPair.EllipticCurves[0], true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.EllipticCurve != nil) && (*(ps.Default.KeyPair.EllipticCurve) != "") {
		tppPolicy.EllipticCurve = createLockedAttribute(*(ps.Default.KeyPair.EllipticCurve), false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && ps.Policy.KeyPair.ServiceGenerated != nil {
		strVal := "1"
		if *(ps.Policy.KeyPair.ServiceGenerated) {
			strVal = "0"
		}
		tppPolicy.ManualCsr = createLockedAttribute(strVal, true)
	} else if ps.Default != nil && ps.Default.KeyPair != nil && (ps.Default.KeyPair.ServiceGenerated != nil) {
		strVal := "1"
		if *(ps.Default.KeyPair.ServiceGenerated) {
			strVal = "0"
		}
		tppPolicy.ManualCsr = createLockedAttribute(strVal, false)
	}

	if ps.Policy != nil && ps.Policy.KeyPair != nil && ps.Policy.KeyPair.ReuseAllowed != nil {

		var intVal int
		if *(ps.Policy.KeyPair.ReuseAllowed) {
			intVal = 1
		} else {
			intVal = 0
		}

		tppPolicy.AllowPrivateKeyReuse = &intVal
		tppPolicy.WantRenewal = &intVal
	}

	if ps.Policy != nil && ps.Policy.SubjectAltNames != nil {
		prohibitedSANType := getProhibitedSanTypes(*(ps.Policy.SubjectAltNames))
		if prohibitedSANType != nil {
			tppPolicy.ProhibitedSANType = prohibitedSANType
		}
	}

	return tppPolicy
}

func createLockedAttribute(value string, locked bool) *tpp_structs.LockedAttribute {
	lockedAtr := tpp_structs.LockedAttribute{
		Value:  value,
		Locked: locked,
	}
	return &lockedAtr
}

func createLockedArrayAttribute(value []string, locked bool) *tpp_structs.LockedArrayAttribute {
	lockedAtr := tpp_structs.LockedArrayAttribute{
		Value:  value,
		Locked: locked,
	}
	return &lockedAtr
}

func getProhibitedSanTypes(sa policy.SubjectAltNames) []string {

	var prohibitedSanTypes []string

	if (sa.DnsAllowed != nil) && !*(sa.DnsAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "DNS")
	}
	if (sa.IpAllowed != nil) && !*(sa.IpAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "IP")
	}

	if (sa.EmailAllowed != nil) && !*(sa.EmailAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "Email")
	}

	if (sa.UriAllowed != nil) && !*(sa.UriAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "URI")
	}

	if (sa.UpnAllowed != nil) && !*(sa.UpnAllowed) {
		prohibitedSanTypes = append(prohibitedSanTypes, "UPN")
	}

	if len(prohibitedSanTypes) == 0 {
		return nil
	}

	return prohibitedSanTypes
}

func BuildPolicySpecificationForTPP(checkPolicyResp tpp_structs.CheckPolicyResponse) (*policy.PolicySpecification, error) {
	if checkPolicyResp.Policy == nil {
		return nil, fmt.Errorf("policy is nul")
	}

	policyResponse := checkPolicyResp.Policy
	var ps policy.PolicySpecification

	/*ps.Users = tppPolicy.Contact
	ps.Approvers = tppPolicy.Approver*/

	var p policy.Policy

	if policyResponse.WhitelistedDomains != nil {
		p.Domains = policyResponse.WhitelistedDomains
	}

	if policyResponse.CertificateAuthority.Value != "" {
		p.CertificateAuthority = &policyResponse.CertificateAuthority.Value
	}

	var subject policy.Subject
	shouldCreateSubject := false
	var defaultSubject policy.DefaultSubject
	shouldCreateDefSubject := false

	var keyPair policy.KeyPair
	shouldCreateKeyPair := false
	var defaultKeyPair policy.DefaultKeyPair
	shouldCreateDefKeyPair := false

	var def policy.Default

	p.WildcardAllowed = &policyResponse.WildcardsAllowed

	if policyResponse.ManagementType.Value != "" {
		boolVal := false
		if policyResponse.ManagementType.Value == tpp_structs.TppManagementTypeProvisioning {
			boolVal = true
		}
		if policyResponse.ManagementType.Locked {
			p.AutoInstalled = &boolVal
		} else {
			def.AutoInstalled = &boolVal
		}
	}

	//resolve subject's attributes

	//resolve org
	if policyResponse.Subject.Organization.Value != "" {
		if policyResponse.Subject.Organization.Locked {
			shouldCreateSubject = true
			subject.Orgs = []string{policyResponse.Subject.Organization.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.Org = &policyResponse.Subject.Organization.Value
		}
	}

	//resolve orgUnit

	if len(policyResponse.Subject.OrganizationalUnit.Value) > 0 {
		if policyResponse.Subject.OrganizationalUnit.Locked {
			shouldCreateSubject = true
			subject.OrgUnits = policyResponse.Subject.OrganizationalUnit.Value
		} else {
			shouldCreateDefSubject = true
			defaultSubject.OrgUnits = policyResponse.Subject.OrganizationalUnit.Value
		}
	}

	//resolve localities
	if policyResponse.Subject.City.Value != "" {
		if policyResponse.Subject.City.Locked {
			shouldCreateSubject = true
			subject.Localities = []string{policyResponse.Subject.City.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.Locality = &policyResponse.Subject.City.Value
		}
	}

	//resolve states

	if policyResponse.Subject.State.Value != "" {
		if policyResponse.Subject.State.Locked {
			shouldCreateSubject = true
			subject.States = []string{policyResponse.Subject.State.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.State = &policyResponse.Subject.State.Value
		}
	}

	//resolve countries
	if policyResponse.Subject.Country.Value != "" {
		if policyResponse.Subject.Country.Locked {
			shouldCreateSubject = true
			subject.Countries = []string{policyResponse.Subject.Country.Value}
		} else {
			shouldCreateDefSubject = true
			defaultSubject.Country = &policyResponse.Subject.Country.Value
		}
	}

	//resolve key pair's attributes

	//resolve keyTypes
	if policyResponse.KeyPair.KeyAlgorithm.Value != "" {
		if policyResponse.KeyPair.KeyAlgorithm.Locked {
			keyPair.KeyTypes = []string{policyResponse.KeyPair.KeyAlgorithm.Value}
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.KeyType = &policyResponse.KeyPair.KeyAlgorithm.Value
		}
	}

	//resolve rsaKeySizes
	if policyResponse.KeyPair.KeySize.Value > 0 {
		if policyResponse.KeyPair.KeySize.Locked {
			keyPair.RsaKeySizes = []int{policyResponse.KeyPair.KeySize.Value}
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.RsaKeySize = &policyResponse.KeyPair.KeySize.Value
		}
	}

	//resolve ellipticCurves
	/*if tppPolicy.EllipticCurve != nil {
		if tppPolicy.EllipticCurve.Locked {
			shouldCreateKeyPair = true
			keyPair.EllipticCurves = []string{tppPolicy.EllipticCurve.Value}
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.EllipticCurve = &tppPolicy.EllipticCurve.Value
		}
	}*/

	//resolve generationType

	value := policyResponse.CsrGeneration.Value
	if value != "" {
		booleanValue := true

		//this mean that is a generated csr so ServiceGenerated is false
		if value == policy.UserProvided {
			booleanValue = false
		}

		if policyResponse.CsrGeneration.Locked {
			keyPair.ServiceGenerated = &booleanValue
		} else {
			shouldCreateDefKeyPair = true
			defaultKeyPair.ServiceGenerated = &booleanValue
		}
	}

	keyPair.ReuseAllowed = &policyResponse.PrivateKeyReuseAllowed
	shouldCreateKeyPair = true

	//assign policy's subject and key pair values
	if shouldCreateSubject {
		p.Subject = &subject
	}
	if shouldCreateKeyPair {
		p.KeyPair = &keyPair
	}
	subjectAltNames := resolveSubjectAltNames((*policyResponse))

	if subjectAltNames != nil {
		p.SubjectAltNames = subjectAltNames
	}

	//set policy and defaults to policy specification.
	ps.Policy = &p

	if shouldCreateDefSubject {
		def.Subject = &defaultSubject
	}
	if shouldCreateDefKeyPair {
		def.KeyPair = &defaultKeyPair
	}

	if shouldCreateDefSubject || shouldCreateDefKeyPair || def.AutoInstalled != nil {
		ps.Default = &def
	}

	return &ps, nil

}

func resolveSubjectAltNames(policyResponse tpp_structs.PolicyResponse) *policy.SubjectAltNames {

	trueVal := true
	falseVal := false
	var subjectAltName policy.SubjectAltNames

	if policyResponse.SubjAltNameDnsAllowed {
		subjectAltName.DnsAllowed = &trueVal
	} else {
		subjectAltName.DnsAllowed = &falseVal
	}

	if policyResponse.SubjAltNameIpAllowed {
		subjectAltName.IpAllowed = &trueVal
	} else {
		subjectAltName.IpAllowed = &falseVal
	}

	if policyResponse.SubjAltNameEmailAllowed {
		subjectAltName.EmailAllowed = &trueVal
	} else {
		subjectAltName.EmailAllowed = &falseVal
	}

	if policyResponse.SubjAltNameUriAllowed {
		subjectAltName.UriAllowed = &trueVal
	} else {
		subjectAltName.UriAllowed = &falseVal
	}

	if policyResponse.SubjAltNameUpnAllowed {
		subjectAltName.UpnAllowed = &trueVal
	} else {
		subjectAltName.UpnAllowed = &falseVal
	}

	return &subjectAltName
}
