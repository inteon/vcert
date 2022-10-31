package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

func GetFileType(f string) string {
	extension := filepath.Ext(f)

	//As yaml extension could be yaml or yml then convert it to just .yaml
	extension = strings.ToLower(extension)
	if extension == ".yml" {
		extension = YamlExtension
	}

	return extension
}

func GetParent(p string) string {
	lastIndex := strings.LastIndex(p, "\\")
	parentPath := p[:lastIndex]
	return parentPath
}

func GetPolicySpecificationFromFile(policySpecLocation string, verify bool) (*PolicySpecification, error) {
	file, bytes, err := GetFileAndBytes(policySpecLocation)
	if err != nil {
		return nil, err
	}
	file.Close() // the file contents are read already

	fileExt := GetFileType(policySpecLocation)
	fileExt = strings.ToLower(fileExt)

	if verify {
		err = VerifyPolicySpec(bytes, fileExt)
		if err != nil {
			err = fmt.Errorf("policy specification file is not valid: %s", err)
			return nil, err
		}
	}

	//based on the extension call the appropriate method to feed the policySpecification
	//structure.
	var policySpecification PolicySpecification
	if fileExt == JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return nil, err
		}
	} else if fileExt == YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("the specified file is not supported")
	}

	return &policySpecification, nil
}

func GetApplicationName(zone string) string {
	data := strings.Split(zone, "\\")
	if data != nil && data[0] != "" {
		return data[0]
	}
	return ""
}

func GetCitName(zone string) string {
	data := strings.Split(zone, "\\")
	if len(data) == 2 {
		return data[1]
	}
	return ""
}

func IsPolicyEmpty(ps *PolicySpecification) bool {
	if ps.Policy == nil {
		return true
	}

	policy := ps.Policy

	if policy.WildcardAllowed != nil {
		return false
	}
	if policy.SubjectAltNames != nil {
		san := policy.SubjectAltNames

		if san.DnsAllowed != nil {
			return false
		}

		if san.UriAllowed != nil {
			return false
		}

		if san.EmailAllowed != nil {
			return false
		}

		if san.IpAllowed != nil {
			return false
		}

		if san.UpnAllowed != nil {
			return false
		}

		if len(san.IpConstraints) > 0 {
			return false
		}

		if len(san.UriProtocols) > 0 {
			return false
		}
	}

	if policy.CertificateAuthority != nil && *(policy.CertificateAuthority) != "" {
		return false
	}

	if policy.MaxValidDays != nil {
		return false
	}

	if len(policy.Domains) > 0 {
		return false
	}

	if policy.Subject != nil {

		subject := policy.Subject

		if len(subject.OrgUnits) > 0 {
			return false
		}
		if len(subject.Countries) > 0 {
			return false
		}
		if len(subject.States) > 0 {
			return false
		}
		if len(subject.Localities) > 0 {
			return false
		}
		if len(subject.Orgs) > 0 {
			return false
		}

	}

	if policy.KeyPair != nil {
		keyPair := policy.KeyPair
		if keyPair.ReuseAllowed != nil {
			return false
		}
		if len(keyPair.RsaKeySizes) > 0 {
			return false
		}
		if len(keyPair.KeyTypes) > 0 {
			return false
		}
		if len(keyPair.EllipticCurves) > 0 {
			return false
		}
		if keyPair.ServiceGenerated != nil {
			return false
		}
	}

	return true
}

func IsDefaultEmpty(ps *PolicySpecification) bool {

	if ps.Default == nil {
		return true
	}

	def := ps.Default

	if def.Domain != nil && *(def.Domain) != "" {
		return false
	}

	if def.KeyPair != nil {
		keyPair := def.KeyPair

		if keyPair.ServiceGenerated != nil {
			return false
		}

		if keyPair.EllipticCurve != nil && *(keyPair.EllipticCurve) != "" {
			return false
		}

		if keyPair.RsaKeySize != nil {
			return false
		}
		if keyPair.KeyType != nil && *(keyPair.KeyType) != "" {
			return false
		}

	}

	if def.Subject != nil {
		subject := def.Subject

		if len(subject.OrgUnits) > 0 {
			return false
		}

		if subject.Org != nil && *(subject.Org) != "" {
			return false
		}

		if subject.State != nil && *(subject.State) != "" {
			return false
		}

		if subject.Country != nil && *(subject.Country) != "" {
			return false
		}

		if subject.Locality != nil && *(subject.Locality) != "" {
			return false
		}

	}

	return true
}

func VerifyPolicySpec(bytes []byte, fileExt string) error {

	var err error
	var policySpecification PolicySpecification

	if fileExt == JsonExtension {
		err = json.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else if fileExt == YamlExtension {
		err = yaml.Unmarshal(bytes, &policySpecification)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("the specified file is not supported")
	}

	return nil
}

func GetFileAndBytes(p string) (*os.File, []byte, error) {
	file, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, nil, err
	}
	return file, bytes, nil
}
func GetPolicySpec() *PolicySpecification {

	emptyString := ""
	intVal := 0
	falseBool := false

	specification := PolicySpecification{
		Policy: &Policy{
			CertificateAuthority: &emptyString,
			Domains:              []string{""},
			WildcardAllowed:      &falseBool,
			AutoInstalled:        &falseBool,
			MaxValidDays:         &intVal,
			Subject: &Subject{
				Orgs:       []string{""},
				OrgUnits:   []string{""},
				Localities: []string{""},
				States:     []string{""},
				Countries:  []string{""},
			},
			KeyPair: &KeyPair{
				KeyTypes:         []string{""},
				RsaKeySizes:      []int{0},
				ServiceGenerated: &falseBool,
				ReuseAllowed:     &falseBool,
				EllipticCurves:   []string{""},
			},
			SubjectAltNames: &SubjectAltNames{
				DnsAllowed:    &falseBool,
				IpAllowed:     &falseBool,
				EmailAllowed:  &falseBool,
				UriAllowed:    &falseBool,
				UpnAllowed:    &falseBool,
				UriProtocols:  []string{""},
				IpConstraints: []string{""},
			},
		},
		Default: &Default{
			Domain: &emptyString,
			Subject: &DefaultSubject{
				Org:      &emptyString,
				OrgUnits: []string{""},
				Locality: &emptyString,
				State:    &emptyString,
				Country:  &emptyString,
			},
			KeyPair: &DefaultKeyPair{
				KeyType:          &emptyString,
				RsaKeySize:       &intVal,
				EllipticCurve:    &emptyString,
				ServiceGenerated: &falseBool,
			},
		},
	}
	return &specification
}
