/*
 * Copyright 2018-2022 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tpp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

const defaultKeySize = 2048
const defaultSignatureAlgorithm = x509.SHA256WithRSA
const defaultClientID = "vcert-sdk"
const defaultScope = "certificate:manage,revoke"
const defaultWorkloadName = "Default"

func (c *Connector) getHTTPClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	/* #nosec */
	if c.trust != nil {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.RootCAs = c.trust
	}
	netTransport.TLSClientConfig = tlsConfig
	c.client = &http.Client{
		Timeout:   time.Second * 30,
		Transport: netTransport,
	}
	return c.client
}

// GenerateRequest creates a new certificate request, based on the zone/policy configuration and the user data
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	if config == nil {
		config, err = c.ReadZoneConfiguration()
		if err != nil {
			return fmt.Errorf("could not read zone configuration: %s", err)
		}
	}

	tppMgmtType := config.CustomAttributeValues[string(tpp_structs.TppManagementType)]
	if tppMgmtType == "Monitoring" || tppMgmtType == "Unassigned" {
		return fmt.Errorf("Unable to request certificate from TPP, current TPP configuration would not allow the request to be processed")
	}

	config.UpdateCertificateRequest(req)

	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		if config.CustomAttributeValues[string(tpp_structs.TppManualCSR)] == "0" {
			return fmt.Errorf("Unable to request certificate by local generated CSR when zone configuration is 'Manual Csr' = 0")
		}
		err = req.GeneratePrivateKey()
		if err != nil {
			return err
		}
		err = req.GenerateCSR()
		if err != nil {
			return err
		}
	case certificate.UserProvidedCSR:
		if config.CustomAttributeValues[string(tpp_structs.TppManualCSR)] == "0" {
			return fmt.Errorf("Unable to request certificate with user provided CSR when zone configuration is 'Manual Csr' = 0")
		}
		if len(req.GetCSR()) == 0 {
			return fmt.Errorf("CSR was supposed to be provided by user, but it's empty")
		}

	case certificate.ServiceGeneratedCSR:
	}
	return nil
}

func getPolicyDN(zone string) string {
	modified := zone
	reg := regexp.MustCompile(`^\\VED\\Policy`)
	if reg.FindStringIndex(modified) == nil {
		reg = regexp.MustCompile(`^\\`)
		if reg.FindStringIndex(modified) == nil {
			modified = "\\" + modified
		}
		modified = "\\VED\\Policy" + modified
	}
	return modified
}

func getDeviceDN(zone string, location certificate.Location) string {
	workload := location.Workload
	if workload == "" {
		workload = "Default"
	}
	return getPolicyDN(zone + "\\" + location.Instance + "\\" + workload)
}

func getCertificateDN(zone, cn string) string {
	return getPolicyDN(zone + "\\" + cn)
}

func stripBackSlashes(s string) string {

	var r = regexp.MustCompile(`\\+`)

	result := r.ReplaceAll([]byte(s), []byte("\\"))
	return string(result)
}

func newPEMCollectionFromResponse(base64Response string, chainOrder certificate.ChainOption) (*certificate.PEMCollection, error) {
	if base64Response != "" {
		certBytes, err := base64.StdEncoding.DecodeString(base64Response)
		if err != nil {
			return nil, err
		}

		return certificate.PEMCollectionFromBytes(certBytes, chainOrder)
	}
	return nil, nil
}

func serverPolicyToZoneConfig(sp tpp_structs.PolicyResponse, zc *endpoint.ZoneConfiguration) {
	zc.Country = sp.Subject.Country.Value
	zc.Organization = sp.Subject.Organization.Value
	zc.OrganizationalUnit = sp.Subject.OrganizationalUnit.Value
	zc.Province = sp.Subject.State.Value
	zc.Locality = sp.Subject.City.Value
	key := endpoint.AllowedKeyConfiguration{}
	err := key.KeyType.Set(sp.KeyPair.KeyAlgorithm.Value)
	if err != nil {
		return
	}
	if sp.KeyPair.KeySize.Value != 0 {
		key.KeySizes = []int{sp.KeyPair.KeySize.Value}
	}
	if sp.KeyPair.EllipticCurve.Value != "" {
		curve := certificate.EllipticCurveNotSet
		err = curve.Set(sp.KeyPair.EllipticCurve.Value)
		if err == nil {
			key.KeyCurves = append(key.KeyCurves, curve)
		}
	}
	zc.KeyConfiguration = &key
}

func serverPolicyToPolicy(sp tpp_structs.PolicyResponse) (p endpoint.Policy) {
	addStartEnd := func(s string) string {
		if !strings.HasPrefix(s, "^") {
			s = "^" + s
		}
		if !strings.HasSuffix(s, "$") {
			s = s + "$"
		}
		return s
	}
	escapeOne := func(s string) string {
		return addStartEnd(regexp.QuoteMeta(s))
	}
	escapeArray := func(l []string) []string {
		escaped := make([]string, len(l))
		for i, r := range l {
			escaped[i] = escapeOne(r)
		}
		return escaped
	}
	const allAllowedRegex = ".*"
	if len(sp.WhitelistedDomains) == 0 {
		p.SubjectCNRegexes = []string{allAllowedRegex}
	} else {
		p.SubjectCNRegexes = make([]string, len(sp.WhitelistedDomains))
		for i, d := range sp.WhitelistedDomains {
			if sp.WildcardsAllowed {
				p.SubjectCNRegexes[i] = addStartEnd(`([\p{L}\p{N}-*]+\.)*` + regexp.QuoteMeta(d))
			} else {
				p.SubjectCNRegexes[i] = addStartEnd(`([\p{L}\p{N}-]+\.)*` + regexp.QuoteMeta(d))
			}
		}
	}
	if sp.Subject.OrganizationalUnit.Locked {
		p.SubjectOURegexes = escapeArray(sp.Subject.OrganizationalUnit.Value)
	} else {
		p.SubjectOURegexes = []string{allAllowedRegex}
	}
	if sp.Subject.Organization.Locked {
		p.SubjectORegexes = []string{escapeOne(sp.Subject.Organization.Value)}
	} else {
		p.SubjectORegexes = []string{allAllowedRegex}
	}
	if sp.Subject.City.Locked {
		p.SubjectLRegexes = []string{escapeOne(sp.Subject.City.Value)}
	} else {
		p.SubjectLRegexes = []string{allAllowedRegex}
	}
	if sp.Subject.State.Locked {
		p.SubjectSTRegexes = []string{escapeOne(sp.Subject.State.Value)}
	} else {
		p.SubjectSTRegexes = []string{allAllowedRegex}
	}
	if sp.Subject.Country.Locked {
		p.SubjectCRegexes = []string{escapeOne(sp.Subject.Country.Value)}
	} else {
		p.SubjectCRegexes = []string{allAllowedRegex}
	}
	if sp.SubjAltNameDnsAllowed {
		if len(sp.WhitelistedDomains) == 0 {
			p.DnsSanRegExs = []string{allAllowedRegex}
		} else {
			p.DnsSanRegExs = make([]string, len(sp.WhitelistedDomains))
			for i, d := range sp.WhitelistedDomains {
				if sp.WildcardsAllowed {
					p.DnsSanRegExs[i] = addStartEnd(`([\p{L}\p{N}-*]+\.)*` + regexp.QuoteMeta(d))
				} else {
					p.DnsSanRegExs[i] = addStartEnd(`([\p{L}\p{N}-]+\.)*` + regexp.QuoteMeta(d))
				}
			}
		}
	} else {
		p.DnsSanRegExs = []string{}
	}
	if sp.SubjAltNameIpAllowed {
		p.IpSanRegExs = []string{allAllowedRegex}
	} else {
		p.IpSanRegExs = []string{}
	}
	if sp.SubjAltNameEmailAllowed {
		p.EmailSanRegExs = []string{allAllowedRegex}
	} else {
		p.EmailSanRegExs = []string{}
	}
	if sp.SubjAltNameUriAllowed {
		p.UriSanRegExs = []string{allAllowedRegex}
	} else {
		p.UriSanRegExs = []string{}
	}
	if sp.SubjAltNameUpnAllowed {
		p.UpnSanRegExs = []string{allAllowedRegex}
	} else {
		p.UpnSanRegExs = []string{}
	}
	if sp.KeyPair.KeyAlgorithm.Locked {
		var keyType certificate.KeyType
		if err := keyType.Set(sp.KeyPair.KeyAlgorithm.Value); err != nil {
			panic(err)
		}
		key := endpoint.AllowedKeyConfiguration{KeyType: keyType}
		if keyType == certificate.KeyTypeRSA {
			if sp.KeyPair.KeySize.Locked {
				for _, i := range certificate.AllSupportedKeySizes() {
					if i >= sp.KeyPair.KeySize.Value {
						key.KeySizes = append(key.KeySizes, i)
					}
				}
			} else {
				key.KeySizes = certificate.AllSupportedKeySizes()
			}
		} else {
			var curve certificate.EllipticCurve
			if sp.KeyPair.EllipticCurve.Locked {
				if err := curve.Set(sp.KeyPair.EllipticCurve.Value); err != nil {
					panic(err)
				}
				key.KeyCurves = append(key.KeyCurves, curve)
			} else {
				key.KeyCurves = certificate.AllSupportedCurves()
			}

		}
		p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, key)
	} else {
		var ks []int
		for _, s := range certificate.AllSupportedKeySizes() {
			if !sp.KeyPair.KeySize.Locked || s >= sp.KeyPair.KeySize.Value {
				ks = append(ks, s)
			}
		}
		p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, endpoint.AllowedKeyConfiguration{
			KeyType: certificate.KeyTypeRSA, KeySizes: ks,
		})
		if sp.KeyPair.EllipticCurve.Locked {
			var curve certificate.EllipticCurve
			if err := curve.Set(sp.KeyPair.EllipticCurve.Value); err != nil {
				panic(err)
			}
			p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, endpoint.AllowedKeyConfiguration{
				KeyType: certificate.KeyTypeECDSA, KeyCurves: []certificate.EllipticCurve{curve},
			})
		} else {
			p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, endpoint.AllowedKeyConfiguration{
				KeyType: certificate.KeyTypeECDSA, KeyCurves: certificate.AllSupportedCurves(),
			})
		}
	}
	p.AllowWildcards = sp.WildcardsAllowed
	p.AllowKeyReuse = sp.PrivateKeyReuseAllowed
	return
}
