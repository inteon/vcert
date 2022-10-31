/*
 * Copyright 2018 Venafi, Inc.
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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
	"github.com/Venafi/vcert/v4/test"
)

func TestRequestAndSearchCertificate(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	config, err := tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	cn := test.RandCN()
	appInfo := "APP Info " + cn
	workload := fmt.Sprintf("workload-%d", time.Now().Unix())
	instance := "devops-instance"
	cfValue := cn
	req := &certificate.Request{Timeout: time.Second * 30}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	u := url.URL{Scheme: "https", Host: "example.com", Path: "/test"}
	req.URIs = []*url.URL{&u}
	req.FriendlyName = cn
	req.CustomFields = []certificate.CustomField{
		{Name: "custom", Value: cfValue},
		{Type: certificate.CustomFieldOrigin, Value: appInfo},
	}
	req.Location = &certificate.Location{
		Instance:   instance,
		Workload:   workload,
		TLSAddress: "wwww.example.com:443",
	}

	req.KeyLength = 1024

	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req.PickupID, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	certCollections, err := tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode([]byte(certCollections.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	if cert.Subject.CommonName != cn {
		t.Fatalf("mismatched common names: %v and %v", cn, cert.Subject.CommonName)
	}
	if cert.URIs[0].String() != u.String() {
		t.Fatalf("mismatched URIs: %v and %v", u.String(), cert.URIs[0].String())
	}

	thumbprint := calcThumbprint(certCollections.Certificate)
	searchResult, err := tpp.searchCertificatesByFingerprint(thumbprint)
	if err != nil {
		t.Fatal(err)
	}

	guid := searchResult.Certificates[0].Guid
	details, err := tpp.searchCertificateDetails(guid)
	if err != nil {
		t.Fatal(err)
	}

	//check custom fields
	if details.CustomFields[0].Value[0] != cfValue {
		t.Fatalf("mismtached custom field valud: want %s but got %s", details.CustomFields[0].Value[0], cfValue)
	}

	//check installed location device
	if !strings.HasSuffix(details.Consumers[0], instance+"\\"+workload) {
		t.Fatalf("Consumer %s should end on %s", details.Consumers[0], instance+"\\"+workload)
	}

	configReq := tpp_structs.ConfigReadDNRequest{
		ObjectDN:      getCertificateDN(ctx.TPPZone, cn),
		AttributeName: "Origin",
	}

	configResp, err := tpp.configReadDN(configReq)
	if err != nil {
		t.Fatal(err)
	}
	if configResp.Values[0] != appInfo {
		t.Fatalf("Origin attribute value should be %s, but it is %s", appInfo, configResp.Values[0])
	}

	//add one more device
	req.Location = &certificate.Location{
		Instance:   instance,
		Workload:   workload + "-1",
		TLSAddress: "wwww.example.com:443",
	}

	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req.PickupID, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	//to wait until cert will be aprooved so we can check list of devices
	_, err = tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}

	details, err = tpp.searchCertificateDetails(guid)
	if err != nil {
		t.Fatal(err)
	}

	if len(details.Consumers) < 1 {
		t.Fatal("There should be at least two devices in consumers")
	}
	//check installed location device
	if !strings.HasSuffix(details.Consumers[1], instance+"\\"+workload+"-1") {
		t.Fatalf("Consumer %s should end on %s", details.Consumers[1], instance+"\\"+workload+"-1")
	}

	//replace first device, second must be kept
	req.Location = &certificate.Location{
		Instance:   instance,
		Workload:   workload,
		TLSAddress: "wwww.example.com:443",
		Replace:    true,
	}

	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req.PickupID, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	//to wait until cert will be aprooved so we can check list of devices
	_, err = tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}

	details, err = tpp.searchCertificateDetails(guid)
	if err != nil {
		t.Fatal(err)
	}

	if len(details.Consumers) < 1 {
		t.Fatal("There should be at least two devices in consumers")
	}

	//check installed location device
	if !strings.HasSuffix(details.Consumers[0], instance+"\\"+workload+"-1") {
		t.Fatalf("Consumer %s should end on %s", details.Consumers[0], instance+"\\"+workload+"-1")
	}
}

func TestSearchDevice(t *testing.T) {
	t.Skip() //we don't use this method now, keep this test for future usage

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	authResp, err := tpp.GetRefreshToken(&endpoint.Authentication{
		User: ctx.TPPuser, Password: ctx.TPPPassword,
		Scope: "configuration:read"})
	if err != nil {
		panic(err)
	}

	err = tpp.Authenticate(&endpoint.Authentication{
		AccessToken: authResp.Access_token,
	})

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req := tpp_structs.ConfigReadDNRequest{
		ObjectDN:      "\\VED\\Policy\\devops\\vcert\\kube-worker-1\\nginx_246",
		AttributeName: "Certificate",
	}

	resp, err := tpp.configReadDN(req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(resp)
}

type FormatSearchCertificateArgumentsMock struct {
	zone            string
	cn              string
	sans            *certificate.Sans
	certMinTimeLeft time.Duration
}

// TODO: find a way to test the correct time
func TestFormatSearchCertificateArguments(t *testing.T) {
	timeRegex := "((?:(\\d{4}-\\d{2}-\\d{2})T(\\d{2}%3A\\d{2}%3A\\d{2}(?:\\.\\d+)?))(Z|[\\+-]\\d{2}%3A\\d{2})?)$"
	testCases := []struct {
		name     string
		input    FormatSearchCertificateArgumentsMock
		expected string
	}{
		{
			// test empty arguments, should return just the ValidToGreater
			// argument
			name:     "Empty",
			input:    FormatSearchCertificateArgumentsMock{},
			expected: "^ValidToGreater=" + timeRegex,
		},
		{
			// test with just CN, should return Common Name and ValidToGreater
			// arguments
			name: "CN",
			input: FormatSearchCertificateArgumentsMock{
				cn: "test.example.com",
			},
			expected: "^CN=test\\.example\\.com&ValidToGreater=" + timeRegex,
		},
		{
			// test with just 1 DNS, should return SAN-DNS and ValidToGreater
			// arguments
			name: "SANS_1",
			input: FormatSearchCertificateArgumentsMock{
				sans: &certificate.Sans{DNS: []string{"one.example.com"}},
			},
			expected: "^SAN-DNS=one\\.example\\.com&ValidToGreater=" + timeRegex,
		},
		{
			// test with 2 DNS, should return both SAN-DNS and ValidToGreater
			// arguments
			name: "SANS_2",
			input: FormatSearchCertificateArgumentsMock{
				sans: &certificate.Sans{DNS: []string{"one.example.com", "two.example.com"}},
			},
			expected: "^SAN-DNS=one\\.example\\.com,two\\.example\\.com&ValidToGreater=" + timeRegex,
		},
		{
			// test with CN and 1 DNS, should return the Common Name, DNS and
			// ValidToGreater arguments
			name: "CN SANS_1",
			input: FormatSearchCertificateArgumentsMock{
				cn:   "test.example.com",
				sans: &certificate.Sans{DNS: []string{"one.example.com"}},
			},
			expected: "^CN=test\\.example\\.com&SAN-DNS=one\\.example\\.com&ValidToGreater=" + timeRegex,
		},
		{
			// test with CN and 2 DNS, should return the Common Name, 2 DNS and
			// ValidToGreater arguments
			name: "CN SANS_2",
			input: FormatSearchCertificateArgumentsMock{
				cn:   "test.example.com",
				sans: &certificate.Sans{DNS: []string{"one.example.com", "two.example.com"}},
			},
			expected: "^CN=test\\.example\\.com&SAN-DNS=one\\.example\\.com,two\\.example\\.com&ValidToGreater=" + timeRegex,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			req := formatSearchCertificateArguments(testCase.input.cn, testCase.input.sans, testCase.input.certMinTimeLeft)
			matches, err := regexp.MatchString(testCase.expected, strings.Join(req, "&"))
			if err != nil {
				t.Fatal(err)
			}
			if !matches {
				// might want to send a better error message in case of failure
				t.Errorf("unmatched regexp\nExpected:\n%v\nGot:\n%v", testCase.expected, req)
			}
		})
	}
}
