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
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	neturl "net/url"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (c *Connector) searchCertificatesByFingerprint(fp string) (*certificate.CertSearchResponse, error) {
	fp = strings.Replace(fp, ":", "", -1)
	fp = strings.Replace(fp, ".", "", -1)
	fp = strings.ToUpper(fp)

	var req certificate.SearchRequest
	req = append(req, fmt.Sprintf("Thumbprint=%s", fp))

	return c.SearchCertificates(&req)
}

func (c *Connector) configReadDN(req tpp_structs.ConfigReadDNRequest) (resp *tpp_structs.ConfigReadDNResponse, err error) {
	return c.rawClient().PostConfigReadDn(&req)
}

func (c *Connector) searchCertificateDetails(guid string) (*tpp_structs.CertificateDetailsResponse, error) {
	return c.rawClient().GetCertificateById(guid)
}

func formatSearchCertificateArguments(cn string, sans *certificate.Sans, certMinTimeLeft time.Duration) []string {
	// get future (or past) date for certificate validation
	date := time.Now().Add(certMinTimeLeft)
	// create request arguments
	req := make([]string, 0)

	if cn != "" {
		req = append(req, fmt.Sprintf("CN=%s", cn))
	}

	if sans != nil && sans.DNS != nil {
		req = append(req, fmt.Sprintf("SAN-DNS=%s", strings.Join(sans.DNS, ",")))
	}

	req = append(req, fmt.Sprintf("ValidToGreater=%s", neturl.QueryEscape(date.Format(time.RFC3339))))

	return req
}

func calcThumbprint(cert string) string {
	p, _ := pem.Decode([]byte(cert))
	h := sha1.New()
	h.Write(p.Bytes)
	buf := h.Sum(nil)
	return strings.ToUpper(fmt.Sprintf("%x", buf))
}
