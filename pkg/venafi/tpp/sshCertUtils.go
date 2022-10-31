/*
 * Copyright 2018-2021 Venafi, Inc.
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
	"fmt"
	"log"
	netUrl "net/url"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

const (
	SSHCaRootPath = util.PathSeparator + "VED" + util.PathSeparator + "Certificate Authority" + util.PathSeparator + "SSH" + util.PathSeparator + "Templates"
)

func RequestSshCertificate(c *Connector, req *certificate.SshCertRequest) (*certificate.SshCertificateObject, error) {
	sshCertReq := convertToSshCertReq(req)

	if sshCertReq.KeyId == "" {
		log.Println("Requesting SSH certificate from ", sshCertReq.CADN)
	} else {
		log.Println("Requesting SSH certificate with certificate identifier: ", sshCertReq.KeyId)
	}

	//TODO: Maybe, there is a better way to set the timeout.
	c.getHTTPClient().Timeout = time.Duration(req.Timeout) * time.Second

	response, err := c.rawClient().PostSshCertificateRequest(&sshCertReq)
	if err != nil {
		if response.Response.ErrorMessage != "" && c.verbose {
			log.Println(util.GetJsonAsString(response.Response))
		}
		return nil, err
	}

	log.Println("SSH certificate DN: ", response.DN)
	log.Println("GUID: ", response.Guid)

	if response.Response.Success && response.ProcessingDetails.Status == "Rejected" {
		return nil, endpoint.ErrCertificateRejected{CertificateID: req.PickupID, Status: response.ProcessingDetails.StatusDescription}
	}

	return convertToGenericRetrieveResponse(response), nil
}

func convertToSshCertReq(req *certificate.SshCertRequest) tpp_structs.TPPSshCertRequest {
	var tppSshCertReq tpp_structs.TPPSshCertRequest

	if len(req.Principals) > 0 {
		tppSshCertReq.Principals = req.Principals
	}

	if len(req.Extensions) > 0 {

		tppSshCertReq.Extensions = make(map[string]interface{})

		for _, extension := range req.Extensions {

			data := strings.Split(extension, ":")

			key := data[0]
			value := ""

			//if value is specified then get it.
			if len(data) > 1 {
				value = data[1]
			}

			tppSshCertReq.Extensions[key] = value

		}
	}

	if req.PolicyDN != "" {
		tppSshCertReq.PolicyDN = req.PolicyDN
	}

	if req.ObjectName != "" {
		tppSshCertReq.ObjectName = req.ObjectName
	}

	if len(req.DestinationAddresses) > 0 {
		tppSshCertReq.DestinationAddresses = req.DestinationAddresses
	}

	if req.KeyId != "" {
		tppSshCertReq.KeyId = req.KeyId
	}

	if req.ValidityPeriod != "" {
		tppSshCertReq.ValidityPeriod = req.ValidityPeriod
	}

	if len(req.SourceAddresses) > 0 {
		tppSshCertReq.SourceAddresses = req.SourceAddresses
	}

	if req.PublicKeyData != "" {
		tppSshCertReq.PublicKeyData = req.PublicKeyData
	}

	if req.Template != "" {
		tppSshCertReq.CADN = getSshCaDN(req.Template)
	}

	if req.ForceCommand != "" {
		tppSshCertReq.ForceCommand = req.ForceCommand
	}

	tppSshCertReq.IncludePrivateKeyData = true
	tppSshCertReq.IncludeCertificateDetails = true

	return tppSshCertReq
}

func RetrieveSshCertificate(c *Connector, req *certificate.SshCertRequest) (*certificate.SshCertificateObject, error) {
	var reqRetrieve tpp_structs.TppSshCertRetrieveRequest

	if req.PickupID != "" {
		reqRetrieve.DN = req.PickupID
	}

	if req.Guid != "" {
		reqRetrieve.Guid = req.Guid
	}

	if req.PrivateKeyPassphrase != "" {
		reqRetrieve.PrivateKeyPassphrase = req.PrivateKeyPassphrase
	}

	//this values are always true
	reqRetrieve.IncludePrivateKeyData = true
	reqRetrieve.IncludeCertificateDetails = true

	startTime := time.Now()
	for {
		var retrieveResponse *tpp_structs.TppSshCertOperationResponse
		retrieveResponse, err := retrieveSshCerOnce(reqRetrieve, c)
		if err != nil {
			return nil, err
		}
		if retrieveResponse.CertificateData != "" {
			return convertToGenericRetrieveResponse(retrieveResponse), nil
		}

		if retrieveResponse.Response.Success && retrieveResponse.ProcessingDetails.Status == "Rejected" {
			return nil, endpoint.ErrCertificateRejected{CertificateID: req.PickupID, Status: retrieveResponse.ProcessingDetails.StatusDescription}
		}

		if req.Timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: retrieveResponse.ProcessingDetails.StatusDescription}
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}
}

func retrieveSshCerOnce(sshRetrieveReq tpp_structs.TppSshCertRetrieveRequest, c *Connector) (*tpp_structs.TppSshCertOperationResponse, error) {
	return c.rawClient().PostSshCertificateRetrieve(&sshRetrieveReq)
}

func convertToGenericRetrieveResponse(data *tpp_structs.TppSshCertOperationResponse) *certificate.SshCertificateObject {
	response := &certificate.SshCertificateObject{}

	response.CertificateDetails = data.CertificateDetails
	response.PrivateKeyData = data.PrivateKeyData
	response.PublicKeyData = data.PublicKeyData
	response.CertificateData = data.CertificateData
	response.Guid = data.Guid
	response.DN = data.DN
	response.CAGuid = data.CAGuid
	response.CADN = data.CADN
	response.ProcessingDetails = data.ProcessingDetails

	return response
}

func getSshConfigUrl(key, value string) (query string) {
	query = fmt.Sprintf("%s=%s", key, value)
	return netUrl.PathEscape(query)
}

func RetrieveSshConfig(c *Connector, ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {
	var query string
	if ca.Template != "" {
		fullPath := getSshCaDN(ca.Template)
		query = getSshConfigUrl("DN", fullPath)
		fmt.Println("Retrieving the configured CA public key for template:", fullPath)
	} else if ca.Guid != "" {
		query = getSshConfigUrl("guid", ca.Guid)
		fmt.Println("Retrieving the configured CA public key for template with GUID:", ca.Guid)
	} else {
		return nil, fmt.Errorf("CA template or GUID are not specified")
	}

	data, err := c.rawClient().GetSshTemplatePublicKeyData([]string{query})
	if err != nil {
		return nil, fmt.Errorf("error while retriving CA public key, error %w", err)
	}

	conf := certificate.SshConfig{
		CaPublicKey: string(data),
	}

	if c.accessToken != "" {
		principals, err := RetrieveSshCaPrincipals(c, ca)
		if err != nil {
			return nil, err
		}

		conf.Principals = principals
	} else {
		fmt.Println("Skipping retrieval of Default Principals. No authentication data is provided.")
	}

	return &conf, nil
}

func GetAvailableSshTemplates(c *Connector) ([]certificate.SshAvaliableTemplate, error) {
	return c.rawClient().GetSshTemplateAvaliable()
}

func RetrieveSshCaPrincipals(c *Connector, ca *certificate.SshCaTemplateRequest) ([]string, error) {
	tppReq := tpp_structs.SshTppCaTemplateRequest{}

	if ca.Template != "" {
		tppReq.DN = getSshCaDN(ca.Template)
		fmt.Println("Retrieving the configured Default Principals for template:", tppReq.DN)
	} else if ca.Guid != "" {
		tppReq.Guid = ca.Guid
		fmt.Println("Retrieving the configured Default Principals for template with GUID:", ca.Guid)
	} else {
		return nil, fmt.Errorf("CA template or GUID are not specified")
	}

	data, err := c.rawClient().PostSshTemplateRetrieve(&tppReq)
	if err != nil {
		return nil, err
	}

	return data.AccessControl.DefaultPrincipals, nil
}

func getSshCaDN(ca string) string {
	fullPath := ca
	if !strings.HasPrefix(ca, util.PathSeparator) {
		fullPath = util.PathSeparator + ca
	}

	if !strings.HasPrefix(fullPath, SSHCaRootPath) {
		fullPath = SSHCaRootPath + fullPath
	}

	return fullPath
}
