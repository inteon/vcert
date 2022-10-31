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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_convert"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_validate"
	"github.com/Venafi/vcert/v4/pkg/verror"
)

// Connector contains the base data needed to communicate with a TPP Server
type Connector struct {
	baseURL string
	client  *http.Client

	apiKey      string
	accessToken string

	verbose  bool
	Identity tpp_structs.Identity
	trust    *x509.CertPool
	zone     string
}

func (c *Connector) rawClient() *tpp_api.RawClient {
	return &tpp_api.RawClient{
		BaseUrl:    c.baseURL,
		HttpClient: c.getHTTPClient(),
		Authenticator: func(r *http.Request) error {
			if c.accessToken != "" {
				r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
			} else if c.apiKey != "" {
				r.Header.Add("x-venafi-api-key", c.apiKey)
			}
			return nil
		},
	}
}

func (c *Connector) IsCSRServiceGenerated(req *certificate.Request) (bool, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSshConfig(ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {
	return RetrieveSshConfig(c, ca)
}

func (c *Connector) RetrieveAvailableSSHTemplates() (response []certificate.SshAvaliableTemplate, err error) {
	return GetAvailableSshTemplates(c)
}

// NewConnector creates a new TPP Connector object used to communicate with TPP
func NewConnector(url string, zone string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	c := Connector{verbose: verbose, trust: trust, zone: zone}
	var err error
	c.baseURL, err = normalizeURL(url)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to normalize URL: %v", verror.UserDataError, err)
	}
	return &c, nil
}

// normalizeURL normalizes the base URL used to communicate with TPP
func normalizeURL(url string) (normalizedURL string, err error) {
	var baseUrlRegex = regexp.MustCompile(`^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$`)
	modified := strings.ToLower(url)
	if strings.HasPrefix(modified, "http://") {
		modified = "https://" + modified[7:]
	} else if !strings.HasPrefix(modified, "https://") {
		modified = "https://" + modified
	}
	if !strings.HasSuffix(modified, "/") {
		modified = modified + "/"
	}

	modified = strings.TrimSuffix(modified, "vedsdk/")

	if loc := baseUrlRegex.FindStringIndex(modified); loc == nil {
		return "", fmt.Errorf("The specified TPP URL is invalid. %s\nExpected TPP URL format 'https://tpp.company.com/vedsdk/'", url)
	}

	return modified, nil
}

func (c *Connector) SetZone(z string) {
	c.zone = z
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeTPP
}

// Ping attempts to connect to the TPP Server WebSDK API and returns an error if it cannot
func (c *Connector) Ping() error {
	//Extended timeout to allow the server to wake up
	c.getHTTPClient().Timeout = time.Second * 90

	return c.rawClient().GetVedSdk()
}

// Authenticate authenticates the user to the TPP
func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", verror.AuthError, err)
		}
	}()

	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.ClientId == "" {
		auth.ClientId = defaultClientID
	}

	if auth.User != "" && auth.Password != "" {
		data := tpp_structs.AuthorizeRequest{Username: auth.User, Password: auth.Password}
		resp, err := c.rawClient().PostAuthorize(&data)
		if err != nil {
			return err
		}

		c.apiKey = resp.APIKey

		if c.client != nil {
			c.Identity, err = c.retrieveSelfIdentity()
			if err != nil {
				return err
			}
		}
		return nil

	} else if auth.RefreshToken != "" {
		data := tpp_structs.OAuthRefreshAccessTokenRequest{Client_id: auth.ClientId, Refresh_token: auth.RefreshToken}
		resp, err := c.rawClient().PostAuthorizeRefreshAccessToken(&data)
		if err != nil {
			return err
		}

		c.accessToken = resp.Access_token
		auth.RefreshToken = resp.Refresh_token
		if c.client != nil {
			c.Identity, err = c.retrieveSelfIdentity()
			if err != nil {
				return err
			}
		}
		return nil

	} else if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken

		if c.client != nil {
			c.Identity, err = c.retrieveSelfIdentity()
			if err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("failed to authenticate: can't determine valid credentials set")
}

// GetRefreshToken Get OAuth refresh and access token
func (c *Connector) GetRefreshToken(auth *endpoint.Authentication) (resp *tpp_structs.OAuthGetRefreshTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.Scope == "" {
		auth.Scope = defaultScope
	}
	if auth.ClientId == "" {
		auth.ClientId = defaultClientID
	}

	if auth.User != "" && auth.Password != "" {
		data := tpp_structs.OAuthGetRefreshTokenRequest{Username: auth.User, Password: auth.Password, Scope: auth.Scope, Client_id: auth.ClientId}
		resp, err := c.rawClient().PostAuthorizeOAuth(&data)
		if err != nil {
			return resp, err
		}
		return resp, nil

	} else if auth.ClientPKCS12 {
		data := tpp_structs.OAuthCertificateTokenRequest{Client_id: auth.ClientId, Scope: auth.Scope}
		resp, err := c.rawClient().PostAuthorizeCertificate(&data)
		if err != nil {
			return resp, err
		}
		return resp, nil
	}

	return resp, fmt.Errorf("failed to authenticate: missing credentials")
}

// RefreshAccessToken Refresh OAuth access token
func (c *Connector) RefreshAccessToken(auth *endpoint.Authentication) (resp *tpp_structs.OAuthRefreshAccessTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.ClientId == "" {
		auth.ClientId = defaultClientID
	}

	if auth.RefreshToken != "" {
		data := tpp_structs.OAuthRefreshAccessTokenRequest{Client_id: auth.ClientId, Refresh_token: auth.RefreshToken}
		resp, err := c.rawClient().PostAuthorizeRefreshAccessToken(&data)
		if err != nil {
			return resp, err
		}
		return resp, nil
	} else {
		return resp, fmt.Errorf("failed to authenticate: missing refresh token")
	}
}

// VerifyAccessToken - call to check whether token is valid and, if so, return its properties
func (c *Connector) VerifyAccessToken(auth *endpoint.Authentication) (resp tpp_structs.OAuthVerifyTokenResponse, err error) {
	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken
		result, err := c.rawClient().GetAuthorizeVerify()
		if err != nil {
			return resp, err
		}

		return *result, nil
	}

	return resp, fmt.Errorf("failed to authenticate: missing access token")
}

// RevokeAccessToken - call to revoke token so that it can never be used again
func (c *Connector) RevokeAccessToken(auth *endpoint.Authentication) (err error) {

	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken

		return c.rawClient().GetRevokeAccessToken()
	}

	return fmt.Errorf("failed to authenticate: missing access token")
}

func (c *Connector) isAuthServerReachable() (bool, error) {
	// Extended timeout to allow the server to wake up
	c.getHTTPClient().Timeout = time.Second * 90

	err := c.rawClient().GetIsAuthServer()

	// panic("add test below")
	// if statusCode == http.StatusAccepted && strings.Contains(statusText, "Venafi Authentication Server") {

	return err == nil, err
}

func wrapAltNames(req *certificate.Request) (items []tpp_structs.SanItem) {
	for _, name := range req.EmailAddresses {
		items = append(items, tpp_structs.SanItem{1, name})
	}
	for _, name := range req.DNSNames {
		items = append(items, tpp_structs.SanItem{2, name})
	}
	for _, name := range req.IPAddresses {
		items = append(items, tpp_structs.SanItem{7, name.String()})
	}
	for _, name := range req.URIs {
		items = append(items, tpp_structs.SanItem{6, name.String()})
	}
	for _, name := range req.UPNs {
		items = append(items, tpp_structs.SanItem{0, name})
	}
	return items
}

func prepareLegacyMetadata(c *Connector, metaItems []tpp_structs.CustomField, dn string) ([]tpp_structs.GuidData, error) {
	metadataItems, err := c.requestAllMetadataItems(dn)
	if nil != err {
		return nil, err
	}
	customFieldsGUIDMap := make(map[string]string)
	for _, item := range metadataItems {
		customFieldsGUIDMap[item.Label] = item.Guid
	}

	var requestGUIDData []tpp_structs.GuidData
	for _, item := range metaItems {
		guid, prs := customFieldsGUIDMap[item.Name]
		if prs {
			requestGUIDData = append(requestGUIDData, tpp_structs.GuidData{guid, item.Values})
		}
	}
	return requestGUIDData, nil
}

// requestAllMetadataItems returns all possible metadata items for a DN
func (c *Connector) requestAllMetadataItems(dn string) ([]tpp_structs.MetadataItem, error) {
	response, err := c.rawClient().PostMetadataGetAll(&tpp_structs.MetadataGetItemsRequest{dn})

	return response.Items, err
}

// requestMetadataItems returns metadata items for a DN that have a value stored
func (c *Connector) requestMetadataItems(dn string) ([]tpp_structs.MetadataKeyValueSet, error) {
	response, err := c.rawClient().PostMetadataGet(&tpp_structs.MetadataGetItemsRequest{dn})

	return response.Data, err
}

// Retrieve user's self identity
func (c *Connector) retrieveSelfIdentity() (response tpp_structs.Identity, err error) {
	respIndentities, err := c.rawClient().GetIdentitySelf()
	if err != nil {
		log.Printf("Failed to get the used user. Error: %v", err)
		return tpp_structs.Identity{}, err
	}

	if len(respIndentities.Identities) == 0 {
		return tpp_structs.Identity{}, fmt.Errorf("failed to get Self. server returned an empty set of identities")
	}

	return respIndentities.Identities[0], nil
}

// requestSystemVersion returns the TPP system version of the connector context
func (c *Connector) RetrieveSystemVersion() (string, error) {
	response, err := c.rawClient().GetSystemStatusVersion()

	return response.Version, err
}

// setCertificateMetadata submits the metadata to TPP for storage returning the lock status of the metadata stored
func (c *Connector) setCertificateMetadata(metadataRequest tpp_structs.MetadataSetRequest) (bool, error) {
	if metadataRequest.DN == "" {
		return false, fmt.Errorf("DN must be provided to setCertificateMetaData")
	}

	if len(metadataRequest.GuidData) == 0 && metadataRequest.KeepExisting {
		// Not an error, but there is nothing to do
		return false, nil
	}

	result, err := c.rawClient().PostMetadataSet(&metadataRequest)
	if err != nil {
		return false, err
	}

	switch result.Result {
	case 0:
		break
	case 17:
		return false, fmt.Errorf("custom field value not a valid list item. Server returned error %v", result.Result)
	default:
		return false, fmt.Errorf("return code %v was returned while adding metadata to %v. Please refer to the Metadata Result Codes in the TPP WebSDK API documentation to determine if further action is needed", result.Result, metadataRequest.DN)
	}
	return result.Locked, nil
}

func prepareRequest(req *certificate.Request, zone string) (tppReq tpp_structs.CertificateRequest, err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR, certificate.UserProvidedCSR:
		tppReq.PKCS10 = string(req.GetCSR())
	case certificate.ServiceGeneratedCSR:
		tppReq.Subject = req.Subject.CommonName // TODO: there is some problem because Subject is not only CN
		if !req.OmitSANs {
			tppReq.SubjectAltNames = wrapAltNames(req)
		}
	default:
		return tppReq, fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	tppReq.CertificateType = "AUTO"
	tppReq.PolicyDN = getPolicyDN(zone)
	tppReq.CADN = req.CADN
	tppReq.ObjectName = req.FriendlyName
	tppReq.DisableAutomaticRenewal = true
	customFieldsMap := make(map[string][]string)
	origin := endpoint.SDKName
	for _, f := range req.CustomFields {
		switch f.Type {
		case certificate.CustomFieldPlain:
			customFieldsMap[f.Name] = append(customFieldsMap[f.Name], f.Value)
		case certificate.CustomFieldOrigin:
			origin = f.Value
		}
	}
	tppReq.CASpecificAttributes = append(tppReq.CASpecificAttributes, tpp_structs.NameValuePair{Name: "Origin", Value: origin})
	tppReq.Origin = origin

	if req.ValidityHours > 0 {

		expirationDateAttribute := ""

		switch req.IssuerHint {
		case util.IssuerHintMicrosoft:
			expirationDateAttribute = "Microsoft CA:Specific End Date"
		case util.IssuerHintDigicert:
			expirationDateAttribute = "DigiCert CA:Specific End Date"
		case util.IssuerHintEntrust:
			expirationDateAttribute = "EntrustNET CA:Specific End Date"
		default:
			expirationDateAttribute = "Specific End Date"
		}

		loc, _ := time.LoadLocation("UTC")
		utcNow := time.Now().In(loc)

		//if the days have decimal parts then round it to next day.
		validityDays := req.ValidityHours / 24

		if req.ValidityHours%24 > 0 {

			validityDays = validityDays + 1

		}

		expirationDate := utcNow.AddDate(0, 0, validityDays)

		formattedExpirationDate := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
			expirationDate.Year(), expirationDate.Month(), expirationDate.Day(), expirationDate.Hour(), expirationDate.Minute(), expirationDate.Second())

		tppReq.CASpecificAttributes = append(tppReq.CASpecificAttributes, tpp_structs.NameValuePair{Name: expirationDateAttribute, Value: formattedExpirationDate})
	}

	for name, value := range customFieldsMap {
		tppReq.CustomFields = append(tppReq.CustomFields, tpp_structs.CustomField{name, value})
	}
	if req.Location != nil {
		if req.Location.Instance == "" {
			return tppReq, fmt.Errorf("%w: instance value for Location should not be empty", verror.UserDataError)
		}
		workload := req.Location.Workload
		if workload == "" {
			workload = defaultWorkloadName
		}
		dev := tpp_structs.Device{
			PolicyDN:   getPolicyDN(zone),
			ObjectName: req.Location.Instance,
			Host:       req.Location.Instance,
			Applications: []tpp_structs.Application{
				{
					ObjectName: workload,
					Class:      "Basic",
					DriverName: "appbasic",
				},
			},
		}
		if req.Location.TLSAddress != "" {
			host, port, err := parseHostPort(req.Location.TLSAddress)
			if err != nil {
				return tppReq, err
			}
			dev.Applications[0].ValidationHost = host
			dev.Applications[0].ValidationPort = port
		}
		tppReq.Devices = append(tppReq.Devices, dev)
	}
	switch req.KeyType {
	case certificate.KeyTypeRSA:
		tppReq.KeyAlgorithm = "RSA"
		tppReq.KeyBitSize = req.KeyLength
	case certificate.KeyTypeECDSA:
		tppReq.KeyAlgorithm = "ECC"
		tppReq.EllipticCurve = req.KeyCurve.String()
	}

	//Setting the certificate will be re-enabled.
	//From https://docs.venafi.com/Docs/currentSDK/TopNav/Content/SDK/WebSDK/r-SDK-POST-Certificates-request.php
	//Reenable (Optional) The action to control a previously disabled certificate:
	//
	//    - false: Default. Do not renew a previously disabled certificate.
	//    - true: Clear the Disabled attribute, reenable, and then renew the certificate (in this request). Reuse the same CertificateDN, that is also known as a Certificate object.
	tppReq.Reenable = true

	return tppReq, err
}

func (c *Connector) proccessLocation(req *certificate.Request) error {
	certDN := getCertificateDN(c.zone, req.Subject.CommonName)
	guid, err := c.configDNToGuid(certDN)
	if err != nil {
		return fmt.Errorf("unable to retrieve certificate guid: %s", err)
	}
	if guid == "" {
		if c.verbose {
			log.Printf("certificate with DN %s doesn't exists so no need to check if it is associated with any instances", certDN)
		}
		return nil
	}
	details, err := c.searchCertificateDetails(guid)
	if err != nil {
		return err
	}
	if len(details.Consumers) == 0 {
		log.Printf("There were no instances associated with certificate %s", certDN)
		return nil
	}
	if c.verbose {
		log.Printf("checking associated instances from:\n %s", details.Consumers)
	}
	var device string
	requestedDevice := getDeviceDN(stripBackSlashes(c.zone), *req.Location)

	for _, device = range details.Consumers {
		if c.verbose {
			log.Printf("comparing requested instance %s to %s", requestedDevice, device)
		}
		if device == requestedDevice {
			if req.Location.Replace {
				err = c.dissociate(certDN, device)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("%w: instance %s already exists, change the value or use --replace-instance", verror.UserDataError, device)
			}
		}
	}
	return nil
}

// RequestCertificate submits the CSR to TPP returning the DN of the requested Certificate
func (c *Connector) RequestCertificate(req *certificate.Request) (requestID string, err error) {
	if req.Location != nil {
		err = c.proccessLocation(req)
		if err != nil {
			return
		}
	}
	tppCertificateRequest, err := prepareRequest(req, c.zone)
	if err != nil {
		return "", err
	}

	response, err := c.rawClient().PostCertificateRequest(&tppCertificateRequest)
	if err != nil {
		return "", err
	}
	requestID = response.CertificateDN
	req.PickupID = requestID

	if len(req.CustomFields) == 0 {
		return
	}

	// Handle legacy TPP custom field API
	//Get the saved metadata for the current certificate, deep compare the
	//saved metadata to the requested metadata. If all items match then no further
	//changes need to be made. If they do not match, they try to update them using
	//the 19.2 WebSDK calls
	metadataItems, err := c.requestMetadataItems(requestID)
	if err != nil {
		log.Println(err)
		return
	}
	//prepare struct for search
	metadata := make(map[string]map[string]struct{})
	for _, item := range metadataItems {
		metadata[item.Key.Label] = make(map[string]struct{})
		for _, v := range item.Value {
			metadata[item.Key.Label][v] = struct{}{} //empty struct has zero size
		}
	}
	//Deep compare the request metadata to the fetched metadata
	var allItemsFound = true
	for _, cf := range tppCertificateRequest.CustomFields {
		values, prs := metadata[cf.Name]
		if !prs {
			allItemsFound = false
			break
		}
		for _, value := range cf.Values {
			_, prs := values[value]
			if !prs {
				//Found the field by name, but couldn't find one of the values
				allItemsFound = false
			}
		}
	}

	if allItemsFound {
		return
	}
	log.Println("Saving metadata custom field using 19.2 method")
	//Create a metadata/set command with the metadata from tppCertificateRequest
	guidItems, err := prepareLegacyMetadata(c, tppCertificateRequest.CustomFields, requestID)
	if err != nil {
		log.Println(err)
		return
	}
	requestData := tpp_structs.MetadataSetRequest{requestID, guidItems, true}
	//c.request with the metadata request
	_, err = c.setCertificateMetadata(requestData)
	if err != nil {
		log.Println(err)
	}
	return
}

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {
	var ps *policy.PolicySpecification
	var tp tpp_structs.TppPolicy

	log.Println("Collecting policy attributes")

	if !strings.HasPrefix(name, util.PathSeparator) {
		name = util.PathSeparator + name
	}

	if !strings.HasPrefix(name, policy.RootPath) {
		name = policy.RootPath + name

	}

	tp.Name = &name

	req := tpp_structs.CheckPolicyRequest{
		PolicyDN: name,
	}

	checkPolicyResponse, err := c.rawClient().PostCertificateCheckPolicy(&req)
	if err != nil {
		return nil, err
	}

	if checkPolicyResponse.Error != "" {
		return nil, fmt.Errorf(checkPolicyResponse.Error)
	}

	log.Println("Building policy")
	ps, err = tpp_convert.BuildPolicySpecificationForTPP(*checkPolicyResponse)
	if err != nil {
		return nil, err
	}

	userNames, error := c.retrieveUserNamesForPolicySpecification(name)
	if error != nil {
		return nil, error
	}
	ps.Users = userNames

	return ps, nil
}

func (c *Connector) retrieveUserNamesForPolicySpecification(policyName string) ([]string, error) {
	values, _, error := getPolicyAttribute(c, tpp_structs.TppContact, policyName)
	if error != nil {
		return nil, error
	}
	if values != nil {
		var users []string
		for _, prefixedUniversal := range values {
			validateIdentityRequest := tpp_structs.ValidateIdentityRequest{
				ID: tpp_structs.IdentityInformation{
					PrefixedUniversal: prefixedUniversal,
				},
			}

			validateIdentityResponse, error := c.validateIdentity(validateIdentityRequest)
			if error != nil {
				return nil, error
			}

			users = append(users, validateIdentityResponse.ID.Name)
		}

		return users, nil
	}

	return nil, nil
}

func (c *Connector) validateIdentity(validateIdentityRequest tpp_structs.ValidateIdentityRequest) (*tpp_structs.ValidateIdentityResponse, error) {
	validateIdentityResponse, err := c.rawClient().PostIdentityValidate(validateIdentityRequest)
	if err != nil {
		return nil, err
	}
	return validateIdentityResponse, nil
}

func PolicyExist(policyName string, c *Connector) (bool, error) {
	req := tpp_structs.PolicyExistPayloadRequest{
		ObjectDN: policyName,
	}

	response, err := c.rawClient().PostConfigIsValidPolicy(&req)
	if err != nil {
		return false, err
	}

	//if error is not null then the policy doesn't exists
	if response.Result == 1 && response.PolicyObject.DN != "" {
		return true, nil
	} else if (response.Error != "") && (response.Result == 400) {
		return false, nil
	} else {
		return false, fmt.Errorf(response.Error)
	}

}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {
	//validate policy specification and policy
	err := tpp_validate.ValidateTppPolicySpecification(ps)

	if err != nil {
		return "", err
	}

	log.Printf("policy specification is valid")
	var status string
	tppPolicy := tpp_convert.BuildTppPolicy(ps)
	if !strings.HasPrefix(name, util.PathSeparator) {
		name = util.PathSeparator + name
	}

	if !strings.HasPrefix(name, policy.RootPath) {
		name = policy.RootPath + name

	}

	tppPolicy.Name = &name

	//validate if the policy exists
	policyExists, err := PolicyExist(name, c)
	if err != nil {
		return "", err
	}

	if policyExists {
		log.Printf("found existing policy folder: %s", name)
	} else {

		//validate if the parent exist
		parent := policy.GetParent(name)

		parentExist, err := PolicyExist(parent, c)
		if err != nil {
			return "", err
		}

		if parent != policy.RootPath && !parentExist {

			return "", fmt.Errorf("the policy's parent doesn't exists")

		}
	}

	//step 1 create root policy folder.
	if !policyExists {

		log.Printf("creating policy folder: %s", name)

		req := tpp_structs.PolicyPayloadRequest{
			Class:    policy.PolicyClass,
			ObjectDN: *(tppPolicy.Name),
		}

		err := c.rawClient().PostConfigCreatePolicy(&req)
		if err != nil {
			return "", err
		}
	}
	//step 2 create policy's attributes.

	log.Printf("updating certificate policy attributes")

	//create Approver
	if tppPolicy.Approver != nil {
		err = createPolicyAttribute(c, tpp_structs.TppApprover, tppPolicy.Approver, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}
	if policyExists {
		err = resetTPPAttributes(*(tppPolicy.Name), c)
		if err != nil {
			return "", err
		}
	}

	//set Contacts
	status, err = c.setContact(&tppPolicy)
	if err != nil {
		return "", err
	}

	//create Domain Suffix Whitelist
	if tppPolicy.ManagementType != nil {
		err = createPolicyAttribute(c, tpp_structs.TppManagementType, []string{tppPolicy.ManagementType.Value}, *(tppPolicy.Name), tppPolicy.ManagementType.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Domain Suffix Whitelist
	if tppPolicy.DomainSuffixWhitelist != nil {
		err = createPolicyAttribute(c, tpp_structs.TppDomainSuffixWhitelist, tppPolicy.DomainSuffixWhitelist, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}

	//create Prohibit Wildcard
	if tppPolicy.ProhibitWildcard != nil {
		err = createPolicyAttribute(c, tpp_structs.TppProhibitWildcard, []string{strconv.Itoa(*(tppPolicy.ProhibitWildcard))}, *(tppPolicy.Name), false)
		if err != nil {
			return "", err
		}
	}

	//create Certificate Authority
	if tppPolicy.CertificateAuthority != nil {
		err = createPolicyAttribute(c, tpp_structs.TppCertificateAuthority, []string{*(tppPolicy.CertificateAuthority)}, *(tppPolicy.Name), false)
		if err != nil {
			return "", err
		}
	}

	//create Organization attribute
	if tppPolicy.Organization != nil {
		err = createPolicyAttribute(c, tpp_structs.TppOrganization, []string{tppPolicy.Organization.Value}, *(tppPolicy.Name), tppPolicy.Organization.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Organizational Unit attribute
	if tppPolicy.OrganizationalUnit != nil {
		err = createPolicyAttribute(c, tpp_structs.TppOrganizationalUnit, tppPolicy.OrganizationalUnit.Value, *(tppPolicy.Name), tppPolicy.OrganizationalUnit.Locked)
		if err != nil {
			return "", err
		}
	}
	//create City attribute
	if tppPolicy.City != nil {
		err = createPolicyAttribute(c, tpp_structs.TppCity, []string{tppPolicy.City.Value}, *(tppPolicy.Name), tppPolicy.City.Locked)
		if err != nil {
			return "", err
		}
	}

	//create State attribute
	if tppPolicy.State != nil {
		err = createPolicyAttribute(c, tpp_structs.TppState, []string{tppPolicy.State.Value}, *(tppPolicy.Name), tppPolicy.State.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Country attribute
	if tppPolicy.Country != nil {
		err = createPolicyAttribute(c, tpp_structs.TppCountry, []string{tppPolicy.Country.Value}, *(tppPolicy.Name), tppPolicy.Country.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Key Algorithm attribute
	if tppPolicy.KeyAlgorithm != nil {
		err = createPolicyAttribute(c, tpp_structs.TppKeyAlgorithm, []string{tppPolicy.KeyAlgorithm.Value}, *(tppPolicy.Name), tppPolicy.KeyAlgorithm.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Key Bit Strength
	if tppPolicy.KeyBitStrength != nil {
		err = createPolicyAttribute(c, tpp_structs.TppKeyBitStrength, []string{tppPolicy.KeyBitStrength.Value}, *(tppPolicy.Name), tppPolicy.KeyBitStrength.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Elliptic Curve attribute
	if tppPolicy.EllipticCurve != nil {
		err = createPolicyAttribute(c, tpp_structs.TppEllipticCurve, []string{tppPolicy.EllipticCurve.Value}, *(tppPolicy.Name), tppPolicy.EllipticCurve.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Manual Csr attribute
	if tppPolicy.ManualCsr != nil {
		err = createPolicyAttribute(c, tpp_structs.TppManualCSR, []string{tppPolicy.ManualCsr.Value}, *(tppPolicy.Name), tppPolicy.ManualCsr.Locked)
		if err != nil {
			return "", err
		}
	}

	if tppPolicy.ProhibitedSANType != nil {
		err = createPolicyAttribute(c, tpp_structs.TppProhibitedSANTypes, tppPolicy.ProhibitedSANType, *(tppPolicy.Name), false)
		if err != nil {
			return "", err
		}
	}

	//Allow Private Key Reuse" & "Want Renewal
	if tppPolicy.AllowPrivateKeyReuse != nil {
		err = createPolicyAttribute(c, tpp_structs.TppAllowPrivateKeyReuse, []string{strconv.Itoa(*(tppPolicy.AllowPrivateKeyReuse))}, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}

	if tppPolicy.WantRenewal != nil {
		err = createPolicyAttribute(c, tpp_structs.TppWantRenewal, []string{strconv.Itoa(*(tppPolicy.WantRenewal))}, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}

	log.Printf("policy successfully applied to %s", name)

	return status, nil
}

func (c *Connector) setContact(tppPolicy *tpp_structs.TppPolicy) (status string, err error) {
	if tppPolicy.Contact != nil {
		contacts, err := c.resolveContacts(tppPolicy.Contact)
		if err != nil {
			return "", fmt.Errorf("an error happened trying to resolve the contacts: %w", err)
		}
		if contacts != nil {
			tppPolicy.Contact = contacts

			err = createPolicyAttribute(c, tpp_structs.TppContact, tppPolicy.Contact, *(tppPolicy.Name), true)
			if err != nil {
				return "", err
			}
		}
	}

	return status, nil
}

func (c *Connector) resolveContacts(contacts []string) ([]string, error) {
	var identities []string
	uniqueContacts := getUniqueStringSlice(contacts)
	for _, contact := range uniqueContacts {
		identity, err := c.getIdentity(contact)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity.PrefixedUniversal)
	}

	return identities, nil
}

func getUniqueStringSlice(stringSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range stringSlice {
		if _, found := keys[entry]; !found {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func (c *Connector) getIdentity(userName string) (*tpp_structs.Identity, error) {
	if userName == "" {
		return nil, fmt.Errorf("identity string cannot be null")
	}

	req := tpp_structs.BrowseIdentitiesRequest{
		Filter:       userName,
		Limit:        2,
		IdentityType: policy.AllIdentities,
	}

	resp, err := c.browseIdentities(req)
	if err != nil {
		return nil, err
	}

	return c.getIdentityMatching(resp.Identities, userName)
}

func (c *Connector) getIdentityMatching(identities []tpp_structs.Identity, identityName string) (*tpp_structs.Identity, error) {
	var identityEntryMatching *tpp_structs.Identity

	if len(identities) > 0 {
		for i := range identities {
			identityEntry := identities[i]
			if identityEntry.Name == identityName {
				identityEntryMatching = &identityEntry
				break
			}
		}
	}

	//if the identity is not null
	if identityEntryMatching != nil {
		return identityEntryMatching, nil
	} else {
		return nil, fmt.Errorf("it was not possible to find the user %s", identityName)
	}
}

func (c *Connector) browseIdentities(browseReq tpp_structs.BrowseIdentitiesRequest) (*tpp_structs.BrowseIdentitiesResponse, error) {
	browseIdentitiesResponse, err := c.rawClient().PostIdentityBrowse(browseReq)
	if err != nil {
		return nil, err
	}
	return browseIdentitiesResponse, nil
}

// RetrieveCertificate attempts to retrieve the requested certificate
func (c *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {

	includeChain := req.ChainOption != certificate.ChainOptionIgnore
	rootFirstOrder := includeChain && req.ChainOption == certificate.ChainOptionRootFirst

	if req.PickupID == "" && req.Thumbprint != "" {
		// search cert by Thumbprint and fill pickupID
		searchResult, err := c.searchCertificatesByFingerprint(req.Thumbprint)
		if err != nil {
			return nil, fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return nil, fmt.Errorf("No certifiate found using fingerprint %s", req.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return nil, fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}
		req.PickupID = searchResult.Certificates[0].DN
	}

	certReq := tpp_structs.CertificateRetrieveRequest{
		CertificateDN:  req.PickupID,
		Format:         "base64",
		RootFirstOrder: rootFirstOrder,
		IncludeChain:   includeChain,
	}
	if req.CsrOrigin == certificate.ServiceGeneratedCSR || req.FetchPrivateKey {
		certReq.IncludePrivateKey = true
		if req.KeyType == certificate.KeyTypeRSA {
			certReq.Format = "Base64 (PKCS #8)"
		}
		certReq.Password = req.KeyPassword
	}

	startTime := time.Now()
	for {
		var retrieveResponse *tpp_structs.CertificateRetrieveResponse
		retrieveResponse, err = c.retrieveCertificateOnce(certReq)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve: %s", err)
		}
		if retrieveResponse.CertificateData != "" {
			certificates, err = newPEMCollectionFromResponse(retrieveResponse.CertificateData, req.ChainOption)
			if err != nil {
				return
			}
			err = req.CheckCertificate(certificates.Certificate)
			return
		}
		if req.Timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: retrieveResponse.Status}
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *Connector) retrieveCertificateOnce(certReq tpp_structs.CertificateRetrieveRequest) (*tpp_structs.CertificateRetrieveResponse, error) {
	retrieveResponse, err := c.rawClient().PostCertificateRetrieve(&certReq)
	if err != nil {
		return nil, err
	}
	return retrieveResponse, nil
}

func (c *Connector) putCertificateInfo(dn string, attributes []tpp_structs.NameSliceValuePair) error {
	guid, err := c.configDNToGuid(dn)
	if err != nil {
		return err
	}
	return c.rawClient().PutCertificate(guid, &tpp_structs.CertificateInfo{AttributeData: attributes})
}

func (c *Connector) prepareRenewalRequest(renewReq *certificate.RenewalRequest) error {
	if renewReq.CertificateRequest != nil && len(renewReq.CertificateRequest.GetCSR()) != 0 {
		return nil
	}

	searchReq := &certificate.Request{
		PickupID: renewReq.CertificateDN,
	}

	// here we fetch old cert anyway
	oldPcc, err := c.RetrieveCertificate(searchReq)
	if err != nil {
		return fmt.Errorf("Failed to fetch old certificate by id %s: %s", renewReq.CertificateDN, err)
	}
	oldCertBlock, _ := pem.Decode([]byte(oldPcc.Certificate))
	if oldCertBlock == nil || oldCertBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("Failed to fetch old certificate by id %s: PEM parse error", renewReq.CertificateDN)
	}
	oldCert, err := x509.ParseCertificate([]byte(oldCertBlock.Bytes))
	if err != nil {
		return fmt.Errorf("Failed to fetch old certificate by id %s: %s", renewReq.CertificateDN, err)
	}
	if renewReq.CertificateRequest == nil {
		renewReq.CertificateRequest = certificate.NewRequest(oldCert)
	}
	err = c.GenerateRequest(&endpoint.ZoneConfiguration{}, renewReq.CertificateRequest)
	return err
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {
	if renewReq.Thumbprint != "" && renewReq.CertificateDN == "" {
		// search by Thumbprint and fill *renewReq.CertificateDN
		searchResult, err := c.searchCertificatesByFingerprint(renewReq.Thumbprint)
		if err != nil {
			return "", fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return "", fmt.Errorf("No certifiate found using fingerprint %s", renewReq.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return "", fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}

		renewReq.CertificateDN = searchResult.Certificates[0].DN
	}
	if renewReq.CertificateDN == "" {
		return "", fmt.Errorf("failed to create renewal request: CertificateDN or Thumbprint required")
	}
	if renewReq.CertificateRequest != nil && renewReq.CertificateRequest.OmitSANs {
		// if OmitSANSs flag is presented we need to clean SANs values in TPP
		// for preventing adding them to renew request on TPP side
		err = c.putCertificateInfo(renewReq.CertificateDN, []tpp_structs.NameSliceValuePair{
			{"X509 SubjectAltName DNS", nil},
			{"X509 SubjectAltName IPAddress", nil},
			{"X509 SubjectAltName RFC822", nil},
			{"X509 SubjectAltName URI", nil},
			{"X509 SubjectAltName OtherName UPN", nil},
		})
		if err != nil {
			return "", fmt.Errorf("can't clean SANs values for certificate on server side: %v", err)
		}
	}
	//err = c.prepareRenewalRequest(renewReq) todo: uncomment on refactoring
	//if err != nil {
	//	return "", err
	//}
	var r = tpp_structs.CertificateRenewRequest{}
	r.CertificateDN = renewReq.CertificateDN
	if renewReq.CertificateRequest != nil && len(renewReq.CertificateRequest.GetCSR()) != 0 {
		r.PKCS10 = string(renewReq.CertificateRequest.GetCSR())
	}

	response, err := c.rawClient().PostCertificateRenew(&r)
	if err != nil {
		return "", err
	}

	if !response.Success {
		return "", fmt.Errorf("Certificate Renewal error: %s", response.Error)
	}
	return renewReq.CertificateDN, nil
}

// RevocationReasonsMap maps *certificate.RevocationRequest.Reason to TPP-specific webSDK codes
var RevocationReasonsMap = map[string]tpp_structs.RevocationReason{
	"":                       0, // NoReason
	"none":                   0, //
	"key-compromise":         1, // UserKeyCompromised
	"ca-compromise":          2, // CAKeyCompromised
	"affiliation-changed":    3, // UserChangedAffiliation
	"superseded":             4, // CertificateSuperseded
	"cessation-of-operation": 5, // OriginalUseNoLongerValid
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	reason, ok := RevocationReasonsMap[revReq.Reason]
	if !ok {
		return fmt.Errorf("could not parse revocation reason `%s`", revReq.Reason)
	}

	var r = tpp_structs.CertificateRevokeRequest{
		revReq.CertificateDN,
		revReq.Thumbprint,
		reason,
		revReq.Comments,
		revReq.Disable,
	}

	revokeResponse, err := c.rawClient().PostCertificateRevoke(&r)
	if err != nil {
		return
	}
	if !revokeResponse.Success {
		return fmt.Errorf("Revocation error: %s", revokeResponse.Error)
	}
	return
}

var zoneNonFoundregexp = regexp.MustCompile("PolicyDN: .+ does not exist")

func (c *Connector) ReadPolicyConfiguration() (*endpoint.Policy, error) {
	if c.zone == "" {
		return nil, fmt.Errorf("empty zone")
	}

	result, err := c.rawClient().PostCertificateCheckPolicy(&tpp_structs.CheckPolicyRequest{PolicyDN: getPolicyDN(c.zone)})
	if err != nil {
		return nil, err
	}

	p := serverPolicyToPolicy(*result.Policy)

	return &p, err
}

// ReadZoneConfiguration reads the policy data from TPP to get locked and pre-configured values for certificate requests
func (c *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	if c.zone == "" {
		return nil, fmt.Errorf("empty zone")
	}
	zoneConfig := endpoint.NewZoneConfiguration()
	zoneConfig.HashAlgorithm = x509.SHA256WithRSA //todo: check this can have problem with ECDSA key

	result, err := c.rawClient().PostCertificateCheckPolicy(&tpp_structs.CheckPolicyRequest{PolicyDN: getPolicyDN(c.zone)})
	if err != nil {
		return
	}

	p := serverPolicyToPolicy(*result.Policy)
	serverPolicyToZoneConfig(*result.Policy, zoneConfig)
	zoneConfig.Policy = p

	return zoneConfig, nil
}

func (c *Connector) ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	r := tpp_structs.ImportRequest{
		PolicyDN:        req.PolicyDN,
		ObjectName:      req.ObjectName,
		CertificateData: req.CertificateData,
		PrivateKeyData:  req.PrivateKeyData,
		Password:        req.Password,
		Reconcile:       req.Reconcile,
	}

	if r.PolicyDN == "" {
		r.PolicyDN = getPolicyDN(c.zone)
	}

	origin := endpoint.SDKName + " (+)" // standard suffix needed to differentiate certificates imported from enrolled in TPP
	for _, f := range req.CustomFields {
		if f.Type == certificate.CustomFieldOrigin {
			origin = f.Value + " (+)"
		}
	}

	response, err := c.rawClient().PostCertificateImport(&r)
	if err != nil {
		return nil, err
	}

	err = c.putCertificateInfo(response.CertificateDN, []tpp_structs.NameSliceValuePair{{Name: "Origin", Value: []string{origin}}})
	if err != nil {
		log.Println(err)
	}
	return response, nil
}

func (c *Connector) SearchCertificates(req *certificate.SearchRequest) (*certificate.CertSearchResponse, error) {
	return c.rawClient().GetCertificate(*req)
}

func (c *Connector) SearchCertificate(zone string, cn string, sans *certificate.Sans, certMinTimeLeft time.Duration) (certificateInfo *certificate.CertificateInfo, err error) {
	// format arguments for request
	req := formatSearchCertificateArguments(cn, sans, certMinTimeLeft)

	// perform request
	searchResult, err := c.rawClient().GetCertificate(req)
	if err != nil {
		return nil, err
	}

	// fail if no certificate is returned from api
	if searchResult.Count == 0 {
		return nil, verror.NoCertificateFoundError
	}

	// map (convert) response to an array of CertificateInfo, only add those
	// certificates whose Zone matches ours
	certificates := make([]*certificate.CertificateInfo, 0)
	n := 0
	policyDn := getPolicyDN(zone)
	for _, cert := range searchResult.Certificates {
		if cert.ParentDn == policyDn {
			match := cert.X509
			certificates = append(certificates, &match)
			certificates[n].ID = cert.Guid
			n = n + 1
		}
	}

	// fail if no certificates found with matching zone
	if n == 0 {
		return nil, verror.NoCertificateWithMatchingZoneFoundError
	}

	// at this point all certificates belong to our zone, the next step is
	// finding the newest valid certificate matching the provided sans
	return certificate.FindNewestCertificateWithSans(certificates, sans)
}

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Connector) ListCertificates(filter endpoint.Filter) ([]certificate.CertificateInfo, error) {
	if c.zone == "" {
		return nil, fmt.Errorf("empty zone")
	}
	min := func(i, j int) int {
		if i < j {
			return i
		}
		return j
	}
	const batchSize = 500
	limit := 100000000
	if filter.Limit != nil {
		limit = *filter.Limit
	}
	var buf [][]certificate.CertificateInfo
	for offset := 0; limit > 0; limit, offset = limit-batchSize, offset+batchSize {
		var b []certificate.CertificateInfo
		var err error
		b, err = c.getCertsBatch(offset, min(limit, batchSize), filter.WithExpired)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b)
		if len(b) < min(limit, batchSize) {
			break
		}
	}
	sumLen := 0
	for _, b := range buf {
		sumLen += len(b)
	}
	infos := make([]certificate.CertificateInfo, sumLen)
	offset := 0
	for _, b := range buf {
		copy(infos[offset:], b[:])
		offset += len(b)
	}
	return infos, nil
}

func (c *Connector) getCertsBatch(offset, limit int, withExpired bool) ([]certificate.CertificateInfo, error) {
	query := []string{
		"ParentDNRecursive=" + neturl.QueryEscape(getPolicyDN(c.zone)),
		"limit=" + fmt.Sprintf("%d", limit),
		"offset=" + fmt.Sprintf("%d", offset),
	}
	if !withExpired {
		query = append(query, "ValidToGreater="+neturl.QueryEscape(time.Now().Format(time.RFC3339)))
	}

	r, err := c.rawClient().GetCertificate(query)
	if err != nil {
		return nil, err
	}

	infos := make([]certificate.CertificateInfo, len(r.Certificates))
	for i, c := range r.Certificates {
		c.X509.ID = c.DN
		infos[i] = c.X509
	}

	return infos, nil
}

func parseHostPort(s string) (host string, port string, err error) {
	slice := strings.Split(s, ":")
	if len(slice) != 2 {
		err = fmt.Errorf("%w: bad address %s.  should be host:port.", verror.UserDataError, s)
		return
	}
	host = slice[0]
	port = slice[1]
	return
}

func (c *Connector) dissociate(certDN, applicationDN string) error {
	req := &tpp_structs.CertificateDissociate{
		CertificateDN: certDN,
		ApplicationDN: []string{applicationDN},
		DeleteOrphans: true,
	}
	log.Println("Dissociating device", applicationDN)
	return c.rawClient().PostCertificateDissociate(req)
}

func (c *Connector) associate(certDN, applicationDN string, pushToNew bool) error {
	req := tpp_structs.CertificateAssociate{
		CertificateDN: certDN,
		ApplicationDN: []string{applicationDN},
		PushToNew:     pushToNew,
	}
	log.Println("Associating device", applicationDN)
	err := c.rawClient().PostCertificateAssociate(&req)
	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) configDNToGuid(objectDN string) (guid string, err error) {
	resp, err := c.rawClient().PostConfigDnToGuid(&tpp_structs.DNToGUIDRequest{
		objectDN,
	})
	if err != nil {
		return "", err
	}

	if resp.Result != 1 {
		return "", fmt.Errorf("result code %d is not success.", resp.Result)
	}
	return resp.GUID, nil

}

func (c *Connector) findObjectsOfClass(req *tpp_structs.FindObjectsOfClassRequest) (*tpp_structs.FindObjectsOfClassResponse, error) {
	return c.rawClient().PostConfigFindObjectsOfClass(req)
}

// GetZonesByParent returns a list of valid zones for a TPP parent folder specified by parent
func (c *Connector) GetZonesByParent(parent string) ([]string, error) {
	var zones []string

	parentFolderDn := parent
	if !strings.HasPrefix(parentFolderDn, "\\VED\\Policy") {
		parentFolderDn = fmt.Sprintf("\\VED\\Policy\\%s", parentFolderDn)
	}

	request := tpp_structs.FindObjectsOfClassRequest{
		Class:    "Policy",
		ObjectDN: parentFolderDn,
	}
	response, err := c.findObjectsOfClass(&request)
	if err != nil {
		return nil, err
	}

	for _, folder := range response.PolicyObjects {
		// folder.DN will always start with \VED\Policy but short form is preferrable since both are supported
		zones = append(zones, strings.Replace(folder.DN, "\\VED\\Policy\\", "", 1))
	}
	return zones, nil
}

func createPolicyAttribute(c *Connector, at tpp_structs.TppAttribute, av []string, n string, l bool) error {
	request := tpp_structs.PolicySetAttributePayloadRequest{
		Locked:        l,
		ObjectDN:      n,
		Class:         policy.PolicyAttributeClass,
		AttributeName: string(at),
		Values:        av,
	}

	// if is locked is a policy value
	// if is not locked then is a default.
	response, err := c.rawClient().PostConfigWritePolicy(&request)
	if err != nil {
		return err
	}

	if response.Error != "" {
		err = fmt.Errorf(response.Error)
		return err
	}

	return err
}

func getPolicyAttribute(c *Connector, at tpp_structs.TppAttribute, n string) (s []string, b *bool, err error) {
	request := tpp_structs.PolicyGetAttributePayloadRequest{
		ObjectDN:      n,
		Class:         policy.PolicyAttributeClass,
		AttributeName: string(at),
		Values:        []string{"1"},
	}

	// if is locked is a policy value
	// if is not locked then is a default.
	response, err := c.rawClient().PostConfigReadPolicy(&request)
	if err != nil {
		return nil, nil, err
	}

	if len(response.Values) > 0 {
		return response.Values, &response.Locked, nil
	}
	//no value set and no error.
	return nil, nil, nil
}

func resetTPPAttributes(zone string, c *Connector) error {

	//reset Contact
	err := resetTPPAttribute(c, tpp_structs.TppContact, zone)
	if err != nil {
		return err
	}

	//reset Domain Suffix Whitelist
	err = resetTPPAttribute(c, tpp_structs.TppDomainSuffixWhitelist, zone)
	if err != nil {
		return err
	}

	//reset Prohibit Wildcard
	err = resetTPPAttribute(c, tpp_structs.TppProhibitWildcard, zone)
	if err != nil {
		return err
	}

	//reset Certificate Authority
	err = resetTPPAttribute(c, tpp_structs.TppCertificateAuthority, zone)
	if err != nil {
		return err
	}

	//reset Organization attribute
	err = resetTPPAttribute(c, tpp_structs.TppOrganization, zone)
	if err != nil {
		return err
	}

	//reset Organizational Unit attribute
	err = resetTPPAttribute(c, tpp_structs.TppOrganizationalUnit, zone)
	if err != nil {
		return err
	}

	//reset City attribute
	err = resetTPPAttribute(c, tpp_structs.TppCity, zone)
	if err != nil {
		return err
	}

	//reset State attribute
	err = resetTPPAttribute(c, tpp_structs.TppState, zone)
	if err != nil {
		return err
	}

	//reset Country attribute
	err = resetTPPAttribute(c, tpp_structs.TppCountry, zone)
	if err != nil {
		return err
	}

	//reset Key Algorithm attribute
	err = resetTPPAttribute(c, tpp_structs.TppKeyAlgorithm, zone)
	if err != nil {
		return err
	}

	//reset Key Bit Strength
	err = resetTPPAttribute(c, tpp_structs.TppKeyBitStrength, zone)
	if err != nil {
		return err
	}

	//reset Elliptic Curve attribute
	err = resetTPPAttribute(c, tpp_structs.TppEllipticCurve, zone)
	if err != nil {
		return err
	}

	//reset Manual Csr attribute
	err = resetTPPAttribute(c, tpp_structs.TppManualCSR, zone)
	if err != nil {
		return err
	}

	//reset Manual Csr attribute
	err = resetTPPAttribute(c, tpp_structs.TppProhibitedSANTypes, zone)
	if err != nil {
		return err
	}

	//reset Allow Private Key Reuse" & "Want Renewal
	err = resetTPPAttribute(c, tpp_structs.TppAllowPrivateKeyReuse, zone)
	if err != nil {
		return err
	}

	err = resetTPPAttribute(c, tpp_structs.TppWantRenewal, zone)
	if err != nil {
		return err
	}

	err = resetTPPAttribute(c, tpp_structs.TppManagementType, zone)
	if err != nil {
		return err
	}

	return nil
}

func resetTPPAttribute(c *Connector, at tpp_structs.TppAttribute, zone string) error {
	request := tpp_structs.ClearTTPAttributesRequest{
		ObjectDN:      zone,
		Class:         policy.PolicyAttributeClass,
		AttributeName: string(at),
	}
	// if is locked is a policy value
	// if is not locked then is a default.

	response, err := c.rawClient().PostConfigCleanPolicy(&request)
	if err != nil {
		return err
	}

	if response.Error != "" {
		err = fmt.Errorf(response.Error)
		return err
	}

	return nil
}

func (c *Connector) RequestSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {

	return RequestSshCertificate(c, req)

}

func (c *Connector) RetrieveSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	return RetrieveSshCertificate(c, req)
}

func (c *Connector) RetrieveCertificateMetaData(dn string) (*certificate.CertificateMetaData, error) {

	//first step convert dn to guid
	request := tpp_structs.DNToGUIDRequest{ObjectDN: dn}

	guidInfo, err := c.rawClient().PostConfigDnToGuid(&request)
	if err != nil {
		return nil, err
	}

	//second step get certificate metadata
	data, err := c.rawClient().GetCertificateById(guidInfo.GUID)
	if err != nil {
		return nil, err
	}

	return &data.CertificateMetaData, nil
}
