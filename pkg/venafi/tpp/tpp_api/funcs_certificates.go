package tpp_api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (rc *RawClient) PostCertificateRetrieve(certReq *tpp_structs.CertificateRetrieveRequest) (*tpp_structs.CertificateRetrieveResponse, error) {
	url := urlCertificateRetrieve.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), certReq)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.CertificateRetrieveResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PutCertificate(guid string, certificateInfo *tpp_structs.CertificateInfo) error {
	url := urlCertificateById.Absolute(rc.BaseUrl).Params(guid)

	req, err := newRequest(http.MethodPut, string(url), certificateInfo)
	if err != nil {
		return err
	}

	if err := rc.Authenticator(req); err != nil {
		return err
	}

	if err := makeRawRequest(rc.HttpClient, req, nil); err != nil {
		return err
	}

	return nil
}

func (rc *RawClient) PostCertificateRequest(renewReq *tpp_structs.CertificateRequest) (*tpp_structs.CertificateRequestResponse, error) {
	url := urlCertificateRequest.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), renewReq)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.CertificateRequestResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostCertificateRenew(renewReq *tpp_structs.CertificateRenewRequest) (*tpp_structs.CertificateRenewResponse, error) {
	url := urlCertificateRenew.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), renewReq)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.CertificateRenewResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostCertificateRevoke(certificateRevokeRequest *tpp_structs.CertificateRevokeRequest) (*tpp_structs.CertificateRevokeResponse, error) {
	url := urlCertificateRevoke.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), certificateRevokeRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.CertificateRevokeResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostCertificateImport(importRequest *tpp_structs.ImportRequest) (*certificate.ImportResponse, error) {
	url := urlCertificateImport.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), importRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &certificate.ImportResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) GetCertificate(searchRequest []string) (*certificate.CertSearchResponse, error) {
	url := fmt.Sprintf("%s?%s", urlCertificate.Absolute(rc.BaseUrl), strings.Join(searchRequest, "&"))

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &certificate.CertSearchResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) GetCertificateById(guid string) (*tpp_structs.CertificateDetailsResponse, error) {
	url := urlCertificateById.Absolute(rc.BaseUrl).Params(guid)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.CertificateDetailsResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostCertificateDissociate(certificateDissociate *tpp_structs.CertificateDissociate) error {
	url := urlCertificateDissociate.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), certificateDissociate)
	if err != nil {
		return err
	}

	if err := rc.Authenticator(req); err != nil {
		return err
	}

	if err := makeRawRequest(rc.HttpClient, req, nil); err != nil {
		return err
	}

	return nil
}

func (rc *RawClient) PostCertificateAssociate(certificateAssociate *tpp_structs.CertificateAssociate) error {
	url := urlCertificateAssociate.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), certificateAssociate)
	if err != nil {
		return err
	}

	if err := rc.Authenticator(req); err != nil {
		return err
	}

	if err := makeRawRequest(rc.HttpClient, req, nil); err != nil {
		return err
	}

	return nil
}

func (rc *RawClient) PostCertificateCheckPolicy(certificateCheckPolicy *tpp_structs.CheckPolicyRequest) (*tpp_structs.CheckPolicyResponse, error) {
	url := urlCertificateCheckPolicy.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), certificateCheckPolicy)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.CheckPolicyResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
