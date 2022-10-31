package tpp_api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (rc *RawClient) PostSshCertificateRequest(request *tpp_structs.TPPSshCertRequest) (*tpp_structs.TppSshCertOperationResponse, error) {
	url := urlSshCertificateRequest.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.TppSshCertOperationResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostSshCertificateRetrieve(sshRetrieveReq *tpp_structs.TppSshCertRetrieveRequest) (*tpp_structs.TppSshCertOperationResponse, error) {
	url := urlSshCertificateRetrieve.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), sshRetrieveReq)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.TppSshCertOperationResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) GetSshTemplatePublicKeyData(query []string) ([]byte, error) {
	url := fmt.Sprintf("%s?%s", urlSshTemplatePublicKeyData.Absolute(rc.BaseUrl), strings.Join(query, "&"))

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	var bytes []byte
	if err := makeRawRequest(rc.HttpClient, req, func(_ *http.Response, body io.Reader) (err error) {
		bytes, err = io.ReadAll(body)
		return
	}); err != nil {
		return nil, err
	}

	return bytes, nil
}

func (rc *RawClient) GetSshTemplateAvaliable() ([]certificate.SshAvaliableTemplate, error) {
	url := urlSshTemplateAvaliable.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := []certificate.SshAvaliableTemplate{}

	if err := makeRequest(rc.HttpClient, req, &responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostSshTemplateRetrieve(request *tpp_structs.SshTppCaTemplateRequest) (*tpp_structs.SshTppCaTemplateResponse, error) {
	url := urlSshTemplateRetrieve.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.SshTppCaTemplateResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
