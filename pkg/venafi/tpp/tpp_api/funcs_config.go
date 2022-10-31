package tpp_api

import (
	"net/http"

	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (rc *RawClient) PostConfigDnToGuid(dnToGUIDRequest *tpp_structs.DNToGUIDRequest) (*tpp_structs.DNToGUIDResponse, error) {
	url := urlConfigDnToGuid.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), dnToGUIDRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.DNToGUIDResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostConfigFindObjectsOfClass(request *tpp_structs.FindObjectsOfClassRequest) (*tpp_structs.FindObjectsOfClassResponse, error) {
	url := urlConfigFindObjectsOfClass.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.FindObjectsOfClassResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostConfigWritePolicy(request *tpp_structs.PolicySetAttributePayloadRequest) (*tpp_structs.PolicySetAttributeResponse, error) {
	url := urlConfigWritePolicy.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.PolicySetAttributeResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostConfigReadPolicy(request *tpp_structs.PolicyGetAttributePayloadRequest) (*tpp_structs.PolicyGetAttributeResponse, error) {
	url := urlConfigReadPolicy.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.PolicyGetAttributeResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostConfigCleanPolicy(request *tpp_structs.ClearTTPAttributesRequest) (*tpp_structs.PolicySetAttributeResponse, error) {
	url := urlConfigCleanPolicy.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.PolicySetAttributeResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostConfigIsValidPolicy(request *tpp_structs.PolicyExistPayloadRequest) (*tpp_structs.PolicyIsValidResponse, error) {
	url := urlConfigIsValidPolicy.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.PolicyIsValidResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostConfigCreatePolicy(request *tpp_structs.PolicyPayloadRequest) error {
	url := urlConfigCreatePolicy.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
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

func (rc *RawClient) PostConfigReadDn(request *tpp_structs.ConfigReadDNRequest) (*tpp_structs.ConfigReadDNResponse, error) {
	url := urlConfigReadDn.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.ConfigReadDNResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
