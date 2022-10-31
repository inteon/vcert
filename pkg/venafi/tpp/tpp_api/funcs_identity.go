package tpp_api

import (
	"net/http"

	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (rc *RawClient) GetIdentitySelf() (*tpp_structs.IdentitiesResponse, error) {
	url := urlIdentitySelf.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.IdentitiesResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostIdentityValidate(validateIdentityRequest tpp_structs.ValidateIdentityRequest) (*tpp_structs.ValidateIdentityResponse, error) {
	url := urlIdentityValidate.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), validateIdentityRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.ValidateIdentityResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostIdentityBrowse(browseIdentitiesRequest tpp_structs.BrowseIdentitiesRequest) (*tpp_structs.BrowseIdentitiesResponse, error) {
	url := urlIdentityBrowse.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), browseIdentitiesRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.BrowseIdentitiesResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
