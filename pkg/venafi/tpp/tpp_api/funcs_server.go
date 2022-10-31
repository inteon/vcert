package tpp_api

import (
	"net/http"

	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (rc *RawClient) GetVedSdk() error {
	url := urlVedSdk.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
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

func (rc *RawClient) GetSystemStatusVersion() (*tpp_structs.SystemStatusVersion, error) {
	url := urlSystemStatusVersion.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.SystemStatusVersion{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
