package tpp_api

import (
	"net/http"

	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (rc *RawClient) GetAuthorizeVerify() (*tpp_structs.OAuthVerifyTokenResponse, error) {
	url := urlAuthorizeVerify.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodGet, string(url), nil)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.OAuthVerifyTokenResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) GetRevokeAccessToken() error {
	url := urlRevokeAccessToken.Absolute(rc.BaseUrl)

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

func (rc *RawClient) GetIsAuthServer() error {
	url := urlAuthorizeIsAuthServer.Absolute(rc.BaseUrl)

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

func (rc *RawClient) PostAuthorizeOAuth(request *tpp_structs.OAuthGetRefreshTokenRequest) (*tpp_structs.OAuthGetRefreshTokenResponse, error) {
	url := urlAuthorizeOAuth.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.OAuthGetRefreshTokenResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostAuthorizeRefreshAccessToken(request *tpp_structs.OAuthRefreshAccessTokenRequest) (*tpp_structs.OAuthRefreshAccessTokenResponse, error) {
	url := urlAuthorizeRefreshAccessToken.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.OAuthRefreshAccessTokenResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostAuthorizeCertificate(request *tpp_structs.OAuthCertificateTokenRequest) (*tpp_structs.OAuthGetRefreshTokenResponse, error) {
	url := urlAuthorizeCertificate.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.OAuthGetRefreshTokenResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

// Deprecated: use other authorize endpoints instead
func (rc *RawClient) PostAuthorize(request *tpp_structs.AuthorizeRequest) (*tpp_structs.AuthorizeResponse, error) {
	url := urlAuthorize.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), request)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.AuthorizeResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
