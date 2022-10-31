package tpp_structs

// RESP: vedauth/authorize/verify
type OAuthVerifyTokenResponse struct {
	AccessIssuedOn string `json:"access_issued_on_ISO8601,omitempty"`
	ClientID       string `json:"application,omitempty"`
	Expires        string `json:"expires_ISO8601,omitempty"`
	GrantIssuedOn  string `json:"grant_issued_on_ISO8601,omitempty"`
	Identity       string `json:"identity,omitempty"`
	Scope          string `json:"scope,omitempty"`
	ValidFor       int    `json:"valid_for,omitempty"`
}

type AuthorizeRequest struct {
	Username string `json:",omitempty"`
	Password string `json:",omitempty"`
}

type AuthorizeResponse struct {
	APIKey     string `json:",omitempty"`
	ValidUntil string `json:",omitempty"` //todo: add usage
}

type OAuthGetRefreshTokenRequest struct {
	Client_id string `json:"client_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Scope     string `json:"scope"`
}
type OAuthGetRefreshTokenResponse struct {
	Access_token  string `json:"access_token,omitempty"`
	Expires       int    `json:"expires,omitempty"`
	ExpiresIn     int    `json:"expires_in,omitempty"` //Attribute added as it's used on vSSH
	Identity      string `json:"identity,omitempty"`
	Refresh_token string `json:"refresh_token,omitempty"`
	Refresh_until int    `json:"refresh_until,omitempty"`
	Scope         string `json:"scope,omitempty"`
	Token_type    string `json:"token_type,omitempty"`
}

type OAuthRefreshAccessTokenRequest struct {
	Refresh_token string `json:"refresh_token,omitempty"`
	Client_id     string `json:"client_id"`
}

type OAuthCertificateTokenRequest struct {
	Client_id string `json:"client_id"`
	Scope     string `json:"scope,omitempty"`
}

type OAuthRefreshAccessTokenResponse struct {
	Access_token  string `json:"access_token,omitempty"`
	Expires       int    `json:"expires,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Refresh_token string `json:"refresh_token,omitempty"`
	Refresh_until int    `json:"refresh_until,omitempty"`
	Token_type    string `json:"token_type,omitempty"`
}
