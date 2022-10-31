package tpp_structs

import "github.com/Venafi/vcert/v4/pkg/certificate"

// REQ: vedsdk/sshcertificates/request
type TPPSshCertRequest struct {
	CADN                      string                 `json:"CADN,omitempty"`
	PolicyDN                  string                 `json:"PolicyDN,omitempty"`
	ObjectName                string                 `json:"ObjectName,omitempty"`
	DestinationAddresses      []string               `json:"DestinationAddresses,omitempty"`
	KeyId                     string                 `json:"KeyId,omitempty"`
	Principals                []string               `json:"Principals,omitempty"`
	ValidityPeriod            string                 `json:"ValidityPeriod,omitempty"`
	PublicKeyData             string                 `json:"PublicKeyData,omitempty"`
	Extensions                map[string]interface{} `json:"Extensions,omitempty"`
	ForceCommand              string                 `json:"ForceCommand,omitempty"`
	SourceAddresses           []string               `json:"SourceAddresses,omitempty"`
	IncludePrivateKeyData     bool                   `json:"IncludePrivateKeyData,omitempty"`
	PrivateKeyPassphrase      string                 `json:"PrivateKeyPassphrase,omitempty"`
	IncludeCertificateDetails bool                   `json:"IncludeCertificateDetails,omitempty"`
	ProcessingTimeout         string                 `json:"ProcessingTimeout,omitempty"`
}

// REQ: vedsdk/sshcertificates/retrieve
type TppSshCertRetrieveRequest struct {
	Guid                      string
	DN                        string
	IncludePrivateKeyData     bool
	PrivateKeyPassphrase      string
	PrivateKeyFormat          string
	IncludeCertificateDetails bool
}

// RESP: vedsdk/sshcertificates/request
// RESP: vedsdk/sshcertificates/retrieve
type TppSshCertOperationResponse struct {
	ProcessingDetails  certificate.ProcessingDetails
	Guid               string
	DN                 string
	CertificateData    string
	PrivateKeyData     string
	PublicKeyData      string
	CAGuid             string
	CADN               string
	CertificateDetails certificate.SshCertificateDetails
	Response           TppSshCertResponseInfo
}

type TppSshCertResponseInfo struct {
	ErrorCode    int
	ErrorMessage string
	Success      bool
}

// RESP: vedsdk/sshcertificates/template/retrieve
type SshTppCaTemplateResponse struct {
	AccessControl certificate.AccessControl
	Response      TppSshCertResponseInfo `json:"Response,omitempty"`
}

// REQ: vedsdk/sshcertificates/template/retrieve
type SshTppCaTemplateRequest struct {
	DN   string `json:"DN,omitempty"`
	Guid string `json:"Guid,omitempty"`
}
