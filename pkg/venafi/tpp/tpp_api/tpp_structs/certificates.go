package tpp_structs

import "github.com/Venafi/vcert/v4/pkg/certificate"

// REQ: vedsdk/certificates/checkpolicy
type CheckPolicyRequest struct {
	PolicyDN string `json:"PolicyDN"`
}

// RESP: vedsdk/certificates/checkpolicy
type CheckPolicyResponse struct {
	Error  string          `json:"Error"`
	Policy *PolicyResponse `json:"Policy"`
}

type PolicyResponse struct {
	CertificateAuthority LockedAttribute `json:"CertificateAuthority"`
	CsrGeneration        LockedAttribute `json:"CsrGeneration"`
	KeyGeneration        LockedAttribute `json:"KeyGeneration"`
	KeyPair              KeyPairResponse `json:"KeyPair"`
	ManagementType       LockedAttribute `json:"ManagementType"`

	PrivateKeyReuseAllowed  bool `json:"PrivateKeyReuseAllowed"`
	SubjAltNameDnsAllowed   bool `json:"SubjAltNameDnsAllowed"`
	SubjAltNameEmailAllowed bool `json:"SubjAltNameEmailAllowed"`
	SubjAltNameIpAllowed    bool `json:"SubjAltNameIpAllowed"`
	SubjAltNameUpnAllowed   bool `json:"SubjAltNameUpnAllowed"`
	SubjAltNameUriAllowed   bool `json:"SubjAltNameUriAllowed"`

	Subject               SubjectResponse `json:"Subject"`
	UniqueSubjectEnforced bool            `json:"UniqueSubjectEnforced"`
	WhitelistedDomains    []string        `json:"WhitelistedDomains"`
	WildcardsAllowed      bool            `json:"WildcardsAllowed"`
}

type KeyPairResponse struct {
	KeyAlgorithm  LockedAttribute    `json:"KeyAlgorithm"`
	KeySize       LockedIntAttribute `json:"KeySize"`
	EllipticCurve LockedAttribute    `json:"EllipticCurve"`
}

type SubjectResponse struct {
	City               LockedAttribute      `json:"City"`
	Country            LockedAttribute      `json:"Country"`
	Organization       LockedAttribute      `json:"Organization"`
	OrganizationalUnit LockedArrayAttribute `json:"OrganizationalUnit"`
	State              LockedAttribute      `json:"State"`
}

// REQ: vedsdk/certificates/%s
type CertificateInfo struct {
	AttributeData []NameSliceValuePair
}

type NameSliceValuePair struct {
	Name  string
	Value []string
}

// REQ: vedsdk/certificates/dissociate
type CertificateDissociate struct {
	CertificateDN string
	ApplicationDN []string
	DeleteOrphans bool
}

// REQ: vedsdk/certificates/associate
type CertificateAssociate struct {
	CertificateDN string
	ApplicationDN []string
	PushToNew     bool
}

// RESP: vedsdk/certificates/%s
type CertificateDetailsResponse struct {
	certificate.CertificateMetaData `json:",inline"`

	Consumers []string
	Disabled  bool `json:",omitempty"`
}

// REQ: vedsdk/certificates/request
type CertificateRequest struct {
	PolicyDN                string          `json:",omitempty"`
	CADN                    string          `json:",omitempty"`
	ObjectName              string          `json:",omitempty"`
	Subject                 string          `json:",omitempty"`
	OrganizationalUnit      string          `json:",omitempty"`
	Organization            string          `json:",omitempty"`
	City                    string          `json:",omitempty"`
	State                   string          `json:",omitempty"`
	Country                 string          `json:",omitempty"`
	SubjectAltNames         []SanItem       `json:",omitempty"`
	Contact                 string          `json:",omitempty"`
	CASpecificAttributes    []NameValuePair `json:",omitempty"`
	Origin                  string          `json:",omitempty"`
	PKCS10                  string          `json:",omitempty"`
	KeyAlgorithm            string          `json:",omitempty"`
	KeyBitSize              int             `json:",omitempty"`
	EllipticCurve           string          `json:",omitempty"`
	DisableAutomaticRenewal bool            `json:",omitempty"`
	CustomFields            []CustomField   `json:",omitempty"`
	Devices                 []Device        `json:",omitempty"`
	CertificateType         string          `json:",omitempty"`
	Reenable                bool            `json:",omitempty"`
}

type SanItem struct {
	Type int    `json:""`
	Name string `json:""`
}

type NameValuePair struct {
	Name  string `json:",omitempty"`
	Value string `json:",omitempty"`
}

type CustomField struct {
	Name   string
	Values []string
}

type Device struct {
	PolicyDN     string
	ObjectName   string
	Host         string
	Applications []Application
}

type Application struct {
	ObjectName     string
	Class          string
	DriverName     string
	ValidationHost string `json:",omitempty"`
	ValidationPort string `json:",omitempty"`
}

// REQ: vedsdk/certificates/retrieve
type CertificateRetrieveRequest struct {
	CertificateDN     string `json:",omitempty"`
	Format            string `json:",omitempty"`
	Password          string `json:",omitempty"`
	IncludePrivateKey bool   `json:",omitempty"`
	IncludeChain      bool   `json:",omitempty"`
	FriendlyName      string `json:",omitempty"`
	RootFirstOrder    bool   `json:",omitempty"`
}

// RESP: vedsdk/certificates/retrieve
type CertificateRetrieveResponse struct {
	CertificateData string `json:",omitempty"`
	Format          string `json:",omitempty"`
	Filename        string `json:",omitempty"`
	Status          string `json:",omitempty"`
	Stage           int    `json:",omitempty"`
}

// REQ: vedsdk/certificates/revoke
type CertificateRevokeRequest struct {
	CertificateDN string           `json:",omitempty"`
	Thumbprint    string           `json:",omitempty"`
	Reason        RevocationReason `json:",omitempty"`
	Comments      string           `json:",omitempty"`
	Disable       bool             `json:",omitempty"`
}

type RevocationReason int

// RESP: vedsdk/certificates/revoke
type CertificateRevokeResponse struct {
	Requested bool   `json:",omitempty"`
	Success   bool   `json:",omitempty"`
	Error     string `json:",omitempty"`
}

// REQ: vedsdk/certificates/renew
type CertificateRenewRequest struct {
	CertificateDN string `json:",omitempty"`
	PKCS10        string `json:",omitempty"`
}

// RESP: vedsdk/certificates/renew
type CertificateRenewResponse struct {
	Success bool   `json:",omitempty"`
	Error   string `json:",omitempty"`
}

// RESP: vedsdk/certificates/request
type CertificateRequestResponse struct {
	CertificateDN string `json:",omitempty"`
	Error         string `json:",omitempty"`
}

// REQ: vedsdk/certificates/import
type ImportRequest struct {
	PolicyDN        string `json:",omitempty"`
	ObjectName      string `json:",omitempty"`
	CertificateData string `json:",omitempty"`
	PrivateKeyData  string `json:",omitempty"`
	Password        string `json:",omitempty"`
	Reconcile       bool   `json:",omitempty"`
}
