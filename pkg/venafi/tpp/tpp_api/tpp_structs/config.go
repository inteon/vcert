package tpp_structs

type TppAttribute string

const (
	//tpp policy attributes
	TppContact               TppAttribute = "Contact"
	TppApprover              TppAttribute = "Approver"
	TppCertificateAuthority  TppAttribute = "Certificate Authority"
	TppProhibitWildcard      TppAttribute = "Prohibit Wildcard"
	TppDomainSuffixWhitelist TppAttribute = "Domain Suffix Whitelist"
	TppOrganization          TppAttribute = "Organization"
	TppOrganizationalUnit    TppAttribute = "Organizational Unit"
	TppCity                  TppAttribute = "City"
	TppState                 TppAttribute = "State"
	TppCountry               TppAttribute = "Country"
	TppKeyAlgorithm          TppAttribute = "Key Algorithm"
	TppKeyBitStrength        TppAttribute = "Key Bit Strength"
	TppEllipticCurve         TppAttribute = "Elliptic Curve"
	TppProhibitedSANTypes    TppAttribute = "Prohibited SAN Types"
	TppAllowPrivateKeyReuse  TppAttribute = "Allow Private Key Reuse"
	TppWantRenewal           TppAttribute = "Want Renewal"
	TppDnsAllowed            TppAttribute = "DNS"
	TppIpAllowed             TppAttribute = "IP"
	TppEmailAllowed          TppAttribute = "Email"
	TppUriAllowed            TppAttribute = "URI"
	TppUpnAllowed            TppAttribute = "UPN"
	TppManagementType        TppAttribute = "Management Type"
	TppManualCSR             TppAttribute = "Manual Csr"

	TppManagementTypeEnrollment   = "Enrollment"
	TppManagementTypeProvisioning = "Provisioning"
)

// RESP: vedsdk/config/isvalid
type PolicyIsValidResponse struct {
	Error        string       `json:"Error"`
	Result       int          `json:"Result"`
	PolicyObject PolicyObject `json:"Object"`
}

type PolicyObject struct {
	AbsoluteGUID string `json:"AbsoluteGUID"`
	DN           string `json:"DN"`
	GUID         string `json:"GUID"`
	Id           int    `json:"Id"`
	Name         string `json:"Name"`
	Parent       string `json:"Parent"`
	Revision     int    `json:"Revision"`
	TypeName     string `json:"TypeName"`
}

// REQ: vedsdk/config/create
type PolicyPayloadRequest struct {
	Class    string `json:"Class"`
	ObjectDN string `json:"ObjectDN"`
}

// REQ: vedsdk/config/writepolicy
type PolicySetAttributePayloadRequest struct {
	Locked        bool     `json:"Locked"`
	ObjectDN      string   `json:"ObjectDN"`
	Class         string   `json:"Class"`
	AttributeName string   `json:"AttributeName"`
	Values        []string `json:"Values"`
}

// RESP: vedsdk/config/writepolicy
// RESP: vedsdk/config/clearpolicyattribute
type PolicySetAttributeResponse struct {
	Error  string `json:"Error"`
	Result int    `json:"Result"`
}

// REQ: vedsdk/config/readpolicy
type PolicyGetAttributePayloadRequest struct {
	ObjectDN      string   `json:"ObjectDN"`
	Class         string   `json:"Class"`
	AttributeName string   `json:"AttributeName"`
	Values        []string `json:"Values"`
}

// REQ: vedsdk/config/isvalid
type PolicyExistPayloadRequest struct {
	ObjectDN string `json:"ObjectDN"`
}

// RESP: vedsdk/config/readpolicy
type PolicyGetAttributeResponse struct {
	Locked bool     `json:"Locked"`
	Result int      `json:"Result"`
	Values []string `json:"Values"`
}

// REQ: vedsdk/config/clearpolicyattribute
type ClearTTPAttributesRequest struct {
	ObjectDN      string `json:"ObjectDN"`
	Class         string `json:"Class"`
	AttributeName string `json:"AttributeName"`
}

type LockedAttribute struct {
	Value  string
	Locked bool
}
type LockedIntAttribute struct {
	Value  int
	Locked bool
}
type LockedArrayAttribute struct {
	Value  []string `json:"Values"`
	Locked bool
}

// RESP: vedsdk/config/dntoguid
type DNToGUIDResponse struct {
	ClassName        string `json:"ClassName"`
	GUID             string `json:"GUID"`
	HierarchicalGUID string `json:"HierarchicalGUID"`
	Result           int    `json:"Result"`
	Revision         int    `json:"Revision"`
}

// REQ: vedsdk/config/dntoguid
type DNToGUIDRequest struct {
	ObjectDN string `json:"ObjectDN"`
}

// REQ: vedsdk/config/findobjectsofclass
type FindObjectsOfClassRequest struct {
	Class    string `json:"Class"`
	ObjectDN string `json:"ObjectDN"`
}

// RESP: vedsdk/config/findobjectsofclass
type FindObjectsOfClassResponse struct {
	PolicyObjects []PolicyObject `json:"Objects,omitempty"`
}

// REQ: vedsdk/config/readdn
type ConfigReadDNRequest struct {
	ObjectDN      string `json:",omitempty"`
	AttributeName string `json:",omitempty"`
}

// RESP: vedsdk/config/readdn
type ConfigReadDNResponse struct {
	Result int      `json:",omitempty"`
	Values []string `json:",omitempty"`
}

// Deprecated: this should be moved/ removed
type TppPolicy struct {
	//general values
	Name *string
	//Owners []string "owners": string[],(permissions only)	prefixed name/universal
	Contact []string
	//Permissions string "userAccess": string,	(permissions)	prefixed name/universal
	Approver []string

	//policy's values
	ProhibitWildcard      *int
	DomainSuffixWhitelist []string
	ProhibitedSANType     []string
	CertificateAuthority  *string
	ManagementType        *LockedAttribute

	//subject attributes
	Organization       *LockedAttribute
	OrganizationalUnit *LockedArrayAttribute
	City               *LockedAttribute
	State              *LockedAttribute
	Country            *LockedAttribute

	//keypair attributes
	KeyAlgorithm         *LockedAttribute
	KeyBitStrength       *LockedAttribute
	EllipticCurve        *LockedAttribute
	ManualCsr            *LockedAttribute
	AllowPrivateKeyReuse *int
	WantRenewal          *int
}
