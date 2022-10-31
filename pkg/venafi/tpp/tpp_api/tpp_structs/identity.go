package tpp_structs

// REQ: vedsdk/identity/browse
type BrowseIdentitiesRequest struct {
	Filter       string
	Limit        int
	IdentityType int
}

// REQ: vedsdk/identity/validate
type ValidateIdentityRequest struct {
	ID IdentityInformation
}

type IdentityInformation struct {
	PrefixedUniversal string
}

// RESP: vedsdk/identity/browse
type BrowseIdentitiesResponse struct {
	Identities []Identity `json:"Identities"`
}

// RESP: vedsdk/identity/self
type IdentitiesResponse struct {
	Identities []Identity `json:"Identities"`
}

// RESP: vedsdk/identity/validate
type ValidateIdentityResponse struct {
	ID Identity
}

type Identity struct {
	FullName          string `json:"FullName"`
	Name              string `json:"Name"`
	Prefix            string `json:"Prefix"`
	PrefixedName      string `json:"PrefixedName"`
	PrefixedUniversal string `json:"PrefixedUniversal"`
	Type              int    `json:"Type"`
	Universal         string `json:"Universal"`
}
