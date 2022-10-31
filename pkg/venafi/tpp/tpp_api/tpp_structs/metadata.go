package tpp_structs

// REQ: vedsdk/metadata/getitems
// REQ: vedsdk/metadata/get
type MetadataGetItemsRequest struct {
	ObjectDN string `json:"DN"`
}

// RESP: vedsdk/metadata/getitems
type MetadataGetItemsResponse struct {
	Items  []MetadataItem `json:",omitempty"`
	Locked bool           `json:",omitempty"`
}

type MetadataItem struct {
	AllowedValues     []string `json:",omitempty"`
	Classes           []string `json:",omitempty"`
	ConfigAttribute   string   `json:",omitempty"`
	DefaultValues     []string `json:",omitempty"`
	DN                string   `json:",omitempty"`
	ErrorMessage      string   `json:",omitempty"`
	Guid              string   `json:",omitempty"`
	Help              string   `json:",omitempty"`
	Label             string   `json:",omitempty"`
	Name              string   `json:",omitempty"`
	Policyable        bool     `json:",omitempty"`
	RegularExpression string   `json:",omitempty"`
	RenderHidden      bool     `json:",omitempty"`
	RenderReadOnly    bool     `json:",omitempty"`
	Type              int      `json:",omitempty"`
}

// RESP: vedsdk/metadata/get
type MetadataGetResponse struct {
	Data   []MetadataKeyValueSet
	Locked bool `json:",omitempty"`
}

type MetadataKeyValueSet struct {
	Key   MetadataItem `json:",omitempty"`
	Value []string     `json:",omitempty"`
}

// REQ: vedsdk/metadata/set
type MetadataSetRequest struct {
	DN           string     `json:"DN"`
	GuidData     []GuidData `json:"GuidData"`
	KeepExisting bool       `json:"KeepExisting"`
}

type GuidData struct {
	ItemGuid string   `json:",omitempty"`
	List     []string `json:",omitempty"`
}

// RESP: vedsdk/metadata/set
type MetadataSetResponse struct {
	Locked bool `json:",omitempty"`
	Result int  `json:",omitempty"`
}
