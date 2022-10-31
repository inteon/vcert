package tpp_api

import (
	"net/http"

	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

func (rc *RawClient) PostMetadataGetAll(metadataGetItemsRequest *tpp_structs.MetadataGetItemsRequest) (*tpp_structs.MetadataGetItemsResponse, error) {
	url := urlMetadataGetAll.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), metadataGetItemsRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.MetadataGetItemsResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostMetadataGet(metadataGetItemsRequest *tpp_structs.MetadataGetItemsRequest) (*tpp_structs.MetadataGetResponse, error) {
	url := urlMetadataGet.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), metadataGetItemsRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.MetadataGetResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}

func (rc *RawClient) PostMetadataSet(metadataGetItemsRequest *tpp_structs.MetadataSetRequest) (*tpp_structs.MetadataSetResponse, error) {
	url := urlMetadataSet.Absolute(rc.BaseUrl)

	req, err := newRequest(http.MethodPost, string(url), metadataGetItemsRequest)
	if err != nil {
		return nil, err
	}

	if err := rc.Authenticator(req); err != nil {
		return nil, err
	}

	responseObject := &tpp_structs.MetadataSetResponse{}

	if err := makeRequest(rc.HttpClient, req, responseObject); err != nil {
		return nil, err
	}

	return responseObject, nil
}
