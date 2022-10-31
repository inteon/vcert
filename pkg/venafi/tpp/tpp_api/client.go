package tpp_api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type RawClient struct {
	BaseUrl       string
	HttpClient    httpClient
	Authenticator func(*http.Request) error
}

var ua = fmt.Sprintf("vcert (%s/%s)", runtime.GOOS, runtime.GOARCH)

func newRequest(method string, url string, reqObj interface{}) (*http.Request, error) {
	var payload io.Reader
	if ((method == "POST") || (method == "PUT")) && reqObj != nil {
		jsonBytes, err := json.Marshal(reqObj)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewBuffer(jsonBytes)
	}

	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", ua)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept-Charset", "utf-8")

	if (method == "POST") || (method == "PUT") {
		req.Header.Add("Content-Type", "application/json; charset=utf-8")
	}

	return req, err
}

func makeRawRequest(client httpClient, request *http.Request, fn func(response *http.Response, body io.Reader) error) error {
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	statusOK := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !statusOK {
		return parseResponseErrors(resp.StatusCode, resp.Body)
	}

	if fn != nil {
		return fn(resp, resp.Body)
	}
	return nil
}

func makeRequest(client httpClient, request *http.Request, responseObject interface{}) error {
	return makeRawRequest(client, request, func(response *http.Response, body io.Reader) error {
		return json.NewDecoder(body).Decode(&responseObject)
	})
}
