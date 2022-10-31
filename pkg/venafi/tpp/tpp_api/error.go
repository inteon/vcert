package tpp_api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

type HttpStatusError struct {
	StatusCode int
}

func (e HttpStatusError) Error() string {
	return fmt.Sprintf("HTTP status code %d", e.StatusCode)
}

func IsHttpStatusError(err error, statusCode int) bool {
	statusError := HttpStatusError{}
	return errors.As(err, &statusError) && statusError.StatusCode == statusCode
}

type InvalidResponseBody struct {
	HttpStatusError HttpStatusError
}

func (e InvalidResponseBody) Error() string {
	return fmt.Sprintf("%s: could not read error response body", e.HttpStatusError)
}

type UnstructuredResponseBody struct {
	HttpStatusError HttpStatusError
	Body            string
}

func (e UnstructuredResponseBody) Error() string {
	return fmt.Sprintf("%s: %s", e.HttpStatusError, e.Body)
}

type StructuredResponseBody struct {
	HttpStatusError HttpStatusError
	Body            tpp_structs.ResponseErrors
}

func (e StructuredResponseBody) Error() string {
	return fmt.Sprintf("%s: %v", e.HttpStatusError, e.Body)
}

func parseResponseErrors(statusCode int, body io.Reader) error {
	statusCodeErr := HttpStatusError{StatusCode: statusCode}

	responseBytes, err := io.ReadAll(body)
	if err != nil {
		return InvalidResponseBody{HttpStatusError: statusCodeErr}
	}

	var responseErrors tpp_structs.ResponseErrors

	decoder := json.NewDecoder(bytes.NewBuffer(responseBytes))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&responseErrors)
	if err == nil {
		return StructuredResponseBody{HttpStatusError: statusCodeErr, Body: responseErrors}
	} else {
		return UnstructuredResponseBody{HttpStatusError: statusCodeErr, Body: string(responseBytes)}
	}
}
