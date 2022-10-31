package tpp_api

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fakeClient struct {
	statusCode int
	body       []byte
}

func (fc *fakeClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: fc.statusCode,
		Body:       io.NopCloser(bytes.NewBuffer(fc.body)),
	}, nil
}

func fakeRawClient(statusCode int, body []byte) *RawClient {
	return &RawClient{
		Authenticator: func(r *http.Request) error { return nil },
		HttpClient: &fakeClient{
			statusCode: statusCode,
			body:       body,
		},
	}
}

func TestParseCertificateSearchResponse(t *testing.T) {
	body := `
		{
		  "Certificates": [
			{
			  "CreatedOn": "2018-06-06T12:49:11.4795797Z",
			  "DN": "\\VED\\Policy\\devops\\vcert\\renx3.venafi.example.com",
			  "Guid": "{f32c5cd0-9b77-47ab-bf27-65a1159ff98e}",
			  "Name": "renx3.venafi.example.com",
			  "ParentDn": "\\VED\\Policy\\devops\\vcert",
			  "SchemaClass": "X509 Server Certificate",
			  "_links": [
				{
				  "Details": "/vedsdk/certificates/%7bf32c5cd0-9b77-47ab-bf27-65a1159ff98e%7d"
				}
			  ]
			}
		  ],
		  "DataRange": "Certificates 1 - 1",
		  "TotalCount": 1
		}`

	res, err := fakeRawClient(http.StatusOK, []byte(body)).GetCertificate([]string{"unused"})
	if err != nil {
		t.Fatal(err)
	}

	if res.Certificates[0].DN != "\\VED\\Policy\\devops\\vcert\\renx3.venafi.example.com" {
		t.Fatal("failed to parse cert DN")
	}
}

func TestParseCertificateDetailsResponse(t *testing.T) {
	body := `
		{
		  "CertificateAuthorityDN": "\\VED\\Policy\\devops\\msca_template",
		  "CertificateDetails": {
			"AIACAIssuerURL": [
			  "0:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt",
			  "1:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority"
			],
			"AIAKeyIdentifier": "3CAC9CA60DA130D456A73D78BC231BECB47B4D75",
			"C": "US",
			"CDPURI": "0::False:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl",
			"CN": "t1579099443-xiel.venafi.example.com",
			"EnhancedKeyUsage": "Server Authentication(1.3.6.1.5.5.7.3.1)",
			"Issuer": "CN=QA Venafi CA, DC=venqa, DC=venafi, DC=com",
			"KeyAlgorithm": "RSA",
			"KeySize": 8192,
			"KeyUsage": "KeyEncipherment, DigitalSignature",
			"L": "Las Vegas",
			"O": "Venafi, Inc.",
			"OU": [
			  "Automated Tests"
			],
			"PublicKeyHash": "8637C052479F9C4A01CC0CEE600769597DF69DA8",
			"S": "Nevada",
			"SKIKeyIdentifier": "C65C994B38A5B17841C536A8C8189C6613B02C44",
			"Serial": "6D007AAF80B115C1BE51B6F94E0000007AAF80",
			"SignatureAlgorithm": "sha256RSA",
			"SignatureAlgorithmOID": "1.2.840.113549.1.1.11",
			"StoreAdded": "2020-01-15T14:47:02.0862587Z",
			"Subject": "CN=t1579099443-xiel.venafi.example.com, OU=Automated Tests, O=\"Venafi, Inc.\", L=Las Vegas, S=Nevada, C=US",
			"SubjectAltNameDNS": [
			  "t1579099443-xiel.venafi.example.com"
			],
			"SubjectAltNameURI": [
			  "https://example.com/test"
			],
			"TemplateMajorVersion": "100",
			"TemplateMinorVersion": "4",
			"TemplateName": "WebServer-2008(8years)",
			"TemplateOID": "1.3.6.1.4.1.311.21.8.2344178.8460394.1920656.15056892.1115285.96.9686371.12506947",
			"Thumbprint": "D9F8A14D6687824D2F25D1BE1C2A24697B84CF68",
			"ValidFrom": "2020-01-15T14:36:29.0000000Z",
			"ValidTo": "2028-01-13T14:36:29.0000000Z"
		  },
		  "Contact": [
			"local:{f47ab62f-65d4-4a7f-8a8a-cd5440ce2d60}"
		  ],
		  "CreatedBy": [
			"Web SDK"
		  ],
		  "CreatedOn": "2020-01-15T14:46:53.2296661Z",
		  "CustomFields": [
			{
			  "Name": "custom",
			  "Type": "Text",
			  "Value": [
				"2019-10-10"
			  ]
			}
		  ],
		  "DN": "\\VED\\Policy\\devops\\vcert\\t1579099443-xiel.venafi.example.com",
		  "Guid": "{d1542a81-9268-4c62-af7e-8090fac5194d}",
		  "ManagementType": "Enrollment",
		  "Name": "t1579099443-xiel.venafi.example.com",
		  "ParentDn": "\\VED\\Policy\\devops\\vcert",
		  "ProcessingDetails": {},
		  "RenewalDetails": {
			"City": "Las Vegas",
			"Country": "US",
			"KeySize": 8192,
			"Organization": "Venafi, Inc.",
			"OrganizationalUnit": [
			  "Automated Tests"
			],
			"State": "Nevada",
			"Subject": "t1579099443-xiel.venafi.example.com",
			"SubjectAltNameURI": [
			  "https://example.com/test"
			]
		  },
		  "SchemaClass": "X509 Server Certificate",
		  "ValidationDetails": {
			"LastValidationStateUpdate": "0001-01-01T00:00:00.0000000Z"
		  }
		}`

	res, err := fakeRawClient(http.StatusOK, []byte(body)).GetCertificateById("unused")
	if err != nil {
		t.Fatal(err)
	}

	if res.CustomFields[0].Value[0] != "2019-10-10" {
		t.Fatal("invalid custom field value")
	}
}

func TestParseConfigFindPolicyData(t *testing.T) {
	data := []byte("{\"Locked\":false,\"PolicyDN\":\"\\\\VED\\\\Policy\\\\Web SDK Testing\",\"Result\":1,\"Values\":[\"Engineering\",\"Quality Assurance\"]}")
	tppData, err := fakeRawClient(http.StatusOK, data).PostConfigReadPolicy(nil)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	if len(tppData.Values) != 2 {
		t.Fatalf("Values count was not expected count of 2 actual count is %d", len(tppData.Values))
	}

	_, err = fakeRawClient(http.StatusBadRequest, data).PostConfigReadPolicy(nil)
	if err == nil {
		t.Fatalf("err is nil when expected to not be")
	}

	if !strings.Contains(err.Error(), "HTTP status code 400") {
		t.Fatalf("Parse Certificate error response did not include expected string: Bad Request -- Actual: %s", err)
	}

	data = []byte("bad data")
	_, err = fakeRawClient(http.StatusOK, data).PostConfigReadPolicy(nil)
	if err == nil {
		t.Fatalf("ParseConfigData with bad data did not return an error")
	}
}

func TestParseCertificateRequestData(t *testing.T) {
	data := []byte("{\"CertificateDN\":\"\\\\VED\\\\Policy\\\\Web SDK Testing\\\\bonjoTest 33\"}")

	response, err := fakeRawClient(http.StatusOK, data).PostCertificateRequest(nil)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if !strings.EqualFold(response.CertificateDN, "\\VED\\Policy\\Web SDK Testing\\bonjoTest 33") {
		t.Fatalf("Parse Certificate retrieve response did not include expected CertificateDN: \\VED\\Policy\\Web SDK Testing\\bonjoTest 33 -- Actual: %s", response.CertificateDN)
	}

	_, err = fakeRawClient(http.StatusBadRequest, data).PostCertificateRequest(nil)
	if err == nil {
		t.Fatalf("err is nil when expected to not be")
	}

	if !strings.Contains(err.Error(), "HTTP status code 400") {
		t.Fatalf("Parse Certificate error response did not include expected string: Bad Request -- Actual: %s", err)
	}

	data = []byte("bad data")
	_, err = fakeRawClient(http.StatusOK, data).PostCertificateRequest(nil)
	if err == nil {
		t.Fatalf("ParseRequestData with bad data did not return an error")
	}
}

func TestParseCertificateRetrieveData(t *testing.T) {
	data := []byte("{\"CertificateData\":\"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlHYWpDQ0JWS2dBd0lCQWdJS0hyT1Z5d0FBQUNxNHp6QU5CZ2txaGtpRzl3MEJBUVVGQURCWE1STXdFUVlLDQpDWkltaVpQeUxHUUJHUllEWTI5dE1SWXdGQVlLQ1pJbWlaUHlMR1FCR1JZR2RtVnVZV1pwTVJVd0V3WUtDWkltDQppWlB5TEdRQkdSWUZkbVZ1Y1dFeEVUQVBCZ05WQkFNVENGWmxibEZCSUVOQk1CNFhEVEUyTURJeE9ESXlNRFl3DQpNMW9YRFRFM01URXdPVEl5TlRnek1sb3dnWXd4Q3pBSkJnTlZCQVlUQWxWVE1RMHdDd1lEVlFRSUV3UlZkR0ZvDQpNUXd3Q2dZRFZRUUhFd05UVEVNeEZUQVRCZ05WQkFvVERGWmxibUZtYVN3Z1NXNWpMakVVTUJJR0ExVUVDeE1MDQpSVzVuYVc1bFpYSnBibWN4R2pBWUJnTlZCQXNURVZGMVlXeHBkSGtnUVhOemRYSmhibU5sTVJjd0ZRWURWUVFEDQpFdzUwWlhOMExtSnZibXB2TG1OdmJUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCDQpBTXcwR2RrNm1CeUt0WHJBcXpQQ3pmVzV0V2lTZFFDTzhycHJadStRQXZwYXlUSjBJbFBBbE5QZEt5M3JlRUM1DQowMWxjUlpvYSt0aUpuazVKNWRqcU9oaXErdkhNKzRJYkJWb3lPODNPdmxYd045a1gyc0NuTGJ1MkFTeUJGZmVwDQpVWDJuNmJ5aGVKS3FJSUw1ZXd3TFlMWndYYUhHa1pZL2Q0ZXFSVmM5UTN3Nzh4SkJSbXdCNzhad1lQeVdYd0ZXDQpRTUVyRitMdkRZTnhQeGRtWXVSdFRWRTkvUHBpaWNKUnpVWWUzV25KcEhNRzQ0cDJDR3gvVHJQcDZkUHVoNlUxDQpET2J2UEt0UHAyR25JZy9aaWovL3ZDMU94eFNKMXdFdzdXMFE1N3JpMWl0QkxmTFg3MS9WOEpHMUFEN0t6cFQwDQp6ZGM1OERvVWxHTHg0cXd4dWFmaDR0c0NBd0VBQWFPQ0F3QXdnZ0w4TUIwR0ExVWREZ1FXQkJTTU5XK2Z4ZDZFDQphQ0tkaHk3dG11WS9YSnh4UmpBZkJnTlZIU01FR0RBV2dCUkdWbzIzMkxKRzA5OGg2RVFTUEZBVFFTdzdBVENDDQpBVnNHQTFVZEh3U0NBVkl3Z2dGT01JSUJTcUNDQVVhZ2dnRkNoajlvZEhSd09pOHZNbXM0TFhabGJuRmhMWEJrDQpZeTUyWlc1eFlTNTJaVzVoWm1rdVkyOXRMME5sY25SRmJuSnZiR3d2Vm1WdVVVRWxNakJEUVM1amNteUdnYjlzDQpaR0Z3T2k4dkwwTk9QVlpsYmxGQkpUSXdRMEVzUTA0OU1tczRMWFpsYm5GaExYQmtZeXhEVGoxRFJGQXNRMDQ5DQpVSFZpYkdsakpUSXdTMlY1SlRJd1UyVnlkbWxqWlhNc1EwNDlVMlZ5ZG1salpYTXNRMDQ5UTI5dVptbG5kWEpoDQpkR2x2Yml4RVF6MTJaVzV4WVN4RVF6MTJaVzVoWm1rc1JFTTlZMjl0UDJObGNuUnBabWxqWVhSbFVtVjJiMk5oDQpkR2x2Ymt4cGMzUS9ZbUZ6WlQ5dlltcGxZM1JEYkdGemN6MWpVa3hFYVhOMGNtbGlkWFJwYjI1UWIybHVkSVk5DQpabWxzWlRvdkx6SnJPQzEyWlc1eFlTMXdaR011ZG1WdWNXRXVkbVZ1WVdacExtTnZiUzlEWlhKMFJXNXliMnhzDQpMMVpsYmxGQklFTkJMbU55YkRDQnhBWUlLd1lCQlFVSEFRRUVnYmN3Z2JRd2diRUdDQ3NHQVFVRkJ6QUNob0drDQpiR1JoY0Rvdkx5OURUajFXWlc1UlFTVXlNRU5CTEVOT1BVRkpRU3hEVGoxUWRXSnNhV01sTWpCTFpYa2xNakJUDQpaWEoyYVdObGN5eERUajFUWlhKMmFXTmxjeXhEVGoxRGIyNW1hV2QxY21GMGFXOXVMRVJEUFhabGJuRmhMRVJEDQpQWFpsYm1GbWFTeEVRejFqYjIwL1kwRkRaWEowYVdacFkyRjBaVDlpWVhObFAyOWlhbVZqZEVOc1lYTnpQV05sDQpjblJwWm1sallYUnBiMjVCZFhSb2IzSnBkSGt3Q3dZRFZSMFBCQVFEQWdXZ01Eb0dDU3NHQVFRQmdqY1ZCd1F0DQpNQ3NHSXlzR0FRUUJnamNWQ0lHUGlYS0VoTEJxOVowUWg1Yi9mTVNKRldDYzZFT0Z1NlJkQWdGa0FnRUpNQk1HDQpBMVVkSlFRTU1Bb0dDQ3NHQVFVRkJ3TUJNQnNHQ1NzR0FRUUJnamNWQ2dRT01Bd3dDZ1lJS3dZQkJRVUhBd0V3DQpHUVlEVlIwUkJCSXdFSUlPZEdWemRDNWliMjVxYnk1amIyMHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBSFhSDQpIZXZSTnZhL3l3YVU3VHJTMUlTb2ZqcUVtT1MwVDB2ZWlDenVFZkhwTitZWGg2SzhZVXViODFWTHF2aTJxSmJUDQp0bExwSmNVTytBVHBrYWV5K2RQU1B2WVNUejVKY3BaWjU3MCsrUTg0RFFPcnEvcmJjamFHMHBsNDk1Sk1nQzVRDQo4VUlZa0JTMndEWWhJRVdpYmZZVU91S2c3Y3RVRTV2eVI3eFkvU1JhaFBwUUNVS1o0QmJqNnhnV2VmOW5IVjVVDQpuVWZqQzVjdXJ3TUE5RGVweFBHWGtwVm5FK1RzK1k4ZlFwSmdVUUtmNHRoWklwbVB1d044NU1BVXJxTW9YbkNyDQpIM0Y4NzJJNnF4RlkzUzhyNk1TZUdMdUtyb3h4TEErQk9scDV2cXRqRlo0SWlDcUNmLzA1UzZFbFhaa1V1K1ZpDQpZaUkyQ1VValVEWkdVU2lrMUFBPQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ0K\",\"Filename\":\"test.bonjo.com.cer\",\"Format\":\"base64\"}")

	response, err := fakeRawClient(http.StatusOK, data).PostCertificateRetrieve(nil)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if !strings.EqualFold(response.Filename, "test.bonjo.com.cer") {
		t.Fatalf("Parse Certificate retrieve response did not include expected filename: test.bonjo.com.cer -- Actual: %s", response.Filename)
	}

	_, err = fakeRawClient(http.StatusBadRequest, data).PostCertificateRetrieve(nil)
	if err == nil {
		t.Fatalf("err is nil when expected to not be")
	}

	if !strings.Contains(err.Error(), "HTTP status code 400") {
		t.Fatalf("Parse Certificate error response did not include expected string: Bad Request -- Actual: %s", err)
	}

	data = []byte("bad data")
	_, err = fakeRawClient(http.StatusOK, data).PostCertificateRetrieve(nil)
	if err == nil {
		t.Fatalf("ParseRetrieveData with bad data did not return an error")
	}
}
