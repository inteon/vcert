/*
 * Copyright 2018 Venafi, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tpp

import (
	"crypto/x509"
	"testing"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/venafi/tpp/tpp_api/tpp_structs"
)

const (
	expectedURL = "https://localhost/"
)

func getBaseZoneConfiguration() *endpoint.ZoneConfiguration {
	z := endpoint.NewZoneConfiguration()
	z.Organization = "Venafi"
	z.OrganizationalUnit = []string{"Engineering", "Automated Tests"}
	z.Country = "US"
	z.Province = "Utah"
	z.Locality = "SLC"
	z.AllowedKeyConfigurations = []endpoint.AllowedKeyConfiguration{endpoint.AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{4096}}}
	z.HashAlgorithm = x509.SHA512WithRSA
	return z
}

func TestGetPolicyDN(t *testing.T) {
	const expectedPolicy = "\\VED\\Policy\\One\\Level 2\\This is level Three"

	actualPolicy := getPolicyDN("One\\Level 2\\This is level Three")
	if len(expectedPolicy) != len(actualPolicy) {
		t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
	}
	for i := 0; i < len(expectedPolicy); i++ {
		if expectedPolicy[i] != actualPolicy[i] {
			t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
		}
	}

	actualPolicy = getPolicyDN("\\One\\Level 2\\This is level Three")
	if len(expectedPolicy) != len(actualPolicy) {
		t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
	}
	for i := 0; i < len(expectedPolicy); i++ {
		if expectedPolicy[i] != actualPolicy[i] {
			t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
		}
	}

	actualPolicy = getPolicyDN(expectedPolicy)
	if len(expectedPolicy) != len(actualPolicy) {
		t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
	}
	for i := 0; i < len(expectedPolicy); i++ {
		if expectedPolicy[i] != actualPolicy[i] {
			t.Fatalf("getPolicyDN did not return the expected value of %s -- Actual value %s", expectedPolicy, actualPolicy)
		}
	}
}

func TestNewPEMCertificateCollectionFromResponse(t *testing.T) {
	var (
		tppResponse = "c3ViamVjdD1DTj1jZXJ0YWZpLWJvbmpvLnZlbmFmaS5jb20sIE9VPVF1YWxpdHkgQXNzdXJhbmNlLCBPVT1FbmdpbmVlcmluZywgTz0iVmVuYWZpLCBJbmMuIiwgTD1TTEMsIFM9VXRhaCwgQz1VUw0KaXNzdWVyPUNOPVZlblFBIENsYXNzIEcgQ0EsIERDPXZlbnFhLCBEQz12ZW5hZmksIERDPWNvbQ0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlHbWpDQ0JZS2dBd0lCQWdJS1ZPQkRWQUFCQUFCUXl6QU5CZ2txaGtpRzl3MEJBUVVGQURCZk1STXdFUVlLDQpDWkltaVpQeUxHUUJHUllEWTI5dE1SWXdGQVlLQ1pJbWlaUHlMR1FCR1JZR2RtVnVZV1pwTVJVd0V3WUtDWkltDQppWlB5TEdRQkdSWUZkbVZ1Y1dFeEdUQVhCZ05WQkFNVEVGWmxibEZCSUVOc1lYTnpJRWNnUTBFd0hoY05NVFl3DQpNakkyTWpFek56TXpXaGNOTVRZd016QXlNakV6TnpNeldqQ0JsakVMTUFrR0ExVUVCaE1DVlZNeERUQUxCZ05WDQpCQWdUQkZWMFlXZ3hEREFLQmdOVkJBY1RBMU5NUXpFVk1CTUdBMVVFQ2hNTVZtVnVZV1pwTENCSmJtTXVNUlF3DQpFZ1lEVlFRTEV3dEZibWRwYm1WbGNtbHVaekVhTUJnR0ExVUVDeE1SVVhWaGJHbDBlU0JCYzNOMWNtRnVZMlV4DQpJVEFmQmdOVkJBTVRHR05sY25SaFpta3RZbTl1YW04dWRtVnVZV1pwTG1OdmJUQ0NBU0l3RFFZSktvWklodmNODQpBUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBUEZnbVl1LzRBV0p3SHNtdTRFS3c5Z3Y2bXZweU9DdG5UbjAxNEp2DQpyanV3MStybVJpOXZIUGFoM3hmL255aUZpaFlvSEl5aEZ1RXIrVGZLSE5QQTRiTkE4ZkFvN2lBK012aFRpaU0zDQpDakZJenZYVTlZT3IydmU5MmRKMjM3TDF0Z3FUeGhiZXdOQ0hBdEFrWW00V2RVbUlFZlhMclplUk9oQ1QvQkJSDQpiUDYraTQzWTFxRkw3VnhxWjE0WjBudXhHdDYzdkg4TUx0VitHeWR5T05kdVk2eldOM3FpRmhjeWlValJDMjJyDQprTWlQaWEwQ0dlS0lOWDRNc2lWQ0JmRVdYYTZTVjViSE1ZeE5vUzNkdVRtTUdoQmdsdi9uVlVlR0pKL2tjWkNQDQo5VFREU25qc3BjZFI5SStFVUtYTTBObEs4Z084b1NGZ2lGdWlKdnlQeXFtZjNlTUNBd0VBQWFPQ0F4NHdnZ01hDQpNQjBHQTFVZERnUVdCQlF5UmR3MVZmWU5wMVNZV2ZoRlBqaEw0UjE0b2pBZkJnTlZIU01FR0RBV2dCVHpmaUpXDQp4SGsrNUZJN1JjaCtvcFZjb2xoYWVEQ0JzQVlEVlIwZkJJR29NSUdsTUlHaW9JR2ZvSUdjaGs5b2RIUndPaTh2DQpkbVZ1Y1dFdE1tczRMV2xqWVRFdWRtVnVjV0V1ZG1WdVlXWnBMbU52YlM5RFpYSjBSVzV5YjJ4c0wxWmxibEZCDQpKVEl3UTJ4aGMzTWxNakJISlRJd1EwRW9NU2t1WTNKc2hrbG1hV3hsT2k4dlZtVnVVVUV0TW1zNExVbERRVEV1DQpkbVZ1Y1dFdWRtVnVZV1pwTG1OdmJTOURaWEowUlc1eWIyeHNMMVpsYmxGQklFTnNZWE56SUVjZ1EwRW9NU2t1DQpZM0pzTUlJQmdnWUlLd1lCQlFVSEFRRUVnZ0YwTUlJQmNEQ0J2UVlJS3dZQkJRVUhNQUtHZ2JCc1pHRndPaTh2DQpMME5PUFZabGJsRkJKVEl3UTJ4aGMzTWxNakJISlRJd1EwRXNRMDQ5UVVsQkxFTk9QVkIxWW14cFl5VXlNRXRsDQplU1V5TUZObGNuWnBZMlZ6TEVOT1BWTmxjblpwWTJWekxFTk9QVU52Ym1acFozVnlZWFJwYjI0c1JFTTlkbVZ1DQpjV0VzUkVNOWRtVnVZV1pwTEVSRFBXTnZiVDlqUVVObGNuUnBabWxqWVhSbFAySmhjMlUvYjJKcVpXTjBRMnhoDQpjM005WTJWeWRHbG1hV05oZEdsdmJrRjFkR2h2Y21sMGVUQjFCZ2dyQmdFRkJRY3dBb1pwWm1sc1pUb3ZMMVpsDQpibEZCTFRKck9DMUpRMEV4TG5abGJuRmhMblpsYm1GbWFTNWpiMjB2UTJWeWRFVnVjbTlzYkM5V1pXNVJRUzB5DQphemd0U1VOQk1TNTJaVzV4WVM1MlpXNWhabWt1WTI5dFgxWmxibEZCSUVOc1lYTnpJRWNnUTBFb01Ta3VZM0owDQpNRGNHQ0NzR0FRVUZCekFCaGl0b2RIUndPaTh2ZG1WdWNXRXRNbXM0TFdsallURXVkbVZ1Y1dFdWRtVnVZV1pwDQpMbU52YlM5dlkzTndNQXNHQTFVZER3UUVBd0lGb0RBN0Jna3JCZ0VFQVlJM0ZRY0VMakFzQmlRckJnRUVBWUkzDQpGUWlCajRseWhJU3dhdldkRUllVy8zekVpUlZnZ3FUSFJvZjd2eXNDQVdRQ0FSY3dFd1lEVlIwbEJBd3dDZ1lJDQpLd1lCQlFVSEF3RXdHd1lKS3dZQkJBR0NOeFVLQkE0d0REQUtCZ2dyQmdFRkJRY0RBVEFqQmdOVkhSRUVIREFhDQpnaGhqWlhKMFlXWnBMV0p2Ym1wdkxuWmxibUZtYVM1amIyMHdEUVlKS29aSWh2Y05BUUVGQlFBRGdnRUJBRHNKDQpCaG1hTE5CbnZ0dWNHSHFJbXQ5dUhlSDBWUngwVHF5cEh2N21LTE10YTZubG1iTEMvVzdFV3hrenFlanFPall1DQp1eUIxSU1DOENyNUliTFo0elc3eW5QN1E0ZmNJMldPbFdWQVJTYkRzSVhXaml2SmV0dTBjL2xIMzBuaFNLQWk4DQpDV1JVZVBSckdsT3RZY1BrQnM1RlNxbzdMQjdoNmtXak9wRGR2bVpaK015OTdDSURNOTdTUjRjaGpQUFZxNkhDDQpCc3NoWTk3Y05rekxYbjBsTTRtZTBYZzNkMzM5SVBQam5qYm9FeWFoNjVqa2FpeGtVNVRIbUt5ei9JYlZjTjB2DQpjWWNBZVBFZ2FFdm9WdU1oNzgzS1R3K1ZrTERQQ0Z3Z3F5d0h3aEdxNVBkWmdXazZJbk9CTDQzciszNjNiVlFFDQpjSG92SFQ5Z0hIUUFmdGo5TVdjPQ0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ0KDQpzdWJqZWN0PUNOPVZlblFBIENsYXNzIEcgQ0EsIERDPXZlbnFhLCBEQz12ZW5hZmksIERDPWNvbQ0KaXNzdWVyPUNOPVZlblFBIENBLCBEQz12ZW5xYSwgREM9dmVuYWZpLCBEQz1jb20NCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQ0KTUlJR0d6Q0NCUU9nQXdJQkFnSUtLMGtqSFFBQUFDYUhXakFOQmdrcWhraUc5dzBCQVFVRkFEQlhNUk13RVFZSw0KQ1pJbWlaUHlMR1FCR1JZRFkyOXRNUll3RkFZS0NaSW1pWlB5TEdRQkdSWUdkbVZ1WVdacE1SVXdFd1lLQ1pJbQ0KaVpQeUxHUUJHUllGZG1WdWNXRXhFVEFQQmdOVkJBTVRDRlpsYmxGQklFTkJNQjRYRFRFME1ETXdPVEEzTXpJdw0KTjFvWERURTJNRE13T1RBM05ESXdOMW93WHpFVE1CRUdDZ21TSm9tVDhpeGtBUmtXQTJOdmJURVdNQlFHQ2dtUw0KSm9tVDhpeGtBUmtXQm5abGJtRm1hVEVWTUJNR0NnbVNKb21UOGl4a0FSa1dCWFpsYm5GaE1Sa3dGd1lEVlFRRA0KRXhCV1pXNVJRU0JEYkdGemN5QkhJRU5CTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQw0KQVFFQXJSTVBUcndYUmFENzFTenkwNzBKUUMxbHcrazlMZmhEN3RMcW43bHI4T2cyNDIrbHhGRVJGb2xRZFlXNg0KdjB1dmNuWnJKeEdqK2MzQkp2N0pMU2RMdW1ONCtOOXorQ09sSGoyaElFbVp1SC8vYTNpS0E1K1krNDZ3c1dxTQ0KTU5GeG9uTVVZRFJ0SC9jb2N4L1ltN3lFKzhEeXVUWGM0elozOGhnRml1c0RyQ0g5ZDR6S0VkUXJQaUxjNUVnSQ0Kb2V3YTBKRml1ZG03S3BoMnRoNzVvK0t3eVVYRW1mQVVqSW9HbENDN0YvMEdSRVBpajd0T2ZnWEtvZE5WWHozSw0KemZ1Y2cwcDh2ZjN3ZDVLNnhuekcxRm8vMG8zR2xIWm1NNVRmTER1cngvbWdtZGU4TGZ0QzZCSHRkQkMrcHdwMA0KcHZ5TVVKYWIwQnI2QWxaZVpHMDRJclZQQndJREFRQUJvNElDM3pDQ0F0c3dFZ1lKS3dZQkJBR0NOeFVCQkFVQw0KQXdFQUFUQWpCZ2tyQmdFRUFZSTNGUUlFRmdRVWpSL1VHc3lCeWlZYlVSZWIxSnpyOVRrNURtY3dIUVlEVlIwTw0KQkJZRUZQTitJbGJFZVQ3a1VqdEZ5SDZpbFZ5aVdGcDRNQmtHQ1NzR0FRUUJnamNVQWdRTUhnb0FVd0IxQUdJQQ0KUXdCQk1Bc0dBMVVkRHdRRUF3SUJoakFTQmdOVkhSTUJBZjhFQ0RBR0FRSC9BZ0VBTUI4R0ExVWRJd1FZTUJhQQ0KRkVaV2piZllza2JUM3lIb1JCSThVQk5CTERzQk1JSUJXd1lEVlIwZkJJSUJVakNDQVU0d2dnRktvSUlCUnFDQw0KQVVLR1AyaDBkSEE2THk4eWF6Z3RkbVZ1Y1dFdGNHUmpMblpsYm5GaExuWmxibUZtYVM1amIyMHZRMlZ5ZEVWdQ0KY205c2JDOVdaVzVSUVNVeU1FTkJMbU55YklhQnYyeGtZWEE2THk4dlEwNDlWbVZ1VVVFbE1qQkRRU3hEVGoweQ0KYXpndGRtVnVjV0V0Y0dSakxFTk9QVU5FVUN4RFRqMVFkV0pzYVdNbE1qQkxaWGtsTWpCVFpYSjJhV05sY3l4RA0KVGoxVFpYSjJhV05sY3l4RFRqMURiMjVtYVdkMWNtRjBhVzl1TEVSRFBYWmxibkZoTEVSRFBYWmxibUZtYVN4RQ0KUXoxamIyMC9ZMlZ5ZEdsbWFXTmhkR1ZTWlhadlkyRjBhVzl1VEdsemREOWlZWE5sUDI5aWFtVmpkRU5zWVhOeg0KUFdOU1RFUnBjM1J5YVdKMWRHbHZibEJ2YVc1MGhqMW1hV3hsT2k4dk1tczRMWFpsYm5GaExYQmtZeTUyWlc1eA0KWVM1MlpXNWhabWt1WTI5dEwwTmxjblJGYm5KdmJHd3ZWbVZ1VVVFZ1EwRXVZM0pzTUlIRUJnZ3JCZ0VGQlFjQg0KQVFTQnR6Q0J0RENCc1FZSUt3WUJCUVVITUFLR2dhUnNaR0Z3T2k4dkwwTk9QVlpsYmxGQkpUSXdRMEVzUTA0OQ0KUVVsQkxFTk9QVkIxWW14cFl5VXlNRXRsZVNVeU1GTmxjblpwWTJWekxFTk9QVk5sY25acFkyVnpMRU5PUFVOdg0KYm1acFozVnlZWFJwYjI0c1JFTTlkbVZ1Y1dFc1JFTTlkbVZ1WVdacExFUkRQV052YlQ5alFVTmxjblJwWm1sag0KWVhSbFAySmhjMlUvYjJKcVpXTjBRMnhoYzNNOVkyVnlkR2xtYVdOaGRHbHZia0YxZEdodmNtbDBlVEFOQmdrcQ0KaGtpRzl3MEJBUVVGQUFPQ0FRRUFUTkE4Q3d1bDFVQlFKSGQrNTBiOWc0am5YWDdLZitiVVVtRTlpSkdPcjJhQg0KRTcvTUFIR2RqZnR2ZEpZMFgrbDFoOFhTM09hcXVvOHRyZEdseGg5ZEJyUUVZUDJZbFhuSGdtWTJ4ckk5MmJ6ZA0KaWkzQjlaekxOS2JNTVBqb3d1alplQjNHbXl0ZE5adksrZ2hXWlJaOUEyd05nWUs0T1RWSmpsTURkOUw4NTU4VA0KeURuRXhlaW5JMjRYK3o4Q0YxYllSNWRYMU5KVGhjd0x3UlBRZDdFT1FxWXJmSlYvN2hza2xiQXlwTEFxZVBYdA0KUDlCK0RRNWJ3RmFqZ2VMNWVuOVVPZmtKdjM0WTZ4aVp3NXVaRnVKRDNRRnF3cGM1VTZTdGFGZmt0WXNLZFluSw0KMnlrdE5IQ2l1UmpGanpZMjdUMlNzMmtuRUliTGpPSlJaK0dSVnhQbTBRPT0NCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg0Kc3ViamVjdD1DTj1WZW5RQSBDQSwgREM9dmVucWEsIERDPXZlbmFmaSwgREM9Y29tDQppc3N1ZXI9Q049VmVuUUEgQ0EsIERDPXZlbnFhLCBEQz12ZW5hZmksIERDPWNvbQ0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlEbmpDQ0FvYWdBd0lCQWdJUVNUSEl5LzVKdEo1RDJJb3BHell1MnpBTkJna3Foa2lHOXcwQkFRVUZBREJYDQpNUk13RVFZS0NaSW1pWlB5TEdRQkdSWURZMjl0TVJZd0ZBWUtDWkltaVpQeUxHUUJHUllHZG1WdVlXWnBNUlV3DQpFd1lLQ1pJbWlaUHlMR1FCR1JZRmRtVnVjV0V4RVRBUEJnTlZCQU1UQ0ZabGJsRkJJRU5CTUI0WERURXlNVEV3DQpPVEl5TkRrd00xb1hEVEUzTVRFd09USXlOVGd6TWxvd1Z6RVRNQkVHQ2dtU0pvbVQ4aXhrQVJrV0EyTnZiVEVXDQpNQlFHQ2dtU0pvbVQ4aXhrQVJrV0JuWmxibUZtYVRFVk1CTUdDZ21TSm9tVDhpeGtBUmtXQlhabGJuRmhNUkV3DQpEd1lEVlFRREV3aFdaVzVSUVNCRFFUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCDQpBSmJyUlUwYUp3cGRpdGx3NGM4UGxMRWM0dmh0TXVUSVZDRTJlR21RM296U0J5by9yZ2ZibnlYalRJWFI5T3lmDQpmYkwvMXdNUTN3aWVaNitvUG1yZCs2NXJEK3lLWmMralpQU3p1WkNrbExnVG1uNVBoS3EzcUc2QS9nOUFrNnY4DQpVYmhoZjVvaGNkdjhneldvMjJoMEtYK1BMMFJCWlMrWm8rSGZDOGRWdUIzdWxUQkFjeG9PSmNWVzJCTTBBNUI2DQpWZkF6K0hhZjJXM2lxM3FPcTY4WGFSSmgxL3VsN2VjZXVmSC9XSElUTldYT0xuZXVkcldFbG00aVU4MkRiS1ZSDQp4VkNrY2tUT3RQM01ZNkY3aUcxTnhZYURDbXY0MTJhclpUd3FhR09hVnQ2YTBmdkY5Uy9mczRVK1M1QThxUmtODQo4QUY4dktGM3RXQXJGbk9maVorckhoc0NBd0VBQWFObU1HUXdFd1lKS3dZQkJBR0NOeFFDQkFZZUJBQkRBRUV3DQpDd1lEVlIwUEJBUURBZ0dHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRkVaV2piZllza2JUDQozeUhvUkJJOFVCTkJMRHNCTUJBR0NTc0dBUVFCZ2pjVkFRUURBZ0VBTUEwR0NTcUdTSWIzRFFFQkJRVUFBNElCDQpBUUFWdXkyemR1Qkc2WFhVVHg1Z25aUWxBYStmdVB2LzdHMzMyWE9VcWN0NkQ1UmRVTjlVZDlRM2MxR2NVcmR4DQp0NzFvbS9xV3cxSmhnbnZIWTJJbG9wcTFFdHdZY3JwZitWcThGR0swZVpLa1Q3MEFLRWdTTTYrODZhczdzcVFzDQozbklvSkZCWU9CTG0xRHo0em1zNTFWZ2k3NXFDbDRzVzBUa3NJUHFGNlpGUnNIVHlmYU5wKzZ0RG5jaXZoZkowDQovNzJvdHVyZzdUMlgyVm9qMkY3NG1PMyt1bHpkWEgwNnhiZDFORlJvemFZZ0VCMjFVNVMwc2hTcmRPR0hCMVI4DQp0Z0tidU1XUGplVnZqR3k0NU5LNVhUSURRTHpyOWZiTE0zKzdPRGZiajBxdHZ2dnBxclV3bGhLbjMwNTJSZ05MDQoycERqY1NyazBZTVU1L1ZYNElXcjd2cloNCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCg0K"
	)

	col, err := newPEMCollectionFromResponse(tppResponse, certificate.ChainOptionRootLast)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	if len(col.Chain) != 2 {
		t.Fatalf("PEM Chain did not contain the expected number of elements 2, actual count %d", len(col.Chain))
	}
}

func TestGenerateRequest(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
}

func TestGenerateRequestWithLockedMgmtType(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	zoneConfig.CustomAttributeValues[string(tpp_structs.TppManagementType)] = "Monitoring"
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err == nil {
		t.Fatalf("Error expected, request should not be generated with mgmt type set to Monitoring")
	}
}

func TestGenerateRequestWithNoUserProvidedCSRAllowed(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	zoneConfig.CustomAttributeValues[string(tpp_structs.TppManualCSR)] = "0"
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err == nil {
		t.Fatalf("Error expected, request should not be generated with Manual CSR set to 0")
	}
}

func TestGenerateRequestWithLockedKeyConfiguration(t *testing.T) {
	tpp := Connector{}
	zoneConfig := getBaseZoneConfiguration()
	zoneConfig.AllowedKeyConfigurations = []endpoint.AllowedKeyConfiguration{{KeyType: certificate.KeyTypeECDSA, KeyCurves: []certificate.EllipticCurve{certificate.EllipticCurveP384}}}
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	req.KeyType = certificate.KeyTypeRSA
	zoneConfig.UpdateCertificateRequest(&req)
	err := tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatalf("Error expected, request should be update with key type goten from zone")
	}
}

func TestGetHttpClient(t *testing.T) {
	tpp := Connector{}
	if tpp.getHTTPClient() == nil {
		t.Fatalf("Failed to get http client")
	}
}

func TestConvertServerPolicyToInternalPolicy(t *testing.T) {
	sp := tpp_structs.PolicyResponse{
		KeyPair: tpp_structs.KeyPairResponse{
			KeyAlgorithm: tpp_structs.LockedAttribute{
				Locked: true,
				Value:  "rsa",
			},
			KeySize: tpp_structs.LockedIntAttribute{
				Locked: true,
				Value:  2048,
			},
			EllipticCurve: tpp_structs.LockedAttribute{
				Locked: false,
				Value:  "",
			},
		},
	}

	p := serverPolicyToPolicy(sp)
	if len(p.AllowedKeyConfigurations) != 1 {
		t.Fatal("invalid configurations values")
	}
	k := p.AllowedKeyConfigurations[0]
	if k.KeyType != certificate.KeyTypeRSA {
		t.Fatal("invalid key type")
	}
	if len(k.KeySizes) != 3 || k.KeySizes[0] != 2048 || k.KeySizes[1] != 4096 || k.KeySizes[2] != 8192 {
		t.Fatal("bad key lengths")
	}

	sp = tpp_structs.PolicyResponse{
		KeyPair: tpp_structs.KeyPairResponse{
			KeyAlgorithm: tpp_structs.LockedAttribute{
				Locked: true,
				Value:  "ec",
			},
			KeySize: tpp_structs.LockedIntAttribute{
				Locked: true,
				Value:  2048,
			},
			EllipticCurve: tpp_structs.LockedAttribute{
				Locked: true,
				Value:  "p521",
			},
		},
	}
	p = serverPolicyToPolicy(sp)
	if len(p.AllowedKeyConfigurations) != 1 {
		t.Fatal("invalid configurations values")
	}
	k = p.AllowedKeyConfigurations[0]
	if k.KeyType != certificate.KeyTypeECDSA {
		t.Fatal("invalid key type")
	}
	if len(k.KeyCurves) != 1 || k.KeyCurves[0] != certificate.EllipticCurveP521 {
		t.Fatal("bad key curve")
	}

	sp = tpp_structs.PolicyResponse{
		KeyPair: tpp_structs.KeyPairResponse{
			KeyAlgorithm: tpp_structs.LockedAttribute{
				Locked: false,
				Value:  "ec",
			},
			KeySize: tpp_structs.LockedIntAttribute{
				Locked: true,
				Value:  2048,
			},
			EllipticCurve: tpp_structs.LockedAttribute{
				Locked: true,
				Value:  "p384",
			},
		},
	}
	p = serverPolicyToPolicy(sp)
	if len(p.AllowedKeyConfigurations) != 2 {
		t.Fatal("invalid configurations values")
	}
	k = p.AllowedKeyConfigurations[0]
	if k.KeyType != certificate.KeyTypeRSA {
		t.Fatal("invalid key type")
	}
	if len(k.KeySizes) != 3 || k.KeySizes[0] != 2048 || k.KeySizes[1] != 4096 || k.KeySizes[2] != 8192 {
		t.Fatal("bad key lengths")
	}
	k = p.AllowedKeyConfigurations[1]
	if k.KeyType != certificate.KeyTypeECDSA {
		t.Fatal("invalid key type")
	}
	if len(k.KeyCurves) != 1 || k.KeyCurves[0] != certificate.EllipticCurveP384 {
		t.Fatal("bad key curve")
	}

}
