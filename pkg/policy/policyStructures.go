package policy

type CADetails struct {
	CertificateAuthorityProductOptionId *string
	CertificateAuthorityOrganizationId  *int64
}

type CertificateAuthorityInfo struct {
	CAType            string
	CAAccountKey      string
	VendorProductName string
}
