package tpp_api

import "fmt"

type urlResource string

const (
	urlVedSdk urlResource = "vedsdk"

	urlAuthorize                   urlResource = "vedsdk/authorize"
	urlAuthorizeIsAuthServer       urlResource = "vedauth/authorize/isauthserver"
	urlAuthorizeCertificate        urlResource = "vedauth/authorize/certificate"
	urlAuthorizeOAuth              urlResource = "vedauth/authorize/oauth"
	urlAuthorizeVerify             urlResource = "vedauth/authorize/verify"
	urlAuthorizeRefreshAccessToken urlResource = "vedauth/authorize/token"
	urlRevokeAccessToken           urlResource = "vedauth/revoke/token"

	urlCertificate            urlResource = "vedsdk/certificates"
	urlCertificateById        urlResource = "vedsdk/certificates/%s"
	urlCertificateImport      urlResource = "vedsdk/certificates/import"
	urlCertificateCheckPolicy urlResource = "vedsdk/certificates/checkpolicy"
	urlCertificateRenew       urlResource = "vedsdk/certificates/renew"
	urlCertificateRequest     urlResource = "vedsdk/certificates/request"
	urlCertificateRetrieve    urlResource = "vedsdk/certificates/retrieve"
	urlCertificateRevoke      urlResource = "vedsdk/certificates/revoke"
	urlCertificateAssociate   urlResource = "vedsdk/certificates/associate"
	urlCertificateDissociate  urlResource = "vedsdk/certificates/dissociate"

	urlMetadataSet    urlResource = "vedsdk/metadata/set"
	urlMetadataGet    urlResource = "vedsdk/metadata/get"
	urlMetadataGetAll urlResource = "vedsdk/metadata/getitems"

	urlSystemStatusVersion urlResource = "vedsdk/systemstatus/version"

	urlConfigCreatePolicy       urlResource = "vedsdk/config/create"
	urlConfigWritePolicy        urlResource = "vedsdk/config/writepolicy"
	urlConfigReadPolicy         urlResource = "vedsdk/config/readpolicy"
	urlConfigIsValidPolicy      urlResource = "vedsdk/config/isvalid"
	urlConfigDnToGuid           urlResource = "vedsdk/config/dntoguid"
	urlConfigReadDn             urlResource = "vedsdk/config/readdn"
	urlConfigFindPolicy         urlResource = "vedsdk/config/findpolicy"
	urlConfigCleanPolicy        urlResource = "vedsdk/config/clearpolicyattribute"
	urlConfigFindObjectsOfClass urlResource = "vedsdk/config/findobjectsofclass"

	urlIdentityBrowse   urlResource = "vedsdk/identity/browse"
	urlIdentityValidate urlResource = "vedsdk/identity/validate"
	urlIdentitySelf     urlResource = "vedsdk/identity/self"

	urlSshCertificateRequest    urlResource = "vedsdk/sshcertificates/request"
	urlSshCertificateRetrieve   urlResource = "vedsdk/sshcertificates/retrieve"
	urlSshTemplateAvaliable     urlResource = "vedsdk/sshcertificates/template/available"
	urlSshTemplateRetrieve      urlResource = "vedsdk/sshcertificates/template/retrieve"
	urlSshTemplatePublicKeyData urlResource = "vedsdk/sshcertificates/template/retrieve/publickeydata"
)

func (ur urlResource) Absolute(baseUrl string) urlResource {
	return urlResource(baseUrl + string(ur))
}

func (ur urlResource) Params(params ...interface{}) urlResource {
	return urlResource(fmt.Sprintf(string(ur), params...))
}
