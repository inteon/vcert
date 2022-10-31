package certificate

type SshCaTemplateRequest struct {
	Template string
	Guid     string
}

type AccessControl struct {
	DefaultPrincipals []string
}

type SshConfig struct {
	CaPublicKey string
	Principals  []string
}
