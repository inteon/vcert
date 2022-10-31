package policy

import "github.com/Venafi/vcert/v4/pkg/util"

const (
	JsonExtension        = ".json"
	YamlExtension        = ".yaml"
	RootPath             = util.PathSeparator + "VED" + util.PathSeparator + "Policy"
	PolicyClass          = "Policy"
	PolicyAttributeClass = "X509 Certificate"

	AllowAll     = ".*"
	UserProvided = "UserProvided"
	DefaultCA    = "BUILTIN\\Built-In CA\\Default Product"

	IdentityUser              = 1
	IdentitySecurityGroup     = 2
	IdentityDistributionGroup = 8
	AllIdentities             = IdentityUser + IdentitySecurityGroup + IdentityDistributionGroup
)
