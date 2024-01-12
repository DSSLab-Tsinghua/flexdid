package psidentity

const (
	// AttributeIndexOU contains the index of the OU attribute in the idemix credential attributes
	AttributeIndexOU = iota

	// AttributeIndexRole contains the index of the Role attribute in the idemix credential attributes
	AttributeIndexRole

	// AttributeIndexEnrollmentId contains the index of the Enrollment ID attribute in the idemix credential attributes
	AttributeIndexEnrollmentId

	// AttributeIndexRevocationHandle contains the index of the Revocation Handle attribute in the idemix credential attributes
	AttributeIndexRevocationHandle
)

const (
	// AttributeNameOU is the attribute name of the Organization Unit attribute
	IssuerAttributeOne = "One"

	// AttributeNameRole is the attribute name of the Role attribute
	IssuerAttributeTwo = "Two"

	// AttributeNameEnrollmentId is the attribute name of the Enrollment ID attribute
	IssuerAttributeThree = "Three"

	// AttributeNameRevocationHandle is the attribute name of the revocation handle attribute
	//AttributeNameRevocationHandle = "RevocationHandle"
	IssuerAttributeFour = "Four"
)

const (
	// AttributeNameOU is the attribute name of the Organization Unit attribute
	UserAttributeNumber = "000000"

	// AttributeNameRole is the attribute name of the Role attribute
	UserAttributeManufacturer = "companyA"

	// AttributeNameEnrollmentId is the attribute name of the Enrollment ID attribute
	UserAttributeDate = "2022-12-12"

	// AttributeNameRevocationHandle is the attribute name of the revocation handle attribute
	//AttributeNameRevocationHandle = "RevocationHandle"
	UserAttributeLevel = "LevelOne"
)


const (
	// AttributeNameOU is the attribute name of the Organization Unit attribute
	AttributeNameOU = "OU"

	// AttributeNameRole is the attribute name of the Role attribute
	AttributeNameRole = "Role"

	// AttributeNameEnrollmentId is the attribute name of the Enrollment ID attribute
	AttributeNameEnrollmentId = "EnrollmentID"

	// AttributeNameRevocationHandle is the attribute name of the revocation handle attribute
	//AttributeNameRevocationHandle = "RevocationHandle"
	AttributeNameRevocationHandle = "RevocationHandleRevocationRevocatiHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandleRevocationHandle"
)

const (

	PsIdentityDirIssuerKey                  = "issuer-key"
	PsIdentityConfigIssuerPublicKey         = "IssuerPublicKey"
	PsIdentityConfigIssuerSecretKey			= "IssuerSecretKey"
	PsIdentityConfigRevocationKey   		= "RevocationKey"

	PsIdentityDirUserKey                    = "user-key"
	PsIdentityConfigUserSecretKey			= "UserSecretKey"
	PsIdentityConfigUserPublicKey		    = "UserPublicKey"

	PsIdentityDirUserCred                 	= "user-cred"
	PsIdentityConfigPrimaryCred             = "PrimaryCred"
	PsIdentityConfigDeriveCred			    = "DeriveCred"
	PsIdentityConfigAggregateCred			= "AggregateCred"


	// PsIdentityConfigDirUser                 = "user-config"
	// PsIdentityCredDirUser                 	= "user-cred"
	// PsIdentityConfigFileSigner              = "CredOrigin"
	// PsIdentityConfigUserSecretKey			= "UserSecretKey"
	// PsIdentityConfigFileUserPublicKey		= "UserPublicKey"

	// PsIdentityDirIssuer             		= "issuer-config"
	// PsIdentityConfigFileIssuerPublicKey     = "IssuerPublicKey"
	// PsIdentityConfigIssuerSecretKey			= "IssuerSecretKey"
	// PsIdentityConfigFileRevocationPublicKey = "RevocationPublicKey"
	// PsIdentityConfigRevocationKey   		= "RevocationKey"
)

type RevocationAlgorithm int32

const (
	ALG_NO_REVOCATION RevocationAlgorithm = iota
)
