package main

// a command line tool that generates the issuer's keys 

import (
	// "crypto/x509"
	// "encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"log"
	psidentity "psidentity"
	rpsidentity "psidentity/psidentity"
	"psidentity/translator/amcl"
	user "psidentity/user"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	FP256BN_AMCL        = "FP256BN_AMCL"
	BN254               = "BN254"
	FP256BN_AMCL_MIRACL = "FP256BN_AMCL_MIRACL"
	BLS12_377_GURVY     = "BLS12_377_GURVY"
	BLS12_381_GURVY     = "BLS12_381_GURVY"
	BLS12_381           = "BLS12_381"
)

// command line flags
var (
	app = kingpin.New("IssuerKryGen", "Utility for generating key material to be used")

	outputDir = app.Flag("output", "The output directory in which to place artifacts").Default("config").String()
	curveID   = app.Flag("curve", "The curve to use to generate the crypto material").Short('c').Default(FP256BN_AMCL).Enum(FP256BN_AMCL, BN254, FP256BN_AMCL_MIRACL, BLS12_377_GURVY, BLS12_381_GURVY, BLS12_381)

	genIssuerKey    = app.Command("issuer-keygen", "Generate issuer key material")
	genPrimaryCred    = app.Command("primary-cred", "Generate primary cred")
	genDeriveCred    = app.Command("derive-cred", "Generate derive cred")
	genAggregateCred    = app.Command("aggregate-cred", "Generate aggregate cred")

	// genUserConfig   = app.Command("userconfig", "Generate a default user certificate")
	// deriveAggregate = app.Command("derive-aggregate", "User certification derive and aggregate")
	// genCAInput              = genSignerConfig.Flag("ca-input", "The folder where CA's secrets are stored").String()
	// genCredOU               = genSignerConfig.Flag("org-unit", "The Organizational Unit of the default signer").Short('u').String()
	// genCredIsAdmin          = genSignerConfig.Flag("admin", "Make the default signer admin").Short('a').Bool()
	// genCredEnrollmentId     = genSignerConfig.Flag("enrollmentId", "The enrollment id of the default signer").Short('e').String()
	// genCredRevocationHandle = genSignerConfig.Flag("revocationHandle", "The handle used to revoke this signer").Short('r').String()

	// version = app.Command("version", "Show version information")
)

type Translator interface {
	G1ToProto(*math.G1) *amcl.ECP
	G1FromProto(*amcl.ECP) (*math.G1, error)
	G1FromRawBytes([]byte) (*math.G1, error)
	G2ToProto(*math.G2) *amcl.ECP2
	G2FromProto(*amcl.ECP2) (*math.G2, error)
}

func main() {
	app.HelpFlag.Short('h')

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var curve *math.Curve
	var tr Translator
	switch *curveID {
	case FP256BN_AMCL:
		curve = math.Curves[math.FP256BN_AMCL]
		tr = &amcl.Fp256bn{C: curve}
	// case BN254:
	// 	curve = math.Curves[math.BN254]
	// 	tr = &amcl.Gurvy{C: curve}
	// case FP256BN_AMCL_MIRACL:
	// 	curve = math.Curves[math.FP256BN_AMCL_MIRACL]
	// 	tr = &amcl.Fp256bnMiracl{C: curve}
	// case BLS12_377_GURVY:
	// 	curve = math.Curves[math.BLS12_377_GURVY]
	// 	tr = &amcl.Gurvy{C: curve}
	// case BLS12_381_GURVY:
	// 	curve = math.Curves[math.BLS12_381_GURVY]
	// 	tr = &amcl.Gurvy{C: curve}
	// case BLS12_381:
	// 	curve = math.Curves[math.BLS12_381]
	// 	tr = &amcl.Gurvy{C: curve}
	default:
		handleError(fmt.Errorf("invalid curve [%s]", *curveID))
	}

	psid := rpsidentity.Psidentity{
		Curve: curve,
	}

	switch command {

	case genIssuerKey.FullCommand():
		//isk, ipk, err := rpsidentity.GenerateIssuerKey(psid, tr)		//commit for idemix issuer
		isk, ipk, err := rpsidentity.GenerateIssuerKeyPS(psid, tr)
		handleError(err)
		usk, upk, err := rpsidentity.GenerateUserKeyPS(psid, tr)
		handleError(err)

		revocationKey, err := rpsidentity.GenerateRevocationKeyPS(psid)
		// fmt.Printf("the type of revocationKey:%T",revocationKey)
		handleError(err)
		// encodedRevocationSK, err := x509.MarshalECPrivateKey(revocationKey)
		// handleError(err)
		// pemEncodedRevocationSK := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedRevocationSK})
		// handleError(err)
		//encodedRevocationPK, err := x509.MarshalPKIXPublicKey(revocationKey.Public())
		//handleError(err)
		//pemEncodedRevocationPK := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedRevocationPK})

		//Prevent overwriting the existing key
		// path := filepath.Join(*outputDir, psidentity.PsIdentityDirIssuer)
		// checkDirectoryNotExists(path, fmt.Sprintf("Directory %s already exists", path))
		// path2 := filepath.Join(*outputDir, psidentity.PsIdentityConfigDirUser)
		// checkDirectoryNotExists(path2, fmt.Sprintf("Directory %s already exists", path2))

		// write private and public keys to the file
		handleError(os.MkdirAll(filepath.Join(*outputDir, psidentity.PsIdentityDirIssuerKey), 0770))
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirIssuerKey, psidentity.PsIdentityConfigIssuerSecretKey), isk)
		// writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirIssuer, psidentity.PsIdentityConfigRevocationKey), pemEncodedRevocationSK)
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirIssuerKey, psidentity.PsIdentityConfigIssuerPublicKey), ipk)
		// writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirIssuer, psidentity.PsIdentityConfigRevocationKey), revocationKey)
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirIssuerKey, psidentity.PsIdentityConfigRevocationKey), revocationKey)



		handleError(os.MkdirAll(filepath.Join(*outputDir, psidentity.PsIdentityDirUserKey), 0770))
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirUserKey, psidentity.PsIdentityConfigUserSecretKey), usk)
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirUserKey, psidentity.PsIdentityConfigUserPublicKey), upk)


	case genPrimaryCred.FullCommand():
		log.Printf("PrimaryCred\n")
		UserAttributeNames := []string{psidentity.UserAttributeNumber, psidentity.UserAttributeManufacturer, psidentity.UserAttributeDate, psidentity.UserAttributeLevel}
		log.Printf("UserAttributeNames is %v\n", UserAttributeNames)

		key, _ := readIssuerKey()
		// revKey := readRevocationKey()

		primaryconfig, err := rpsidentity.GenerateUserPrimaryCred(UserAttributeNames, key, psid, tr)
		handleError(err)

		// path := filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigPrimaryCred)
		// checkDirectoryNotExists(path, fmt.Sprintf("This user config already contains a directory \"%s\"", path))

		// Write config to file
		handleError(os.MkdirAll(filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred), 0770))
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigPrimaryCred), primaryconfig)
		// log.Printf("write primary cred successful")

	case genDeriveCred.FullCommand():
		log.Printf("DeriveCred\n")
		UserAttributeNames := []string{psidentity.UserAttributeNumber, psidentity.UserAttributeManufacturer, psidentity.UserAttributeDate, psidentity.UserAttributeLevel}
		log.Printf("UserAttributeNames is %v\n", UserAttributeNames)

		key, _ := readIssuerKey()
		ukey := readUserKey()
		primaryCred := readUserPrimaryCred()
		log.Printf("The value of primaryCred:%v", primaryCred)

		deriveconfig, aggregateconfig, err := rpsidentity.GenerateUserDeriveCred(UserAttributeNames, primaryCred, key, ukey, psid, tr)
		handleError(err)

		// path := filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigDeriveCred)
		// checkDirectoryNotExists(path, fmt.Sprintf("This user config already contains a directory \"%s\"", path))

		// // Write config to file
		handleError(os.MkdirAll(filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred), 0770))
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigDeriveCred), deriveconfig)
		log.Printf("write derive cred successful")
		writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigAggregateCred), aggregateconfig)
		log.Printf("write aggregate cred successful")

	
	case genAggregateCred.FullCommand():
		log.Printf("AggregateCred\n")
		// UserAttributeNames := []string{psidentity.UserAttributeNumber, psidentity.UserAttributeManufacturer, psidentity.UserAttributeDate, psidentity.UserAttributeLevel}
		// log.Printf("UserAttributeNames is %v\n", UserAttributeNames)

		// key, _ := readIssuerKey()
		// ukey := readUserKey()
		// deriveCred := readUserDeriveCred()
		// log.Printf("The value of deriveCred:%v", deriveCred)
		// log.Printf("The type of deriveCred:%T", deriveCred)
		


		// CredDerive := make([]*rpsidentity.DeriveCredential, 1)
		// CredDerive[0] = *deriveCred
		// CredDerive = append(CredDerive, *deriveCred)

		// aggregateconfig, err := rpsidentity.GenerateUserAggregateCred(ukey, key, CredDerive, psid, tr)
		// handleError(err)

		// // // path := filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigDeriveCred)
		// // // checkDirectoryNotExists(path, fmt.Sprintf("This user config already contains a directory \"%s\"", path))

		// // Write config to file
		// handleError(os.MkdirAll(filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred), 0770))
		// writeFile(filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigAggregateCred), aggregateconfig)
		// log.Printf("write aggregate cred successful")

	}
}



// writeFile writes bytes to a file and panics in case of an error
func writeFile(path string, contents []byte) {
	handleError(ioutil.WriteFile(path, contents, 0640))
}

// readIssuerKey reads the issuer key from the current directory
func readIssuerKey() (rpsidentity.IssuerKeyPS, []byte) {
	path := filepath.Join(*outputDir, psidentity.PsIdentityDirIssuerKey, psidentity.PsIdentityConfigIssuerSecretKey)
	//isk, err := ioutil.ReadFile(path)
	iskBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open issuer secret key file: %s", path))
	}
	path = filepath.Join(*outputDir, psidentity.PsIdentityDirIssuerKey, psidentity.PsIdentityConfigIssuerPublicKey)
	ipkBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open issuer public key file: %s", path))
	}

	//ipk := &rpsidentity.IssuerPublicKey{}
	ipk := &rpsidentity.IssuerPublicKeyPS{}
	handleError(proto.Unmarshal(ipkBytes, ipk))
	//log.Printf("User key Ipk is %v",ipk)
	isk := &rpsidentity.IssuerPrivateKeyPS{}
	handleError(proto.Unmarshal(iskBytes, isk))
	//log.Printf("User key Isk is %v",isk)
	log.Printf("Restore issuer Isk and Ipk successful.")

	//key := rpsidentity.IssuerKey{Isk: isk, Ipk: ipk}
	key := rpsidentity.IssuerKeyPS{Isk: isk, Ipk: ipk}

	return key, ipkBytes
}

func readUserKey() rpsidentity.UserKey {
	path := filepath.Join(*outputDir, psidentity.PsIdentityDirUserKey, psidentity.PsIdentityConfigUserSecretKey)
	uskBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open user secret key file: %s", path))
	}
	path = filepath.Join(*outputDir, psidentity.PsIdentityDirUserKey, psidentity.PsIdentityConfigUserPublicKey)
	upkBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open user public key file: %s", path))
	}

	upk := &rpsidentity.UserPublicKey{}
	handleError(proto.Unmarshal(upkBytes, upk))
	usk := &rpsidentity.UserPrivateKey{}
	handleError(proto.Unmarshal(uskBytes, usk))
	log.Printf("Restore user Isk and Ipk successful.")

	key := rpsidentity.UserKey{Usk: usk, Upk: upk}

	return key

}

// func readUserCred() rpsidentity.PrimaryCredential {
// 	path := filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigPrimaryCred)
// 	confBytes, err := ioutil.ReadFile(path)
// 	if err != nil {
// 		handleError(errors.Wrapf(err, "failed to open user cred file: %s", path))
// 	}

// 	conf := &user.UserMessageConfig{}
// 	handleError(proto.Unmarshal(confBytes, conf))
// 	cred := &rpsidentity.PrimaryCredential{}
// 	handleError(proto.Unmarshal(conf.Cred, cred))

// 	return *cred
// }



func readUserPrimaryCred() rpsidentity.PrimaryCredential {
	path := filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigPrimaryCred)
	confBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open user cred file: %s", path))
	}

	conf := &user.UserPrimaryCred{}
	handleError(proto.Unmarshal(confBytes, conf))
	cred := &rpsidentity.PrimaryCredential{}
	handleError(proto.Unmarshal(conf.PrimaryCred, cred))

	return *cred

	// path := filepath.Join(*outputDir, psidentity.PsIdentityCredDirUser, psidentity.PsIdentityConfigFileSigner)
	// confBytes, err := ioutil.ReadFile(path)
	// if err != nil {
	// 	handleError(errors.Wrapf(err, "failed to open user cred file: %s", path))
	// }
	// cred := &rpsidentity.PrimaryCredential{}
	// handleError(proto.Unmarshal(confBytes, cred))

	// return *cred
}



func readUserDeriveCred() rpsidentity.DeriveCredential {
	path := filepath.Join(*outputDir, psidentity.PsIdentityDirUserCred, psidentity.PsIdentityConfigDeriveCred)
	confBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open user cred file: %s", path))
	}

	conf := &user.UserDeriveCred{}
	handleError(proto.Unmarshal(confBytes, conf))
	cred := &rpsidentity.DeriveCredential{}
	handleError(proto.Unmarshal(conf.DeriveCred, cred))

	return *cred

	// path := filepath.Join(*outputDir, psidentity.PsIdentityCredDirUser, psidentity.PsIdentityConfigFileSigner)
	// confBytes, err := ioutil.ReadFile(path)
	// if err != nil {
	// 	handleError(errors.Wrapf(err, "failed to open user cred file: %s", path))
	// }
	// cred := &rpsidentity.PrimaryCredential{}
	// handleError(proto.Unmarshal(confBytes, cred))

	// return *cred
}





func readRevocationKey() rpsidentity.RsaKey {
	path := filepath.Join(*outputDir, psidentity.PsIdentityDirIssuerKey, psidentity.PsIdentityConfigRevocationKey)
	keyBytes, err := ioutil.ReadFile(path)
	if err != nil {
		handleError(errors.Wrapf(err, "failed to open revocation secret key file: %s", path))
	}

	rk := &rpsidentity.RsaKey{}
	handleError(proto.Unmarshal(keyBytes, rk))

	log.Printf("Restore revocation key successful.")


	return *rk
}


























//func readRevocationKey() *ecdsa.PrivateKey {
//	path := filepath.Join(*outputDir, psidentity.PsIdentityDirIssuer, psidentity.PsIdentityConfigRevocationKey)
//	keyBytes, err := ioutil.ReadFile(path)
//	if err != nil {
//		handleError(errors.Wrapf(err, "failed to open revocation secret key file: %s", path))
//	}
//
//	block, _ := pem.Decode(keyBytes)
//	if block == nil {
//		handleError(errors.Errorf("failed to decode ECDSA private key"))
//	}
//	key, err := x509.ParseECPrivateKey(block.Bytes)
//	handleError(err)
//
//	return key
//}

// func readRevocationPublicKey() []byte {
// 	path := filepath.Join(*genCAInput, imsp.IdemixConfigDirMsp, imsp.IdemixConfigFileRevocationPublicKey)
// 	keyBytes, err := ioutil.ReadFile(path)
// 	if err != nil {
// 		handleError(errors.Wrapf(err, "failed to open revocation secret key file: %s", path))
// 	}

// 	return keyBytes
// }

// checkDirectoryNotExists checks whether a directory with the given path already exists and exits if this is the case
func checkDirectoryNotExists(path string, errorMessage string) {
	_, err := os.Stat(path)
	if err == nil {
		handleError(errors.New(errorMessage))
	}
}

func handleError(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
