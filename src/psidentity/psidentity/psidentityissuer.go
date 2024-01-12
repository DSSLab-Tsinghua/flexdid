/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package psidentity

import (
	// "crypto/ecdsa"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	psidentity "psidentity"
	// math "github.com/IBM/mathlib"
	user "psidentity/user"
	// "math/big"
	"log"
	// "time"
)

// GenerateIssuerKey generates an issuer signing key pair.
// Currently four attributes are supported by the issuer:
// AttributeNameOU is the organization unit name
// AttributeNameRole is the role (member or admin) name
// AttributeNameEnrollmentId is the enrollment id
// AttributeNameRevocationHandle contains the revocation handle, which can be used to revoke this user
// Generated keys are serialized to bytes.
func GenerateIssuerKey(psid Psidentity, tr Translator) ([]byte, []byte, error) {
	rng, err := psid.Curve.Rand()
	if err != nil {
		return nil, nil, err
	}
	AttributeNames := []string{psidentity.AttributeNameOU, psidentity.AttributeNameRole, psidentity.AttributeNameEnrollmentId, psidentity.AttributeNameRevocationHandle}
	// log.Printf("AttributeNames is %v", AttributeNames)

	key, err := psid.NewIssuerKey(AttributeNames, rng, tr)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "cannot generate Issuer key")
	}
	log.Printf("Generate Issuer key success!")

	log.Printf("User key Ipk is %v", key.Ipk)
	ipkSerialized, err := proto.Marshal(key.Ipk)

	return key.Isk, ipkSerialized, err
}

func GenerateIssuerKeyPS(psid Psidentity, tr Translator) ([]byte, []byte, error) {
	rng, err := psid.Curve.Rand()
	if err != nil {
		return nil, nil, err
	}
	// AttributeNames := []string{psidentity.AttributeNameOU, psidentity.AttributeNameRole, psidentity.AttributeNameEnrollmentId, psidentity.AttributeNameRevocationHandle}
	IssuerAttributeNames := []string{psidentity.IssuerAttributeOne, psidentity.IssuerAttributeTwo, psidentity.IssuerAttributeThree, psidentity.IssuerAttributeFour}
	log.Printf("IssuerAttributeNames is %v", IssuerAttributeNames)

	key, err := psid.NewIssuerKeyPS(len(IssuerAttributeNames), rng, tr)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "cannot generate Issuer key")
	}
	log.Printf("Generate Issuer key success!")

	//log.Printf("Issuer key Ipk is %v\n",key.Ipk)
	//log.Printf("Issuer key Isk is %v\n",key.Isk)
	ipkSerialized, err := proto.Marshal(key.Ipk)
	iskSerialized, err := proto.Marshal(key.Isk)

	return iskSerialized, ipkSerialized, err
}



func GenerateUserPrimaryCred(UserAttributeNames []string, key IssuerKeyPS, psid Psidentity, tr Translator) ([]byte, error) {
	// UserAttributeNames := []string{psidentity.UserAttributeNumber, psidentity.UserAttributeManufacturer, psidentity.UserAttributeDate, psidentity.UserAttributeLevel}


	rng, err := psid.Curve.Rand()
	if err != nil {
		return nil, errors.WithMessage(err, "Error getting PRNG")
	}


	// t1 := time.Now().UnixNano() / int64(time.Millisecond)

	temp := 0
	for i := 0; i < len(UserAttributeNames); i++ {
		temp = temp + len([]byte(UserAttributeNames[i]))
	}
	log.Printf("Len of AttributeNames is %v\n", temp)


	msg, d, err := psid.NewCredRequestPS(UserAttributeNames, key.Ipk, rng, tr) //generate commitment (pre-blind-sign), for user
	if err != nil {
		return nil, errors.WithMessage(err, "failed to generate a credential commitment")
	}

	err = msg.VerifyZeroKnowledgeOne(key.Ipk, psid.Curve, tr)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to Zero knowledge one verification")
	}
	log.Printf("Zero knowledge one verification successful.")

	msgBytes, err := proto.Marshal(msg)
	log.Printf("pre-blind-sign successful. Len of msg is %v", len(msgBytes))

	//cred, err := psid.NewCredential(key, msg, attrs, rng, tr)
	cred, err := psid.NewBlindCredential(&key, msg, rng, tr) //generate signture (blind-sign), for issuer
	if err != nil {
		return nil, errors.WithMessage(err, "failed to blind-sign")
	}
	//log.Printf("User Cred is %v",cred)
	log.Printf("blind-sign successful.")

	cred_primary, err := psid.NewPrimaryCredential(UserAttributeNames, d, &key, cred, rng, tr) //unblind signture, for user
	if err != nil {
		return nil, errors.WithMessage(err, "failed to origin-sign")
	}
	//log.Printf("User cred_primary is %v",cred_primary)
	log.Printf("unblind signture successful.")
	// t2 := time.Now().UnixNano() / int64(time.Millisecond)
	// log.Printf("Sign Latency=%v ms.", t2-t1)

	primaryCredBytes, err := proto.Marshal(cred_primary)
	log.Printf("User Primary CredBytes is %v", primaryCredBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal credential")
	}
	log.Printf("generate PrimaryCred successful.")

	primaryCRI := CreateCRI(primaryCredBytes)

	primary := &user.UserPrimaryCred{
		PrimaryCred:               primaryCredBytes,
		PrimaryCri:                primaryCRI,
	}

	return proto.Marshal(primary)

	// return primaryCredBytes, nil
}





// // GenerateSignerConfig creates a new signer config.
// // It generates a fresh user secret and issues a credential
// // with four attributes (described above) using the issuer's key pair.
// func GenerateUserConfig(roleMask int, ouString string, enrollmentId, revocationHandle string, key IssuerKeyPS, revKey RsaKey, psid Psidentity, tr Translator) ([]byte, error) {
// 	UserAttributeNames := []string{psidentity.UserAttributeNumber, psidentity.UserAttributeManufacturer, psidentity.UserAttributeDate, psidentity.UserAttributeLevel}


// 	rng, err := psid.Curve.Rand()
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "Error getting PRNG")
// 	}

// 	// sk := psid.Curve.NewRandomZr(rng)
// 	// ni := psid.Curve.NewRandomZr(rng).Bytes()

// 	// t1 := time.Now().UnixNano() / int64(time.Millisecond)

// 	temp := 0
// 	for i := 0; i < len(UserAttributeNames); i++ {
// 		temp = temp + len([]byte(UserAttributeNames[i]))
// 	}
// 	log.Printf("Len of AttributeNames is %v", temp)

// 	//msg, err := psid.NewCredRequest(sk, ni, key.Ipk, rng, tr)	
// 	msg, d, err := psid.NewCredRequestPS(UserAttributeNames, key.Ipk, rng, tr) //generate commitment (pre-blind-sign), for user
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "failed to generate a credential commitment")
// 	}

// 	err = msg.VerifyZeroKnowledgeOne(key.Ipk, psid.Curve, tr)
// 	if err == nil {
// 		log.Printf("Zero knowledge one pass verification.\n")
// 	}else {
// 		return nil, err
// 	}

// 	msgBytes, err := proto.Marshal(msg)
// 	log.Printf("pre-blind-sign successful. Len of msg is %v", len(msgBytes))

// 	//cred, err := psid.NewCredential(key, msg, attrs, rng, tr)
// 	cred, err := psid.NewBlindCredential(&key, msg, rng, tr) //generate signture (blind-sign), for issuer
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "failed to blind-sign")
// 	}
// 	//log.Printf("User Cred is %v",cred)
// 	log.Printf("blind-sign successful.")

// 	cred_primary, err := psid.NewPrimaryCredential(UserAttributeNames, d, &key, cred, rng, tr) //unblind signture, for user
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "failed to origin-sign")
// 	}
// 	//log.Printf("User cred_primary is %v",cred_primary)
// 	log.Printf("unblind signture successful.")
// 	// t2 := time.Now().UnixNano() / int64(time.Millisecond)
// 	// log.Printf("Sign Latency=%v ms.", t2-t1)

// 	credBytes, err := proto.Marshal(cred_primary)
// 	log.Printf("User CredBytes is %v", credBytes)
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "failed to marshal credential")
// 	}

// 	user := &user.UserMessageConfig{
// 		Cred:                            credBytes,
// 		Sk:                              []byte(""),
// 		OrganizationalUnitIdentifier:    ouString,
// 		Role:                            int32(roleMask),
// 		EnrollmentId:                    enrollmentId,
// 		RevocationHandle:                revocationHandle,
// 		CredentialRevocationInformation: []byte(""),
// 	}

// 	return proto.Marshal(user)
// }





//generate revocation key
func GenerateRevocationKeyPS(psid Psidentity) ([]byte, error) {
	// rng, err := psid.Curve.Rand()
	// if err != nil {
	// 	return nil, nil, err
	// }
	// AttributeNames := []string{psidentity.AttributeNameOU, psidentity.AttributeNameRole, psidentity.AttributeNameEnrollmentId, psidentity.AttributeNameRevocationHandle}
	// //AttributeNames := []string{psidentity.AttributeNameOU, psidentity.AttributeNameRole, psidentity.AttributeNameEnrollmentId}
	// log.Printf("AttributeNames is %v", AttributeNames)

	rsaKey, err := psid.NewRevocationKey()
	if err != nil {
		return nil, errors.WithMessage(err, "cannot generate revocation key")
	}

	// log.Printf("the type of rsaKey: %T",rsaKey) //*psidentity.RsaKey

	log.Printf("Generate Revocation key success!")


	rsaKeySerialized, err := proto.Marshal(rsaKey)

	return rsaKeySerialized, err
}
