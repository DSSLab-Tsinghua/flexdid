package psidentity

import (
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	psidentity "psidentity"
	user "psidentity/user"
	"log"
)

// GenerateUserKey generates a user signing key pair.
// Generated keys are serialized to bytes.
func GenerateUserKeyPS(psid Psidentity, tr Translator) ([]byte, []byte, error) {
	rng, err := psid.Curve.Rand()
	if err != nil {
		return nil, nil, err
	}
	UserAttributeNames := []string{psidentity.UserAttributeNumber, psidentity.UserAttributeManufacturer, psidentity.UserAttributeDate, psidentity.UserAttributeLevel}
	log.Printf("UserAttributeNames is %v", UserAttributeNames)

	key, err := psid.NewUserKeyPS(len(UserAttributeNames), rng, tr)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "cannot generate User key")
	}
	log.Printf("Generate User key success!")

	//log.Printf("User key Ipk is %v\n",key.Upk)
	//log.Printf("User key Isk is %v\n",key.Usk)
	upkSerialized, err := proto.Marshal(key.Upk)
	uskSerialized, err := proto.Marshal(key.Usk)

	return uskSerialized, upkSerialized, err
}




func GenerateUserDeriveCred(UserAttributeNames []string, cred_primary PrimaryCredential, key IssuerKeyPS, uk UserKey, psid Psidentity, tr Translator) ([]byte, []byte, error) {

	rng, err := psid.Curve.Rand()
	if err != nil {
		return nil, nil, err
	}
	// UserAttributeNames := []string{psidentity.UserAttributeNumber, psidentity.UserAttributeManufacturer, psidentity.UserAttributeDate, psidentity.UserAttributeLevel}
	temp := 0
	for i := 0; i < len(UserAttributeNames); i++ {
		temp = temp + len([]byte(UserAttributeNames[i]))
	}
	log.Printf("Len of UserAttributeNames is %v", temp)

	//var mask []int = []int{0,1,0,0}
	var mask1 []int = []int{1, 0, 1, 0}
	var mask2 []int = []int{0, 1, 0, 1}

	cred_derive, err := psid.NewDeriveCredential(UserAttributeNames, &key, &cred_primary, mask1, rng, tr)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to derive a credential")
	}
	// log.Printf("Derive User credential cred_derive is %v",cred_derive)
	// log.Printf("Derive User credential success!")

	deriveCredBytes, err := proto.Marshal(cred_derive)

	log.Printf("User deriveCredBytes is %v", deriveCredBytes)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to marshal derive credential")
	}
	log.Printf("generate DeriveCred successful.")

	deriveCRI := CreateCRI(deriveCredBytes)

	derive := &user.UserDeriveCred{
		DeriveCred:               deriveCredBytes,
		DeriveCri:                deriveCRI,
	}

	deriveBytes, err := proto.Marshal(derive)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to marshal derive information")
	}



	CredDerive := make([]*DeriveCredential, 1)
	CredDerive[0] = cred_derive
	//CredDerive = append(CredDerive, cred_derive)


	cred_aggr, err := psid.NewAggregateCredential(&uk, key.Ipk, CredDerive, rng, tr)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to aggregate")
	}
	log.Printf("Aggregate credential is %v", cred_aggr)

	aggregateCredBytes, err := proto.Marshal(cred_aggr)

	log.Printf("User aggregateCredBytes is %v", aggregateCredBytes)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to marshal aggregate credential")
	}
	log.Printf("generate AggregateCred successful.")

	aggregateCRI := CreateCRI(aggregateCredBytes)

	aggregate := &user.UserAggregateCred{
		AggregateCred:               aggregateCredBytes,
		AggregateCri:                aggregateCRI,
	}

	err = cred_aggr.VerifyAggregate(uk.Upk, psid.Curve, tr)
	if err != nil {
		log.Printf("need to be improved")
	}

	aggregateBytes, err := proto.Marshal(aggregate)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "failed to marshal aggregate information")
	}
	return deriveBytes, aggregateBytes, nil



	// cred_aggr, err := psid.NewAggregateCredential(&uk, key.Ipk, CredDerive, rng, tr)
	// if err != nil {
	// 	return nil, errors.WithMessage(err, "failed to aggregate")
	// }
	// log.Printf("Aggregate derived credential cred_aggr is %v", cred_aggr)
	// //log.Printf("Aggregate derived credential success!")

	// err = psid.VerifyAggregate(cred_aggr, &uk, tr)

	// return cred_derive, nil
}


// func newAggregateCredential(key *UserKey, ipk *IssuerPublicKeyPS, messages []*DeriveCredential, rng io.Reader, tr Translator, curve *math.Curve)



func GenerateUserAggregateCred(uk UserKey, key IssuerKeyPS, messages []*DeriveCredential, psid Psidentity, tr Translator) ([]byte, error) {

// func GenerateUserAggregateCred( cred_primary PrimaryCredential, key IssuerKeyPS, uk UserKey, psid Psidentity, tr Translator) ([]byte, error) {

	rng, err := psid.Curve.Rand()
	if err != nil {
		return nil, err
	}

	// CredDerive := make([]*DeriveCredential, 1)
	// CredDerive[0] = cred_derive
	//CredDerive = append(CredDerive, cred_derive)

	cred_aggr, err := psid.NewAggregateCredential(&uk, key.Ipk, messages, rng, tr)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to aggregate")
	}
	log.Printf("Aggregate credential cred_aggr is %v", cred_aggr)
	//log.Printf("Aggregate derived credential success!")

	// err = psid.VerifyAggregate(cred_aggr, &uk, tr)

	// return cred_derive, nil



	// cred_derive, err := psid.NewDeriveCredential(UserAttributeNames, &key, &cred_primary, mask, rng, tr)
	// if err != nil {
	// 	return nil, errors.WithMessage(err, "failed to derive a credential")
	// }
	// log.Printf("Derive User credential cred_derive is %v",cred_derive)
	// log.Printf("Derive User credential success!")

	aggregateCredBytes, err := proto.Marshal(cred_aggr)

	log.Printf("User aggregateCredBytes is %v", aggregateCredBytes)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal aggregate credential")
	}
	log.Printf("generate AggregateCred successful.")

	aggregateCRI := CreateCRI(aggregateCredBytes)

	aggregate := &user.UserAggregateCred{
		AggregateCred:               aggregateCredBytes,
		AggregateCri:                aggregateCRI,
	}

	err = cred_aggr.VerifyAggregate(uk.Upk, psid.Curve, tr)
	if err != nil {
		log.Printf("need to be improved")
	}

	return proto.Marshal(aggregate)




	// CredDerive := make([]*DeriveCredential, 1)
	// CredDerive[0] = cred_derive
	// //CredDerive = append(CredDerive, cred_derive)

	// cred_aggr, err := psid.NewAggregateCredential(&uk, key.Ipk, CredDerive, rng, tr)
	// if err != nil {
	// 	return nil, errors.WithMessage(err, "failed to aggregate")
	// }
	// log.Printf("Aggregate derived credential cred_aggr is %v", cred_aggr)
	// //log.Printf("Aggregate derived credential success!")

	// err = psid.VerifyAggregate(cred_aggr, &uk, tr)

	// return cred_derive, nil
}














// func GenerateUserCredDerive(cred_primary PrimaryCredential, key IssuerKeyPS, uk UserKey, psid Psidentity, tr Translator) ([]byte, error) {

// 	rng, err := psid.Curve.Rand()
// 	if err != nil {
// 		return nil, err
// 	}
// 	AttributeNames := []string{psidentity.AttributeNameOU, psidentity.AttributeNameRole, psidentity.AttributeNameEnrollmentId, psidentity.AttributeNameRevocationHandle}
// 	temp := 0
// 	for i := 0; i < len(AttributeNames); i++ {
// 		temp = temp + len([]byte(AttributeNames[i]))
// 	}
// 	log.Printf("Len of AttributeNames is %v", temp)

// 	//var mask []int = []int{0,1,0,0}
// 	var mask []int = []int{1, 0, 1, 0}

// 	cred_derive, err := psid.NewDeriveCredential(AttributeNames, &key, &cred_primary, mask, rng, tr)
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "failed to derive a credential")
// 	}
// 	//log.Printf("Derive User credential cred_derive is %v",cred_derive)
// 	log.Printf("Derive User credential success!")

// 	CredDerive := make([]*DeriveCredential, 1)
// 	CredDerive[0] = cred_derive
// 	//CredDerive = append(CredDerive, cred_derive)

// 	cred_aggr, err := psid.NewAggregateCredential(&uk, key.Ipk, CredDerive, rng, tr)
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "failed to aggregate")
// 	}
// 	log.Printf("Aggregate derived credential cred_aggr is %v", cred_aggr)
// 	//log.Printf("Aggregate derived credential success!")

// 	err = psid.VerifyAggregate(cred_aggr, &uk, tr)

// 	return nil, nil
// }
