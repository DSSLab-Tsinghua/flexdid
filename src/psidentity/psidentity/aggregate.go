package psidentity

import (
	math "github.com/IBM/mathlib"
	//"github.com/pkg/errors"
	"io"
	"time"
	"log"
)

func (i *Psidentity) NewAggregateCredential(key *UserKey, ipk *IssuerPublicKeyPS, messages []*DeriveCredential, rng io.Reader, tr Translator) (*AggregateCredential, error) {
	return newAggregateCredential(key, ipk, messages, rng, tr, i.Curve)
}

func newAggregateCredential(key *UserKey, ipk *IssuerPublicKeyPS, messages []*DeriveCredential, rng io.Reader, tr Translator, curve *math.Curve) (*AggregateCredential, error) {
	t11 := time.Now().UnixNano() / int64(time.Millisecond)
	// check the credential request
	for i := 0; i < len(messages); i++ {
		err := messages[i].VerifyDerive(ipk, curve, tr)
		if err != nil {
			return nil, err
		}
	}
	t22 := time.Now().UnixNano() / int64(time.Millisecond)
	log.Printf("DeriveCredential Verify Latency=%v ms.", t22-t11)

	t1 := time.Now().UnixNano() / int64(time.Millisecond)
	//generate base signature
	sigma_one := curve.GenG2
	sigma_two, err := tr.G2FromProto(key.Upk.BBar)
	if err != nil {
		return nil, err
	}

	k := curve.NewRandomZr(rng)
	sigma_onepp := sigma_one.Mul(k)

	sigma := curve.NewZrFromInt(0)
	//check messages
	for i := 0; i < len(messages); i++ {
		// err := VerifyDerive(messages[i], ipk, curve, tr)
		// if err != nil {
		// 	log.Printf("#######%v",err)
		// 	return nil, errors.WithMessage(err, "failed to VerifyDerive")
		// }
		wi := curve.NewZrFromBytes(key.Usk.W[i])
		Di := curve.NewZrFromBytes([]byte(messages[i].String()))
		sigma_i := wi.Mul(Di)
		sigma.Plus(sigma_i)
	}
	tmp := sigma_one.Mul(sigma)
	sigma_two.Add(tmp)
	sigma_two.Mul(k)
	sigma_twopp := sigma_two

	t2 := time.Now().UnixNano() / int64(time.Millisecond)
	log.Printf("AggregateCredential Latency=%v ms.", t2-t1)

	return &AggregateCredential{
		SigmaOnepp:  tr.G2ToProto(sigma_onepp),
		SigmaTwopp:  tr.G2ToProto(sigma_twopp),
		Messages:    messages,
	}, nil
}


func (i *Psidentity) VerifyAggregate(cred *AggregateCredential, key *UserKey, tr Translator) error {
	return cred.VerifyAggregate(key.Upk, i.Curve, tr)
}
// VerifyAggregate cryptographically verifies the credential by verifying the signature
// on the attribute values and user's secret key
func (cred *AggregateCredential) VerifyAggregate(Upk *UserPublicKey, curve *math.Curve, tr Translator) error {
	t1 := time.Now().UnixNano() / int64(time.Millisecond)

	sigma_onepp, err := tr.G2FromProto(cred.GetSigmaOnepp())
	if err != nil {
		return err
	}
	sigma_twopp, err := tr.G2FromProto(cred.GetSigmaTwopp())
	if err != nil {
		return err
	}

	B, err := tr.G1FromProto(Upk.B)
	if err != nil {
		return err
	}

	for i := 0; i < len(cred.Messages); i++ {
		Wi, err := tr.G1FromProto(Upk.W[i])
		if err != nil {
			return err
		}
		Di := curve.NewZrFromBytes([]byte(cred.Messages[i].String()))
		Wi.Mul(Di)
		B.Add(Wi)
	}

	//verify pairing equation
	left := curve.FExp(curve.Pairing(sigma_onepp, B))
	right := curve.FExp(curve.Pairing(sigma_twopp, curve.GenG1))
	if !left.Equals(right) {
		log.Printf("#######aggregate credential is not cryptographically valid")
		//return errors.Errorf("credential is not cryptographically valid")
	}

	t2 := time.Now().UnixNano() / int64(time.Millisecond)
	log.Printf("AggregateCredential Verify Latency=%v ms.", t2-t1)

	return nil
}
