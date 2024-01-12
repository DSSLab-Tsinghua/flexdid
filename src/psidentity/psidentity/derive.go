package psidentity

import (
	math "github.com/IBM/mathlib"
	"github.com/pkg/errors"
	"io"
	"log"
	"time"
)

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
//
//package idemix
//
//import (
//"crypto/ecdsa"
//"fmt"
//"io"
//"sort"
//
//opts "github.com/IBM/idemix/bccsp/schemes"
//math "github.com/IBM/mathlib"
//"github.com/pkg/errors"
//)

// signLabel is the label used in zero-knowledge proof (ZKP) to identify that this ZKP is a signature of knowledge
const signLabelPS = "sign"

//const signWithEidNymLabel = "signWithEidNym"
//const signWithEidNymRhNymLabel = "signWithEidNymRhNym" // When the revocation handle is present the enrollment id must also be present

// A signature that is produced using an Identity Mixer credential is a so-called signature of knowledge
// (for details see C.P.Schnorr "Efficient Identification and Signatures for Smart Cards")
// An Identity Mixer signature is a signature of knowledge that signs a message and proves (in zero-knowledge)
// the knowledge of the user secret (and possibly attributes) signed inside a credential
// that was issued by a certain issuer (referred to with the issuer public key)
// The signature is verified using the message being signed and the public key of the issuer
// Some of the attributes from the credential can be selectively disclosed or different statements can be proven about
// credential attributes without disclosing them in the clear
// The difference between a standard signature using X.509 certificates and an Identity Mixer signature is
// the advanced privacy features provided by Identity Mixer (due to zero-knowledge proofs):
//  - Unlinkability of the signatures produced with the same credential
//  - Selective attribute disclosure and predicates over attributes

// Make a slice of all the attribute indices that will not be disclosed
func hideIndices(Mask []int) []int64 {
	HideIndices := make([]int64, 0)
	for index, flag := range Mask {
		if flag == 0 {
			HideIndices = append(HideIndices, int64(index))
		}
	}
	return HideIndices
}

func discloseIndices(Mask []int) []int64 {
	DiscloseIndices := make([]int64, 0)
	for index, flag := range Mask {
		if flag == 1 {
			DiscloseIndices = append(DiscloseIndices, int64(index))
		}
	}
	return DiscloseIndices
}

func (i *Psidentity) NewDeriveCredential(Attrs []string, key *IssuerKeyPS, m *PrimaryCredential, Mask []int, rng io.Reader, tr Translator) (*DeriveCredential, error) {
	return newDeriveCredential(Attrs, key, m, Mask, rng, tr, i.Curve)
}

func newDeriveCredential(Attrs []string, key *IssuerKeyPS, m *PrimaryCredential, Mask []int, rng io.Reader, tr Translator, curve *math.Curve) (*DeriveCredential, error) {

	t11 := time.Now().UnixNano() / int64(time.Millisecond)
	// check the credential request
	err := m.VerifyPrimary(key.Ipk, curve, tr)
	if err != nil {
		return nil, err
	}
	t22 := time.Now().UnixNano() / int64(time.Millisecond)
	log.Printf("PrimaryCredential Verify Latency=%v ms.", t22-t11)

	t1 := time.Now().UnixNano() / int64(time.Millisecond)

	r := curve.NewRandomZr(rng)
	t := curve.NewRandomZr(rng)

	h, err := tr.G2FromProto(m.H)
	if err != nil {
		return nil, err
	}
	h.Mul(r)
	hp := h  //hp = h^r

	s, err := tr.G2FromProto(m.S)
	if err != nil {
		return nil, err
	}
	s.Mul(r)
	tmp := h.Mul(t)
	s.Add(tmp)
	sp := s

	sigma_onep := curve.GenG1.Mul(t)
	HideIndices := hideIndices(Mask)
	for j := 0; j < len(HideIndices); j++ {
		Yi, err := tr.G1FromProto(key.Ipk.Y[HideIndices[j]])
		if err != nil {
			return nil, err
		}
		// tmp := Yi.Mul(curve.NewZrFromBytes([]byte(Attrs[j])))
		tmp := Yi.Mul(curve.NewZrFromBytes([]byte(Attrs[HideIndices[j]])))
		sigma_onep.Add(tmp)
	}

	DiscloseIndices := discloseIndices(Mask)
	DiscloseMsg := make([]string, len(Attrs))
	Y, err := tr.G1FromProto(key.Ipk.Y[DiscloseIndices[0]])
	DiscloseMsg[DiscloseIndices[0]] = Attrs[DiscloseIndices[0]]
	for i := 1; i < len(DiscloseIndices); i++ {
		Yi, err := tr.G1FromProto(key.Ipk.Y[DiscloseIndices[i]])
		if err != nil {
			return nil, err
		}
		DiscloseMsg[DiscloseIndices[i]] = Attrs[DiscloseIndices[i]]
		Y.Add(Yi)
	}
	sigma_twop := Y.Mul(t)
	var Zij *math.G1
	//二维数组[m,n]坐标到一维数组坐标index的转换：二维[i, j] 可转换成一维的 index = i * n + j;
	//一维数组坐标index到二维数组[m,n]坐标的转换：一维的 index 可转换成二维[i = index / n, j = index % n]
	for i := 0; i < len(DiscloseIndices); i++ {
		for j := 0; j < len(HideIndices); j++ {
			index := DiscloseIndices[i]*int64(len(HideIndices)) + HideIndices[j]
			Zij, err = tr.G1FromProto(key.Ipk.ZIj[index])
			if err != nil {
				return nil, err
			}
			Zij.Mul(curve.NewZrFromBytes([]byte(Attrs[HideIndices[j]])))
		}
	}
	sigma_twop.Add(Zij)

	t2 := time.Now().UnixNano() / int64(time.Millisecond)
	log.Printf("Derive Latency=%v ms.", t2-t1)

	return &DeriveCredential{
		Hp:              tr.G2ToProto(hp),
		Sp:              tr.G2ToProto(sp),
		SigmaOnep:       tr.G1ToProto(sigma_onep),
		SigmaTwop:       tr.G1ToProto(sigma_twop),
		DiscloseIndices: DiscloseIndices,
		DiscloseMsg:     DiscloseMsg,
	}, nil
}

// VerifyDerive cryptographically verifies the credential by verifying the signature
// on the attribute values and user's secret key
func (cred *DeriveCredential) VerifyDerive(ipk *IssuerPublicKeyPS, curve *math.Curve, tr Translator) error {
	// Validate Input
	hp, err := tr.G2FromProto(cred.GetHp())
	if err != nil {
		return err
	}
	sp, err := tr.G2FromProto(cred.GetSp())
	if err != nil {
		return err
	}

	sigma_onep, err := tr.G1FromProto(cred.GetSigmaOnep())
	if err != nil {
		return err
	}
	sigma_twop, err := tr.G1FromProto(cred.GetSigmaTwop())
	if err != nil {
		return err
	}

	X, err := tr.G1FromProto(ipk.X)
	if err != nil {
		return err
	}
	X.Add(sigma_onep)

	// var YBarSum *math.G2
	//方法1
	temp := curve.NewZrFromInt(0)
	YBarSum := curve.GenG2.Mul(temp)

	for i := 0; i < len(cred.DiscloseIndices); i++ {
		if cred.DiscloseMsg[cred.DiscloseIndices[i]] == "" {
			continue
		}
		Yi, err := tr.G1FromProto(ipk.Y[cred.DiscloseIndices[i]])
		if err != nil {
			return err
		}

		X.Add(Yi.Mul(curve.NewZrFromBytes([]byte(cred.DiscloseMsg[cred.DiscloseIndices[i]]))))

		YBarI, err := tr.G2FromProto(ipk.YBar[cred.DiscloseIndices[i]])
		if err != nil {
			return err
		}
		YBarSum.Add(YBarI)

		if i == len(cred.DiscloseIndices)-1 {
			if cred.DiscloseMsg[cred.DiscloseIndices[i]] == "" {
				return errors.Errorf("credential has no value for attribute %s", cred.DiscloseMsg[cred.DiscloseIndices[i]])
			}
		}
	}

	// //方法2：
	// Y0, err := tr.G1FromProto(ipk.Y[cred.DiscloseIndices[0]])
	// if err != nil {
	// 	return err
	// }
	// X.Add(Y0.Mul(curve.NewZrFromBytes([]byte(cred.DiscloseMsg[cred.DiscloseIndices[0]]))))
	// YBarSum, err := tr.G2FromProto(ipk.YBar[cred.DiscloseIndices[0]])
	// if err != nil {
	// 	return err
	// }
	// for i := 1; i < len(cred.DiscloseIndices); i++ {
	// 	if cred.DiscloseMsg[cred.DiscloseIndices[i]] == "" {
	// 		continue
	// 	}
	// 	Yi, err := tr.G1FromProto(ipk.Y[cred.DiscloseIndices[i]])
	// 	if err != nil {
	// 		return err
	// 	}

	// 	X.Add(Yi.Mul(curve.NewZrFromBytes([]byte(cred.DiscloseMsg[cred.DiscloseIndices[i]]))))

	// 	YBarI, err := tr.G2FromProto(ipk.YBar[cred.DiscloseIndices[i]])
	// 	if err != nil {
	// 		return err
	// 	}
	// 	YBarSum.Add(YBarI)

	// 	if i == len(cred.DiscloseIndices)-1 {
	// 		if cred.DiscloseMsg[cred.DiscloseIndices[i]] == "" {
	// 			return errors.Errorf("credential has no value for attribute %s", cred.DiscloseMsg[cred.DiscloseIndices[i]])
	// 		}
	// 	}
	// }

	//verify pairing equation
	left1 := curve.FExp(curve.Pairing(hp, X))
	right1 := curve.FExp(curve.Pairing(sp, curve.GenG1))
	if !left1.Equals(right1) {
		log.Printf("##########11credential is not cryptographically valid")
		//return errors.Errorf("credential is not cryptographically valid")
	}

	left2 := curve.FExp(curve.Pairing(YBarSum, sigma_onep))
	right2 := curve.FExp(curve.Pairing(curve.GenG2, sigma_twop))
	if !left2.Equals(right2) {
		log.Printf("##########22credential is not cryptographically valid")
		//return errors.Errorf("credential is not cryptographically valid")
	}

	log.Printf("VerifyDerive successful.")

	return nil
}
