/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package psidentity

import (
	"io"

	math "github.com/IBM/mathlib"
	"github.com/pkg/errors"

	"time"
	"log"

	// "fmt"
)

// credRequestLabel is the label used in zero-knowledge proof (ZKP) to identify that this ZKP is a credential request
const credRequestLabel = "credRequest"

// Credential issuance is an interactive protocol between a user and an issuer
// The issuer takes its secret and public keys and user attribute values as input
// The user takes the issuer public key and user secret as input
// The issuance protocol consists of the following steps:
// 1) The issuer sends a random nonce to the user
// 2) The user creates a Credential Request using the public key of the issuer, user secret, and the nonce as input
//    The request consists of a commitment to the user secret (can be seen as a public key) and a zero-knowledge proof
//     of knowledge of the user secret key
//    The user sends the credential request to the issuer
// 3) The issuer verifies the credential request by verifying the zero-knowledge proof
//    If the request is valid, the issuer issues a credential to the user by signing the commitment to the secret key
//    together with the attribute values and sends the credential back to the user
// 4) The user verifies the issuer's signature and stores the credential that consists of
//    the signature value, a randomness used to create the signature, the user secret, and the attribute values

// NewCredRequest creates a new Credential Request, the first message of the interactive credential issuance protocol
// (from user to issuer)
func (i *Psidentity) NewCredRequest(sk *math.Zr, IssuerNonce []byte, ipk *IssuerPublicKey, rng io.Reader, tr Translator) (*CredRequest, error) {
	return newCredRequest(sk, IssuerNonce, ipk, rng, i.Curve, tr)
}

func newCredRequest(sk *math.Zr, IssuerNonce []byte, ipk *IssuerPublicKey, rng io.Reader, curve *math.Curve, tr Translator) (*CredRequest, error) {
	// Set Nym as h_{sk}^{sk}
	HSk, err := tr.G1FromProto(ipk.HSk)
	if err != nil {
		return nil, err
	}
	Nym := HSk.Mul(sk)

	// generate a zero-knowledge proof of knowledge (ZK PoK) of the secret key

	// Sample the randomness needed for the proof
	rSk := curve.NewRandomZr(rng)

	// Step 1: First message (t-values)
	t := HSk.Mul(rSk) // t = h_{sk}^{r_{sk}}, cover Nym

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	// proofData is the data being hashed, it consists of:
	// the credential request label
	// 3 elements of G1 each taking 2*math.FieldBytes+1 bytes
	// hash of the issuer public key of length math.FieldBytes
	// issuer nonce of length math.FieldBytes
	proofData := make([]byte, len([]byte(credRequestLabel))+3*curve.G1ByteSize+2*curve.ScalarByteSize)
	index := 0
	index = appendBytesString(proofData, index, credRequestLabel)
	index = appendBytesG1(proofData, index, t)
	index = appendBytesG1(proofData, index, HSk)
	index = appendBytesG1(proofData, index, Nym)
	index = appendBytes(proofData, index, IssuerNonce)
	copy(proofData[index:], ipk.Hash)
	proofC := curve.HashToZr(proofData)

	// Step 3: reply to the challenge message (s-values)
	proofS := curve.ModAdd(curve.ModMul(proofC, sk, curve.GroupOrder), rSk, curve.GroupOrder) // s = r_{sk} + C \cdot sk

	// Done
	return &CredRequest{
		Nym:         tr.G1ToProto(Nym),
		IssuerNonce: IssuerNonce,
		ProofC:      proofC.Bytes(),
		ProofS:      proofS.Bytes(),
	}, nil
}

// Check cryptographically verifies the credential request
func (m *CredRequest) Check(ipk *IssuerPublicKey, curve *math.Curve, tr Translator) error {
	Nym, err := tr.G1FromProto(m.GetNym())
	if err != nil {
		return err
	}

	IssuerNonce := m.GetIssuerNonce()
	ProofC := curve.NewZrFromBytes(m.GetProofC())
	ProofS := curve.NewZrFromBytes(m.GetProofS())

	HSk, err := tr.G1FromProto(ipk.HSk)
	if err != nil {
		return err
	}

	if Nym == nil || IssuerNonce == nil || ProofC == nil || ProofS == nil {
		return errors.Errorf("one of the proof values is undefined")
	}

	// Verify Proof

	// Recompute t-values using s-values
	t := HSk.Mul(ProofS)
	t.Sub(Nym.Mul(ProofC)) // t = h_{sk}^s / Nym^C

	// Recompute challenge
	proofData := make([]byte, len([]byte(credRequestLabel))+3*curve.G1ByteSize+2*curve.ScalarByteSize)
	index := 0
	index = appendBytesString(proofData, index, credRequestLabel)
	index = appendBytesG1(proofData, index, t)
	index = appendBytesG1(proofData, index, HSk)
	index = appendBytesG1(proofData, index, Nym)
	index = appendBytes(proofData, index, IssuerNonce)
	copy(proofData[index:], ipk.Hash)

	if !ProofC.Equals(curve.HashToZr(proofData)) {
		return errors.Errorf("zero knowledge proof is invalid")
	}

	return nil
}



//Yunqing new add
func (i *Psidentity) NewCredRequestPS(UserAttributeNames []string, ipk *IssuerPublicKeyPS, rng io.Reader, tr Translator) (*CredRequestPS, *math.Zr, error) {
	return newCredRequestPS(UserAttributeNames, ipk, rng, i.Curve, tr)
}

func newCredRequestPS(UserAttributeNames []string, ipk *IssuerPublicKeyPS, rng io.Reader, curve *math.Curve, tr Translator) (*CredRequestPS, *math.Zr, error) {
	t1 := time.Now().UnixNano() / int64(time.Millisecond)

	// generage commitment
	d := curve.NewRandomZr(rng)

	commitment := curve.GenG2.Mul(d)

	for i := 0; i < len(UserAttributeNames); i++ {
		YBar, err := tr.G2FromProto(ipk.YBar[i])
		if err != nil {
			return nil, nil, err
		}
		attr := curve.NewZrFromBytes([]byte(UserAttributeNames[i]))
		if err != nil {
			return nil, nil, err
		}
		tmp := YBar.Mul(attr)
		commitment.Add(tmp)
	}

	// generate a zero-knowledge proof of knowledge (ZK PoK) of messages
	//generate k
	p := curve.NewRandomZr(rng)
	w := make([]*math.Zr, len(UserAttributeNames))
	k := curve.GenG2.Mul(p)
	for i := 0; i < len(UserAttributeNames); i++ {
		w[i] = curve.NewRandomZr(rng)
		YBarI, err := tr.G2FromProto(ipk.YBar[i])
		if err != nil {
			return nil, nil, err
		}
		k.Add(YBarI.Mul(w[i]))
	}

	//compute challenge
	// proofData is the data being hashed, it consists of:
	// the credential request label
	// 3 elements of G2 each taking 2*math.FieldBytes+1 bytes
	// hash of the issuer public key of length math.FieldBytes

	proofData := make([]byte, len([]byte(credRequestLabel))+3*curve.G2ByteSize+curve.ScalarByteSize)
	index := 0
	index = appendBytesString(proofData, index, credRequestLabel)
	index = appendBytesG2(proofData, index, commitment)
	index = appendBytesG2(proofData, index, k)
	index = appendBytesG2(proofData, index, curve.GenG2)
	copy(proofData[index:], ipk.Hash)
	challenge := curve.HashToZr(proofData)

	// generate response
	rp := p.Plus(challenge.Mul(d)) //rd = p + challenge * d

	rw := make([][]byte, len(UserAttributeNames))
	for i := 0; i < len(UserAttributeNames); i++ {
		value := w[i].Plus(challenge.Mul(curve.NewZrFromBytes([]byte(UserAttributeNames[i])))) //rw = w[i] + challenge * attributes[i]
		// fmt.Printf("the type of value:%T", value)
		rw[i] = value.Bytes()
	}

	t2 := time.Now().UnixNano() / int64(time.Millisecond)
	log.Printf("Pre-Sign Latency=%v ms.", t2-t1)

	// Done
	return &CredRequestPS{
		Commitment: commitment.Bytes(),
		K:          k.Bytes(),
		Challenge:  challenge.Bytes(),
		Rp:         rp.Bytes(),
		Rw:         rw,
	}, d, nil
}

// Verify cryptographically verifies the credential request
func (m *CredRequestPS) VerifyZeroKnowledgeOne(ipk *IssuerPublicKeyPS, curve *math.Curve, tr Translator) error {
	commitment, err := curve.NewG2FromBytes(m.GetCommitment())
	if err != nil {
		return err
	}
	k, err := curve.NewG2FromBytes(m.GetK())
	if err != nil {
		return err
	}
	challenge := m.GetChallenge()
	rp := curve.NewZrFromBytes(m.GetRp())
	rw := m.GetRw()

	if commitment == nil || k == nil || challenge == nil || rp == nil || rw == nil {
		return errors.Errorf("one of the proof values is undefined")
	}

	// Verify Proof
	//compute left
	left := curve.GenG2.Mul(rp)
	for i := 0; i < len(rw); i++ {
		YBarI, err := tr.G2FromProto(ipk.YBar[i])
		if err != nil {
			return err
		}
		left.Add(YBarI.Mul(curve.NewZrFromBytes(rw[i])))
	}

	right := k
	//compute right
	Ce := commitment.Mul(curve.NewZrFromBytes(challenge))
	right.Add(Ce)

	if !left.Equals(right) {
		return errors.Errorf("zero knowledge proof is invalid")
	}
	return nil
}
