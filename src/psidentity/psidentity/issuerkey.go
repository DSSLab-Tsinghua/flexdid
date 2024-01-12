package psidentity

import (
	"io"

	amcl "psidentity/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	// "fmt"
)

// The Issuer secret ISk and public IPk keys are used to issue credentials and
// to verify signatures created using the credentials

// NewIssuerKey creates a new issuer key pair taking an array of attribute names
// that will be contained in credentials certified by this issuer (a credential specification)
func (i *Psidentity) NewIssuerKey(AttributeNames []string, rng io.Reader, t Translator) (*IssuerKey, error) {
	return newIssuerKey(AttributeNames, rng, i.Curve, t)
}

func newIssuerKey(AttributeNames []string, rng io.Reader, curve *math.Curve, t Translator) (*IssuerKey, error) {
	// validate inputs

	// check for duplicated attributes
	attributeNamesMap := map[string]bool{}
	for _, name := range AttributeNames {
		if attributeNamesMap[name] {
			return nil, errors.Errorf("attribute %s appears multiple times in AttributeNames", name)
		}
		attributeNamesMap[name] = true
	}

	key := new(IssuerKey)

	// generate issuer secret key
	ISk := curve.NewRandomZr(rng)
	key.Isk = ISk.Bytes()

	// generate the corresponding public key
	key.Ipk = new(IssuerPublicKey)
	key.Ipk.AttributeNames = AttributeNames

	W := curve.GenG2.Mul(ISk)
	key.Ipk.W = t.G2ToProto(W)

	// generate bases that correspond to the attributes
	key.Ipk.HAttrs = make([]*amcl.ECP, len(AttributeNames))
	for i := 0; i < len(AttributeNames); i++ {
		key.Ipk.HAttrs[i] = t.G1ToProto(curve.GenG1.Mul(curve.NewRandomZr(rng)))
	}

	// generate base for the secret key
	HSk := curve.GenG1.Mul(curve.NewRandomZr(rng))
	key.Ipk.HSk = t.G1ToProto(HSk)

	// generate base for the randomness
	HRand := curve.GenG1.Mul(curve.NewRandomZr(rng))
	key.Ipk.HRand = t.G1ToProto(HRand)

	BarG1 := curve.GenG1.Mul(curve.NewRandomZr(rng))
	key.Ipk.BarG1 = t.G1ToProto(BarG1)

	BarG2 := BarG1.Mul(ISk)
	key.Ipk.BarG2 = t.G1ToProto(BarG2)

	// generate a zero-knowledge proof of knowledge (ZK PoK) of the secret key which
	// is in W and BarG2.

	// Sample the randomness needed for the proof
	r := curve.NewRandomZr(rng)

	// Step 1: First message (t-values)
	t1 := curve.GenG2.Mul(r) // t1 = g_2^r, cover W
	t2 := BarG1.Mul(r)       // t2 = (\bar g_1)^r, cover BarG2

	// Step 2: Compute the Fiat-Shamir hash, forming the challenge of the ZKP.
	proofData := make([]byte, 3*curve.G1ByteSize+3*curve.G2ByteSize)
	index := 0
	index = appendBytesG2(proofData, index, t1)
	index = appendBytesG1(proofData, index, t2)
	index = appendBytesG2(proofData, index, curve.GenG2)
	index = appendBytesG1(proofData, index, BarG1)
	index = appendBytesG2(proofData, index, W)
	index = appendBytesG1(proofData, index, BarG2)

	proofC := curve.HashToZr(proofData)
	key.Ipk.ProofC = proofC.Bytes()

	// Step 3: reply to the challenge message (s-values)
	proofS := curve.ModAdd(curve.ModMul(proofC, ISk, curve.GroupOrder), r, curve.GroupOrder) // // s = r + C \cdot ISk
	key.Ipk.ProofS = proofS.Bytes()

	// Hash the public key
	serializedIPk, err := proto.Marshal(key.Ipk)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal issuer public key")
	}
	key.Ipk.Hash = curve.HashToZr(serializedIPk).Bytes()

	// We are done
	return key, nil
}

func (i *Psidentity) NewIssuerKeyFromBytes(raw []byte) (*IssuerKey, error) {
	return newIssuerKeyFromBytes(raw)
}

func newIssuerKeyFromBytes(raw []byte) (*IssuerKey, error) {
	ik := &IssuerKey{}
	if err := proto.Unmarshal(raw, ik); err != nil {
		return nil, err
	}

	//raw, err :=proto.Marshal(ik.Ipk.W)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Printf("IPKW : [%v]", ik.Ipk.W.Xa)

	return ik, nil
}

// Check checks that this issuer public key is valid, i.e.
// that all components are present and a ZK proofs verifies
func (IPk *IssuerPublicKey) Check(curve *math.Curve, t Translator) error {
	// Unmarshall the public key
	NumAttrs := len(IPk.GetAttributeNames())
	HSk, err := t.G1FromProto(IPk.GetHSk())
	if err != nil {
		return err
	}

	HRand, err := t.G1FromProto(IPk.GetHRand())
	if err != nil {
		return err
	}

	HAttrs := make([]*math.G1, len(IPk.GetHAttrs()))
	for i := 0; i < len(IPk.GetHAttrs()); i++ {
		HAttrs[i], err = t.G1FromProto(IPk.GetHAttrs()[i])
		if err != nil {
			return err
		}
	}
	BarG1, err := t.G1FromProto(IPk.GetBarG1())
	if err != nil {
		return err
	}

	BarG2, err := t.G1FromProto(IPk.GetBarG2())
	if err != nil {
		return err
	}

	W, err := t.G2FromProto(IPk.GetW())
	if err != nil {
		return err
	}

	ProofC := curve.NewZrFromBytes(IPk.GetProofC())
	ProofS := curve.NewZrFromBytes(IPk.GetProofS())

	// Check that the public key is well-formed
	if NumAttrs < 0 ||
		HSk == nil ||
		HRand == nil ||
		BarG1 == nil ||
		BarG1.IsInfinity() ||
		BarG2 == nil ||
		HAttrs == nil ||
		len(IPk.HAttrs) < NumAttrs {
		return errors.Errorf("some part of the public key is undefined")
	}
	for i := 0; i < NumAttrs; i++ {
		if IPk.HAttrs[i] == nil {
			return errors.Errorf("some part of the public key is undefined")
		}
	}

	// Verify Proof

	// Recompute challenge
	proofData := make([]byte, 3*curve.G1ByteSize+3*curve.G2ByteSize)
	index := 0

	// Recompute t-values using s-values
	t1 := curve.GenG2.Mul(ProofS)
	t1.Add(W.Mul(curve.ModNeg(ProofC, curve.GroupOrder))) // t1 = g_2^s \cdot W^{-C}

	t2 := BarG1.Mul(ProofS)
	t2.Add(BarG2.Mul(curve.ModNeg(ProofC, curve.GroupOrder))) // t2 = {\bar g_1}^s \cdot {\bar g_2}^C

	index = appendBytesG2(proofData, index, t1)
	index = appendBytesG1(proofData, index, t2)
	index = appendBytesG2(proofData, index, curve.GenG2)
	index = appendBytesG1(proofData, index, BarG1)
	index = appendBytesG2(proofData, index, W)
	index = appendBytesG1(proofData, index, BarG2)

	// Verify that the challenge is the same
	if !ProofC.Equals(curve.HashToZr(proofData)) {
		return errors.Errorf("zero knowledge proof in public key invalid")
	}

	return IPk.SetHash(curve)
}

// SetHash appends a hash of a serialized public key
func (IPk *IssuerPublicKey) SetHash(curve *math.Curve) error {
	IPk.Hash = nil
	serializedIPk, err := proto.Marshal(IPk)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal issuer public key")
	}
	IPk.Hash = curve.HashToZr(serializedIPk).Bytes()
	return nil
}




// Yunqing new add
func (i *Psidentity) NewIssuerKeyPS(n int, rng io.Reader, t Translator) (*IssuerKeyPS, error) {
	return newIssuerKeyPS(n, rng, i.Curve, t)
}

func newIssuerKeyPS(n int, rng io.Reader, curve *math.Curve, t Translator) (*IssuerKeyPS, error) {
	// validate inputs

	// check for duplicated attributes
	//attributeNamesMap := map[string]bool{}
	//for _, name := range AttributeNames {
	//	if attributeNamesMap[name] {
	//		return nil, errors.Errorf("attribute %s appears multiple times in AttributeNames", name)
	//	}
	//	attributeNamesMap[name] = true
	//}


	// //test  d1 = d1_b
	// d1 := curve.NewRandomZr(rng)
	// d1_bytes := d1.Bytes()
	// d1_b := curve.NewZrFromBytes(d1_bytes)
	// fmt.Printf("the value of d1:%v\n", d1)
	// fmt.Printf("the value of d1_bytes:%v\n", d1_bytes)
	// fmt.Printf("the value of d1_b:%v\n", d1_b)

	// //test NewRandomZr if truly random
	// d2 := curve.NewRandomZr(rng)
	// fmt.Printf("the value of d2:%v\n", d2)

	key := new(IssuerKeyPS)

	// generate issuer secret key
	key.Isk = new(IssuerPrivateKeyPS)
	key.Ipk = new(IssuerPublicKeyPS)

	tempX := curve.NewRandomZr(rng)
	tempX_bytes := tempX.Bytes()
	tempXX := curve.NewZrFromBytes(tempX_bytes)
	key.Isk.X = tempXX.Bytes()

	key.Ipk.Y = make([]*amcl.ECP, n)
	key.Ipk.YBar = make([]*amcl.ECP2, n)
	//key.Ipk.ZIj = make([]*amcl.ECP, n^2)

	for i := 0; i < n; i++ {
		tempY := curve.NewRandomZr(rng)
		tempY_bytes := tempY.Bytes()
		y_i := curve.NewZrFromBytes(tempY_bytes)
		key.Isk.Y = append(key.Isk.Y,y_i.Bytes())

		// generate the corresponding public key
		// generate Y
		Y_i := curve.GenG1.Mul(y_i)
		key.Ipk.Y[i] = t.G1ToProto(Y_i)

		// genetate YBar
		YBar_i := curve.GenG2.Mul(y_i)
		key.Ipk.YBar[i] = t.G2ToProto(YBar_i)
	}

	// genetate X
	X := curve.GenG1.Mul(tempXX)
	key.Ipk.X = t.G1ToProto(X)

	// generate Z_ij
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j {
				mult := curve.NewZrFromBytes(key.Isk.Y[i]).Mul(curve.NewZrFromBytes(key.Isk.Y[j]))
				Z_ij := curve.GenG1.Mul(mult)
				//key.Ipk.ZIj[i*j] = t.G1ToProto(Z_ij)
				key.Ipk.ZIj = append(key.Ipk.ZIj,t.G1ToProto(Z_ij))
			}
		}
	}

	// Hash the public key
	serializedIPk, err := proto.Marshal(key.Ipk)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal issuer public key")
	}
	key.Ipk.Hash = curve.HashToZr(serializedIPk).Bytes()

	// We are done
	return key, nil
}


// func (IPk *IssuerPublicKeyPS) CheckPS(curve *math.Curve, t Translator) error {
// 	// Unmarshall the public key
// 	X, err := t.G1FromProto(IPk.GetX())
// 	if err != nil {
// 		return err
// 	}

// 	Y := make([]*math.G1, len(IPk.GetY()))
// 	for i := 0; i < len(IPk.GetY()); i++ {
// 		Y[i], err = t.G1FromProto(IPk.GetY()[i])
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	YBar := make([]*math.G2, len(IPk.GetYBar()))
// 	for i := 0; i < len(IPk.GetYBar()); i++ {
// 		YBar[i], err = t.G2FromProto(IPk.GetYBar()[i])
// 		if err != nil {
// 			return err
// 		}
// 	}

// 	Z_ij := make([][]*math.G1, len(IPk.GetZ_ij())*len(IPk.GetZ_ij()[1]))
// 	for i := 0; i < len(IPk.GetZ_ij()); i++ {
// 		for j := 0; j < len(IPk.GetZ_ij()[1]); j++ {
// 			Z_ij[i][j], err = t.G1FromProto(IPk.GetZ_ij()[i][j])
// 			if err != nil {
// 				return err
// 			}
// 		}
// 	}

// 	// Check that the public key is well-formed
// 	if X == nil || Y == nil || YBar == nil || Z_ij == nil {
// 		return errors.Errorf("some part of the public key is undefined")
// 	}

// 	return IPk.SetHashPS(curve)
// }

// // SetHash appends a hash of a serialized public key
// func (IPk *IssuerPublicKeyPS) SetHashPS(curve *math.Curve) error {
// 	IPk.Hash = nil
// 	serializedIPk, err := proto.Marshal(IPk)
// 	if err != nil {
// 		return errors.Wrap(err, "Failed to marshal issuer public key")
// 	}
// 	IPk.Hash = curve.HashToZr(serializedIPk).Bytes()
// 	return nil
// }
