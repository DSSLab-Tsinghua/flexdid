package psidentity

import (
	amcl "psidentity/translator/amcl"
	math "github.com/IBM/mathlib"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"io"
)

func (i *Psidentity) NewUserKeyPS(n int, rng io.Reader, t Translator) (*UserKey, error) {
	return NewUserKeyPS(n, rng, i.Curve, t)
}

func NewUserKeyPS(n int, rng io.Reader, curve *math.Curve, t Translator) (*UserKey, error) {

	key := new(UserKey)

	// generate user key
	key.Usk = new(UserPrivateKey)
	key.Upk = new(UserPublicKey)

	key.Upk.W = make([]*amcl.ECP, n)
	key.Upk.WBar = make([]*amcl.ECP2, n)

	tempb := curve.NewRandomZr(rng)
	tempb_bytes := tempb.Bytes()
	key.Usk.B = curve.NewZrFromBytes(tempb_bytes).Bytes()

	B := curve.GenG1.Mul(curve.NewZrFromBytes(tempb_bytes))
	key.Upk.B = t.G1ToProto(B)

	BBar := curve.GenG2.Mul(curve.NewZrFromBytes(tempb_bytes))
	key.Upk.BBar = t.G2ToProto(BBar)

	for i := 0; i < n; i++ {
		tempw := curve.NewRandomZr(rng)
		tempw_bytes := tempw.Bytes()
		w_i := curve.NewZrFromBytes(tempw_bytes)
		key.Usk.W = append(key.Usk.W, w_i.Bytes())

		// generate the corresponding public key
		W_i := curve.GenG1.Mul(w_i)
		key.Upk.W[i] = t.G1ToProto(W_i)

		// genetate WBar
		WBar_i := curve.GenG2.Mul(w_i)
		key.Upk.WBar[i] = t.G2ToProto(WBar_i)
	}

	// Hash the public key
	serializedUpk, err := proto.Marshal(key.Upk)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal user public key")
	}
	key.Upk.Hash = curve.HashToZr(serializedUpk).Bytes()

	// We are done
	return key, nil
}
