package psidentity

import (
	math "github.com/IBM/mathlib"
	amcl "psidentity/translator/amcl"
)

type Psidentity struct {
	Curve      *math.Curve
	Translator Translator
}

type Translator interface {
	G1ToProto(*math.G1) *amcl.ECP
	G1FromProto(*amcl.ECP) (*math.G1, error)
	G1FromRawBytes([]byte) (*math.G1, error)
	G2ToProto(*math.G2) *amcl.ECP2
	G2FromProto(*amcl.ECP2) (*math.G2, error)
}

