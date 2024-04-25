package bulletproof

import (
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type BulletParams struct {
	P  *big.Int
	N  int64
	G  []curve.G1Affine
	H  []curve.G1Affine
	Bg curve.G1Affine
	Bh curve.G1Affine
}

func (p BulletParams) ParamsGen() BulletParams {
	n := int64(32)
	p.P = fr.Modulus()
	p.N = n
	G := GenerateMultiPoint(n)
	H := GenerateMultiPoint(n)
	g := GeneratePoint()
	h := GeneratePoint()
	p.G = G
	p.H = H
	p.Bg = g
	p.Bh = h
	return p
}
