package util

import (
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
)

type Publickey struct {
	Pk curve.PointAffine
}
type Privatekey struct {
	Sk *big.Int
}

func (pk Publickey) Encrypt(plain *curve.PointAffine, r *big.Int, h curve.PointAffine) []curve.PointAffine {
	c1 := new(curve.PointAffine).Add(plain, new(curve.PointAffine).ScalarMultiplication(&pk.Pk, r))
	c2 := new(curve.PointAffine).ScalarMultiplication(&h, r)

	return []curve.PointAffine{*c1, *c2}
}

func (sk Privatekey) Decryptacc(acc []curve.PointAffine, g1delta *curve.PointAffine) *curve.PointAffine {
	res := new(curve.PointAffine).Add(
		new(curve.PointAffine).Neg(g1delta), new(curve.PointAffine).Add(
			&acc[0], new(curve.PointAffine).Neg(
				new(curve.PointAffine).ScalarMultiplication(
					&acc[1], sk.Sk))))
	return res
}

func Calculate_TK(g *curve.PointAffine, tk *big.Int) *curve.PointAffine {
	TK := new(curve.PointAffine).ScalarMultiplication(g, tk)
	return TK
}

func Calculate_delta(data []byte, hash hash.Hash) *big.Int {
	hashfunc := hash.New()
	hashfunc.Write(data)
	_delta := hashfunc.Sum(nil)
	delta := new(big.Int).SetBytes(_delta)
	return delta
}

func Regulation_TK(cipher []curve.PointAffine, a *big.Int) []curve.PointAffine {
	c1 := new(curve.PointAffine).ScalarMultiplication(&cipher[0], a)
	c2 := new(curve.PointAffine).ScalarMultiplication(&cipher[1], a)
	return []curve.PointAffine{*c1, *c2}
}

func Sign(sk signature.Signer, msg []byte, hashFunc hash.Hash) []byte {
	hFunc := hashFunc.New()

	signature, _ := sk.Sign(msg, hFunc)
	return signature

}

func Pedersen_date(g, h *curve.PointAffine, date, r *big.Int) *curve.PointAffine {
	res := new(curve.PointAffine).Add(
		new(curve.PointAffine).ScalarMultiplication(g, date), new(curve.PointAffine).ScalarMultiplication(h, r))

	return res
}
