package util

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type Account struct {
	A twistededwards.Point
	B twistededwards.Point
}

func CalculateTK(curve twistededwards.Curve, g *twistededwards.CurveParams, tk frontend.Variable) twistededwards.Point {
	G := twistededwards.Point{X: g.Base[0], Y: g.Base[1]}

	TK := curve.ScalarMul(G, tk)
	return TK
}

// acc=(g0*bal+(g1*delta0)+r*pk,r*h),bal=_
func EncryptAcc(curve twistededwards.Curve, plain twistededwards.Point, pk twistededwards.Point, r frontend.Variable, g *twistededwards.CurveParams) Account {
	c1 := curve.Add(plain, curve.ScalarMul(pk, r))
	H := twistededwards.Point{X: g.Base[0], Y: g.Base[1]}
	c2 := curve.ScalarMul(H, r)
	return Account{c1, c2}
}

func DecryptAcc(curve twistededwards.Curve, cipher Account, sk frontend.Variable, delta twistededwards.Point) twistededwards.Point {
	_plain := curve.Add(cipher.A, curve.Neg(curve.ScalarMul(cipher.B, sk)))
	_delta := curve.Neg(delta)

	return curve.Add(_plain, _delta)
}

func EncryptTK(curve twistededwards.Curve, TK twistededwards.Point, pk twistededwards.Point, r frontend.Variable, g *twistededwards.CurveParams) []twistededwards.Point {
	c1 := curve.Add(TK, curve.ScalarMul(pk, r))

	h := twistededwards.Point{X: g.Base[0], Y: g.Base[1]}
	c2 := curve.ScalarMul(h, r)
	return []twistededwards.Point{c1, c2}
}

func RegulationTK(curve twistededwards.Curve, g *twistededwards.CurveParams, cipher []twistededwards.Point, a frontend.Variable) ([]twistededwards.Point, twistededwards.Point) {
	c1 := curve.ScalarMul(cipher[0], a)
	c2 := curve.ScalarMul(cipher[1], a)

	h := twistededwards.Point{X: g.Base[0], Y: g.Base[1]}
	aux := curve.ScalarMul(h, a)

	return []twistededwards.Point{c1, c2}, aux
}

func Pedersen(curve twistededwards.Curve, G, H *twistededwards.CurveParams, date, r frontend.Variable) twistededwards.Point {
	h := twistededwards.Point{X: H.Base[0], Y: H.Base[1]}
	g := twistededwards.Point{X: G.Base[0], Y: G.Base[1]}
	res := curve.Add(curve.ScalarMul(g, date), curve.ScalarMul(h, r))
	return res
}
