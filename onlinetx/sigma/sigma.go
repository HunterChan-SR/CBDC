package sigma

import (
	"Asyn_CBDC/util"
	"crypto/rand"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type CommitParams struct {
	r *big.Int
}

type CommitMent struct {
	Commit curve.PointAffine
}

type Response struct {
	Rp big.Int
}

func (c CommitMent) ParamsGen(params *twistededwards.CurveParams) CommitParams {
	r, _ := rand.Int(rand.Reader, params.Order)
	r = r.Add(r, big.NewInt(int64(10))).Mod(r, params.Order)
	return CommitParams{r: r}
}
func (c CommitMent) Commitmul(params CommitParams, g *curve.PointAffine) CommitMent {
	r := params.r

	commit := new(curve.PointAffine).ScalarMultiplication(g, r)
	return CommitMent{Commit: *commit}
}
func (c CommitMent) Commitmuladd(params1 CommitParams, params2 CommitParams, g1 curve.PointAffine, g2 curve.PointAffine) CommitMent {
	r1 := params1.r
	r2 := params2.r

	commit := new(curve.PointAffine).Add(new(curve.PointAffine).ScalarMultiplication(&g1, r1), new(curve.PointAffine).ScalarMultiplication(&g2, r2))

	return CommitMent{Commit: *commit}
}
func (c CommitMent) CommitencValid(tb CommitParams, tr CommitParams, pk util.Publickey, h curve.PointAffine, g curve.PointAffine) []curve.PointAffine {
	Cipher := pk.Encrypt(new(curve.PointAffine).ScalarMultiplication(&g, tb.r), tr.r, h)
	return Cipher
}
func (r Response) Response(params CommitParams, challenge big.Int, witness *big.Int) Response {
	res := new(big.Int).Add(params.r, new(big.Int).Mul(&challenge, witness))
	return Response{Rp: *res}
}
