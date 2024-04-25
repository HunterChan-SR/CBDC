package enroll

import (
	"Asyn_CBDC/util"

	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

type enrollCircuit struct {
	ExpectedAcc   util.Account         `gnark:",public"`
	PublicKey     twistededwards.Point `gnark:",public"`
	Balance       frontend.Variable    `gnark:",public"`
	Randomness    frontend.Variable
	ExpectedTacPk twistededwards.Point `gnark:",public"`
	TacSk         frontend.Variable
	Seq           frontend.Variable
}

func (circuit *enrollCircuit) Define(api frontend.API) error {
	//choose curve
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	//TK=g2*tk
	_g2, _ := twistededwards.GetCurveParams(curvepara)
	tacpk := util.CalculateTK(curve, _g2, circuit.TacSk)
	api.AssertIsEqual(tacpk.X, circuit.ExpectedTacPk.X)

	//delta0=mimc(tk,seq)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	_g1, _ := twistededwards.GetCurveParams(curvepara)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}

	plaintext := curve.ScalarMul(g1, delta_0)

	_h, _ := twistededwards.GetCurveParams(curvepara)
	acc0 := util.EncryptAcc(curve, plaintext, circuit.PublicKey, circuit.Randomness, _h)
	c1 := acc0.A
	c2 := acc0.B

	api.AssertIsEqual(c1.X, circuit.ExpectedAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedAcc.B.X)

	return nil
}
