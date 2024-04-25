package offlinetx

import (
	"Asyn_CBDC/util"

	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	cir_eddsa "github.com/consensys/gnark/std/signature/eddsa"
)

type offlineCircuit struct {
	SigPublicKey       cir_eddsa.PublicKey `gnark:",public"`
	Signature          cir_eddsa.Signature
	Acc                util.Account
	TacSk              frontend.Variable
	Seq                frontend.Variable
	Seq1               frontend.Variable
	ExpectedDelta      frontend.Variable    `gnark:",public"`
	ExpectedDAcc       util.Account         `gnark:",public"`
	ExpectedDPublicKey twistededwards.Point `gnark:",public"`
	PrivateKey         frontend.Variable
	PublicKey          twistededwards.Point
	Alpha              frontend.Variable
	Randomness         frontend.Variable
	ExpectedCTacPk     [2]twistededwards.Point `gnark:",public"`
	PublicKeyA         twistededwards.Point    `gnark:",public"`
	RandomnessA        frontend.Variable
	A                  frontend.Variable
	ExpectedAux        twistededwards.Point `gnark:",public"`
	Comment            twistededwards.Point `gnark:",public"`
	Date               frontend.Variable
	DateSignature      cir_eddsa.Signature
	Commentr           frontend.Variable
}

func (circuit *offlineCircuit) Define(api frontend.API) error {
	//choose curve
	curvepara := ecctedwards.BN254

	curve, err := twistededwards.NewEdCurve(api, curvepara)
	if err != nil {
		return err
	}

	hashf1, err := mimc.NewMiMC(api)
	hashf2, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	msg := circuit.Acc.A.X

	// verify the signature in the cs
	result_sig := cir_eddsa.Verify(curve, circuit.Signature, msg, circuit.SigPublicKey, &hashf1)
	if result_sig != nil {
		return err
	}
	msg = circuit.Date
	date_sig := cir_eddsa.Verify(curve, circuit.DateSignature, msg, circuit.SigPublicKey, &hashf2)
	if date_sig != nil {
		return err
	}

	//delta0=mimc(tk,seq)
	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.TacSk, circuit.Seq)
	delta_0 := mimc.Sum()
	api.AssertIsEqual(delta_0, circuit.ExpectedDelta)

	//g0bal,Dpk,delta1
	_g1, _ := twistededwards.GetCurveParams(curvepara)
	g1 := twistededwards.Point{X: _g1.Base[0], Y: _g1.Base[1]}
	g1delta0 := curve.ScalarMul(g1, delta_0)

	g0bal := util.DecryptAcc(curve, circuit.Acc, circuit.PrivateKey, g1delta0)

	var dpublickey twistededwards.Point
	dpublickey = curve.ScalarMul(circuit.PublicKey, circuit.Alpha)
	api.AssertIsEqual(dpublickey.X, circuit.ExpectedDPublicKey.X)

	mimc.Reset()
	mimc.Write(circuit.TacSk, circuit.Seq1)
	delta_1 := mimc.Sum()
	g1delta1 := curve.ScalarMul(g1, delta_1)

	plaintext := curve.Add(g0bal, g1delta1)

	_h, _ := twistededwards.GetCurveParams(curvepara)
	acc := util.EncryptAcc(curve, plaintext, dpublickey, circuit.Randomness, _h)
	c1 := acc.A
	c2 := acc.B
	api.AssertIsEqual(c1.X, circuit.ExpectedDAcc.A.X)
	api.AssertIsEqual(c2.X, circuit.ExpectedDAcc.B.X)

	//TK=g2*tk
	_g2, _ := twistededwards.GetCurveParams(curvepara)
	tacpk := util.CalculateTK(curve, _g2, circuit.TacSk)

	//CTk
	_ah, _ := twistededwards.GetCurveParams(curvepara)

	cipher := util.EncryptTK(curve, tacpk, circuit.PublicKeyA, circuit.RandomnessA, _ah)

	reginfo, aux := util.RegulationTK(curve, _ah, cipher, circuit.A)

	api.AssertIsEqual(reginfo[0].X, circuit.ExpectedCTacPk[0].X)
	api.AssertIsEqual(reginfo[1].X, circuit.ExpectedCTacPk[1].X)
	api.AssertIsEqual(aux.X, circuit.ExpectedAux.X)

	_G, _ := twistededwards.GetCurveParams(curvepara)
	_H, _ := twistededwards.GetCurveParams(curvepara)
	comm := util.Pedersen(curve, _G, _H, circuit.Date, circuit.Commentr)
	api.AssertIsEqual(comm.X, circuit.Comment.X)

	return nil
}
