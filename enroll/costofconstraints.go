package enroll

import (
	"Asyn_CBDC/util"

	"github.com/consensys/gnark-crypto/ecc"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

func T_Enroll() {
	curveid := ecctedwards.BN254

	params, _ := twistededwards.GetCurveParams(curveid)
	hashFunc := hash.MIMC_BN254

	var enroll Enroll
	enroll = enroll.Init(params, hashFunc)

	var assignment enrollCircuit
	assignment.TacSk = enroll.Tracesk.Sk
	_TK := enroll.Tracepk
	assignment.ExpectedTacPk = twistededwards.Point{X: _TK.Pk.X, Y: _TK.Pk.Y}
	assignment.Seq = enroll.Seq
	assignment.Balance = enroll.Bal
	_pk := enroll.Pk
	assignment.PublicKey = twistededwards.Point{X: _pk.Pk.X, Y: _pk.Pk.Y}
	assignment.Randomness = enroll.R
	acc := util.Account{
		A: twistededwards.Point{X: enroll.Acc[0].X, Y: enroll.Acc[0].Y},
		B: twistededwards.Point{X: enroll.Acc[1].X, Y: enroll.Acc[1].Y},
	}

	assignment.ExpectedAcc = acc

	var circuit enrollCircuit

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	proof, err := groth16.Prove(r1cs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
	//2780
	//*
}
