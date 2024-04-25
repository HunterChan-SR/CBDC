package offlinetx

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

func T_OfflineTx() {
	curveid := ecctedwards.BN254

	hashFunc := hash.MIMC_BN254
	params, _ := twistededwards.GetCurveParams(curveid)

	var offline Offline
	offline = offline.Execution(params, hashFunc, curveid)

	var circuit offlineCircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	pk, vk, err := groth16.Setup(r1cs)

	var assignment offlineCircuit

	acc_c1 := offline.OldAcc[0]
	acc_c2 := offline.OldAcc[1]
	acc := util.Account{
		A: twistededwards.Point{X: acc_c1.X, Y: acc_c1.Y},
		B: twistededwards.Point{X: acc_c2.X, Y: acc_c2.Y},
	}
	assignment.Acc = acc
	assignment.TacSk = offline.Tracesk.Sk
	assignment.Seq = offline.Oldseq
	assignment.Seq1 = offline.Newseq
	assignment.ExpectedDelta = offline.Delta

	dacccipher := offline.Deriveacc.Acc
	dacc_c1 := dacccipher[0]
	dacc_c2 := dacccipher[1]
	dacc := util.Account{
		A: twistededwards.Point{X: dacc_c1.X, Y: dacc_c1.Y},
		B: twistededwards.Point{X: dacc_c2.X, Y: dacc_c2.Y},
	}
	assignment.ExpectedDAcc = dacc
	assignment.ExpectedDPublicKey = twistededwards.Point{
		X: offline.Deriveacc.Keypair.DPk.Pk.X,
		Y: offline.Deriveacc.Keypair.DPk.Pk.Y,
	}
	assignment.PrivateKey = offline.Sk.Sk
	assignment.PublicKey = twistededwards.Point{X: offline.Pk.Pk.X, Y: offline.Pk.Pk.Y}
	assignment.Alpha = offline.Deriveacc.Keypair.Deriver
	assignment.Randomness = offline.Deriveacc.R
	var ctacpk [2]twistededwards.Point
	ctacpk[0] = twistededwards.Point{X: offline.CipherTk[0].X, Y: offline.CipherTk[0].Y}
	ctacpk[1] = twistededwards.Point{X: offline.CipherTk[1].X, Y: offline.CipherTk[1].Y}
	assignment.ExpectedCTacPk = ctacpk
	assignment.PublicKeyA = twistededwards.Point{X: offline.Apk.Pk.X, Y: offline.Apk.Pk.Y}
	assignment.RandomnessA = offline.Ar
	assignment.A = offline.A
	assignment.ExpectedAux = twistededwards.Point{
		X: offline.Aux.X,
		Y: offline.Aux.Y,
	}
	assignment.Date = offline.Date
	assignment.Comment = twistededwards.Point{
		X: offline.Comment.X,
		Y: offline.Comment.Y,
	}
	assignment.Commentr = offline.Commentr

	_sigpublicKey := offline.Sigpk.Bytes()
	assignment.SigPublicKey.Assign(curveid, _sigpublicKey[:32])
	assignment.Signature.Assign(curveid, offline.Signature)
	assignment.DateSignature.Assign(curveid, offline.DateSignature)

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, err := witness.Public()
	proof, err := groth16.Prove(r1cs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}

	/* test */
	/*var _g1delta3 curve.PointAffine
	_g1delta3.ScalarMultiplication(&offline.G1, &offline.Delta)
	var _g0bal curve.PointAffine
	_g0bal.ScalarMultiplication(&offline.G0, &offline.Bal)
	_privatekey := offline.Sk.Sk
	privatekey := util.Privatekey{Sk: _privatekey}

	g0bal := privatekey.Decryptacc(offline.OldAcc, _g1delta3)

	fmt.Println("test encrypt and decrypt:", g0bal.Equal(&_g0bal))*/

	/*_c1x := offline.OldAcc[0].X*/
	//_c2x := acccipher.B.X
	/*c1x := _c1x.Bytes()*/
	//c2x := _c2x.Bytes()
	/*var _msg []byte
	_msg = append(_msg, c1x[:]...)*/
	//var msg []byte
	//msg = append(msg, c2x[:]...)

	/* test */
	/*sigpublicKey := offline.Sigpk
	isValid, _ := sigpublicKey.Verify(offline.Signature, _msg, hashFunc.New())
	if !isValid {
		fmt.Println("1. invalid signature")
	} else {
		fmt.Println("1. valid signature")
	}*/

	/* test */
	/*var _g1delta4 curve.PointAffine
	_g1delta4.ScalarMultiplication(&offline.G1, &delta_4)
	var dplaintext curve.PointAffine
	dplaintext.Add(&_g1delta4, &g0bal)
	dg0bal := Dacc.Keypair.DSk.Decryptacc(Dacc.Acc, _g1delta4)
	fmt.Println("test encrypt and decrypt:(DAcc)", dg0bal.Equal(&g0bal))*/
}
