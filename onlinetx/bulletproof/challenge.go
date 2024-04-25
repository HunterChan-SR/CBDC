package bulletproof

import (
	"math/big"

	"github.com/consensys/gnark-crypto/hash"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
)

func Challenge_yz(v curve.G1Affine, G curve.G1Affine, H curve.G1Affine, A curve.G1Affine, S curve.G1Affine, i int64) big.Int {
	hashFunc := hash.MIMC_BN254
	mimc := hashFunc.New()

	var data []byte
	data = append(data, v.Marshal()...)
	data = append(data, G.Marshal()...)
	data = append(data, H.Marshal()...)
	data = append(data, A.Marshal()...)
	data = append(data, S.Marshal()...)
	data = append(data, byte(i))

	mimc.Write(data)
	_res := mimc.Sum(nil)

	var res big.Int
	res.SetBytes(_res)

	return res
}

/* test */
/*func T_Challenge_yz() {
	v := new(big.Int).SetInt64(30)
	G := GeneratePoint()
	H := GeneratePoint()
	A := GeneratePoint()
	S := GeneratePoint()

	res := Challenge_yz(v, G, H, A, S, int64(1))
	fmt.Println(res)
}*/

func Challenge_x(v curve.G1Affine, G curve.G1Affine, H curve.G1Affine, A curve.G1Affine, S curve.G1Affine, T1 curve.G1Affine, T2 curve.G1Affine) big.Int {
	hashFunc := hash.MIMC_BN254
	mimc := hashFunc.New()

	var data []byte
	data = append(data, v.Marshal()...)
	data = append(data, G.Marshal()...)
	data = append(data, H.Marshal()...)
	data = append(data, A.Marshal()...)
	data = append(data, S.Marshal()...)
	data = append(data, T1.Marshal()...)
	data = append(data, T2.Marshal()...)

	mimc.Write(data)
	_res := mimc.Sum(nil)
	var res big.Int
	res.SetBytes(_res)

	return res
}
