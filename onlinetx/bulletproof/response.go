package bulletproof

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Calculate_lx(aL []*big.Int, z big.Int, n int64, sL []*big.Int, x big.Int) []*big.Int {
	var lx []*big.Int
	lx = CalVectorAdd(CalVectorSub(aL, GenerateZ(z, n)), CalVectorTimes(sL, &x))
	return lx
}

/* test */
/*func T_calculatelx() {
	n := int64(32)
	v := new(big.Int).SetInt64(30)
	al, _ := Generate_a_L(v, n)

	G := GeneratePoint()
	H := GeneratePoint()
	A := GeneratePoint()
	S := GeneratePoint()
	T1 := GeneratePoint()
	T2 := GeneratePoint()

	z := Challenge_yz(v, G, H, A, S, int64(1))

	params, _ := twistededwards.GetCurveParams(ecct.BN254)
	sl := Generate_s(params, n)

	x := Challenge_x(v, G, H, A, S, T1, T2)

	lx := Calculate_lx(al, z, n, sl, x)

	fmt.Println(lx)
}*/

func Calculate_rx(yn []*big.Int, aR []*big.Int, z big.Int, n int64, sR []*big.Int, x big.Int) []*big.Int {
	P = fr.Modulus()
	var rx []*big.Int
	z2 := big.NewInt(0)
	z2.Mul(&z, &z)
	z2.Mod(z2, P)
	rx = CalVectorAdd(CalHadamardVec(yn, CalVectorAdd(aR, CalVectorAdd(GenerateZ(z, n), CalVectorTimes(sR, &x)))), CalVectorTimes(Generate2n(n), z2))
	return rx
}

/* test */
/*func T_calculaterx() {
	n := int64(32)
	v := new(big.Int).SetInt64(30)
	al, _ := Generate_a_L(v, n)
	ar := Generate_a_R(al)

	G := GeneratePoint()
	H := GeneratePoint()
	A := GeneratePoint()
	S := GeneratePoint()
	T1 := GeneratePoint()
	T2 := GeneratePoint()

	y := Challenge_yz(v, G, H, A, S, int64(1))
	z := Challenge_yz(v, G, H, A, S, int64(2))

	params, _ := twistededwards.GetCurveParams(ecct.BN254)
	sr := Generate_s(params, n)

	x := Challenge_x(v, G, H, A, S, T1, T2)

	yn := GenerateY(y, n)
	res := Calculate_rx(yn, ar, z, n, sr, x)

	fmt.Println(res)

}*/

// <lx,rx>
func Calculate_tx(l []*big.Int, r []*big.Int) *big.Int {
	return Inner_produ(l, r)
}

// taux
func Calculate_taux(tau1 *big.Int, tau2 *big.Int, x big.Int, z big.Int, gamma *big.Int) *big.Int {
	P = fr.Modulus()
	x2 := big.NewInt(0)
	x2.Mul(&x, &x)
	x2.Mod(x2, P)
	z2 := big.NewInt(0)
	z2.Mul(&z, &z)
	z2.Mod(z2, P)
	_taux := big.NewInt(0)
	_taux.Add(x2.Mul(x2, tau2), z2.Mul(z2, gamma))
	_taux.Mod(_taux, P)
	taux := big.NewInt(0)
	taux.Mul(tau1, &x)
	taux.Add(_taux, taux)
	taux.Mod(taux, P)
	return taux
}

// miu
func Calculate_miu(alpha *big.Int, rho *big.Int, x big.Int) *big.Int {
	P = fr.Modulus()
	_rhox := big.NewInt(0)
	_rhox.Mul(rho, &x)
	_rhox.Mod(_rhox, P)
	miu := big.NewInt(0)
	miu.Add(alpha, _rhox)
	miu.Mod(miu, P)
	return miu
}
