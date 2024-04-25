package bulletproof

import (
	"crypto/rand"
	"errors"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var P *big.Int

// inner product a,b
func Inner_produ(a []*big.Int, b []*big.Int) *big.Int {
	P = fr.Modulus()
	var sum *big.Int
	sum = big.NewInt(0)
	for key, _ := range a {
		var tmp *big.Int
		tmp = big.NewInt(0)
		tmp.Mul(a[key], b[key])
		tmp.Mod(tmp, P)
		sum.Add(sum, tmp)
		sum.Mod(sum, P)
	}
	return sum
}

/* test */
/*func T_innerpro() {
	var a []*big.Int
	t := big.NewInt(1)
	a = append(a, t)
	t = big.NewInt(2)
	a = append(a, t)

	var b []*big.Int
	t = big.NewInt(3)
	b = append(b, t)
	t = big.NewInt(1)
	b = append(b, t)

	res := Inner_produ(a, b)
	fmt.Println(res)
}*/

// generate a_L vector for v<=2^n-1
func Generate_a_L(v *big.Int, n int64) ([]*big.Int, error) {
	var a_L []*big.Int
	max := big.NewInt(1)

	//v>2^n-1
	max.Exp(big.NewInt(2), big.NewInt(n), nil)
	if v.Cmp(max) > -1 {
		return nil, errors.New("invalid v!")
	}

	for i := n; i > 0; i-- {
		temp := big.NewInt(1)
		a_L = append(a_L, big.NewInt(int64(temp.Mod(v, big.NewInt(2)).Cmp(big.NewInt(0)))))
		v.Div(v, big.NewInt(2))
	}

	return a_L, nil
}

/* test */
/*func T_aL() {
	v := new(big.Int).SetInt64(30)
	var aL []*big.Int
	aL, _ = Generate_a_L(v, 32)
	fmt.Println(aL)
}*/

// generate a_R=a_L-1
func Generate_a_R(a_L []*big.Int) (a_R []*big.Int) {
	for _, value := range a_L {
		a_R = append(a_R, addInP(value, negBig(big.NewInt(1))))
	}
	return a_R
}

/* test */
/*func T_aR() {
	fmt.Println("rp:")
	v := new(big.Int).SetInt64(130)
	var aL []*big.Int
	aL, _ = Generate_a_L(v, 32)
	fmt.Println("aL:", aL)

	var aR []*big.Int
	aR = Generate_a_R(aL)
	fmt.Println("aR:", aR)
}*/

// generate s_L s_R
func Generate_s(n int64) []*big.Int {
	var s []*big.Int
	for i := n; i > 0; i-- {
		/*random big int*/
		var r *big.Int
		r, _ = rand.Int(rand.Reader, fr.Modulus())
		s = append(s, r)
	}

	return s
}

/* test */
/*func T_s() {
	params, _ := twistededwards.GetCurveParams(ecct.BN254)
	s := Generate_s(params, 32)
	fmt.Println(s)
}*/

func GenerateY(y big.Int, n int64) []*big.Int {
	P = fr.Modulus()
	var yVector []*big.Int
	var i int64 = 1
	yVector = append(yVector, big.NewInt(1))
	for ; i < n; i++ {
		var tmp big.Int
		tmp.Mul(yVector[i-1], &y)
		tmp.Mod(&tmp, P)
		yVector = append(yVector, &tmp)
	}
	return yVector
}

/* test */
/*func T_Y() {
	v := new(big.Int).SetInt64(30)
	G := GeneratePoint()
	H := GeneratePoint()
	A := GeneratePoint()
	S := GeneratePoint()

	y := Challenge_yz(v, G, H, A, S, int64(1))

	res := GenerateY(y, int64(6))

	fmt.Println("y:", y)
	fmt.Println("res:", res)
}*/

func Generate2n(n int64) []*big.Int {
	P = fr.Modulus()
	var yVector []*big.Int
	var i int64 = 1
	yVector = append(yVector, big.NewInt(1))
	for ; i < n; i++ {
		var tmp big.Int
		tmp.Mul(yVector[i-1], big.NewInt(2))
		tmp.Mod(&tmp, P)
		yVector = append(yVector, &tmp)
	}
	return yVector
}

/* test */
/*func T_2n() {
	res := Generate2n(10)
	fmt.Println(res)
}*/

func GenerateZ(z big.Int, n int64) []*big.Int {
	var zVector []*big.Int
	for i := n; i > 0; i-- {
		zVector = append(zVector, &z)
	}
	return zVector
}

func GenerateZ1(z big.Int, n int64) []*big.Int {
	P = fr.Modulus()
	var z1Vector []*big.Int
	var z1 *big.Int
	z1 = big.NewInt(1)
	z1.Neg(&z)
	z1.Mod(z1, P)
	for i := n; i > 0; i-- {
		z1Vector = append(z1Vector, z1)
	}
	return z1Vector
}

/* test */
/*func T_Z() {
	v := new(big.Int).SetInt64(30)
	G := GeneratePoint()
	H := GeneratePoint()
	A := GeneratePoint()
	S := GeneratePoint()

	z := Challenge_yz(v, G, H, A, S, int64(1))

	res := GenerateZ(z, int64(6))

	fmt.Println("z:", z.Bytes())
	fmt.Println("res:", res)
}*/

func GenerateH1(H []curve.G1Affine, y big.Int, n int64, order *big.Int) []curve.G1Affine {
	yn := GenerateY(y, n)
	var h1 []curve.G1Affine
	for key, value := range H {
		var tmp curve.G1Affine
		var yinv *big.Int
		yinv = big.NewInt(0)
		yinv = inverseBig(yn[key])
		tmp.ScalarMultiplication(&value, yinv)
		h1 = append(h1, tmp)
	}
	return h1
}

// sub(vector_a,vector_b)
func CalVectorSub(a []*big.Int, b []*big.Int) []*big.Int {
	P = fr.Modulus()
	var c []*big.Int

	for key, _ := range a {
		var tmp *big.Int
		tmp = big.NewInt(0)
		tmp.Sub(a[key], b[key])
		tmp.Mod(tmp, P)
		c = append(c, tmp)
	}
	return c
}

/* test */
/*func T_sub() {
	var a *big.Int
	var b *big.Int
	a = big.NewInt(1)
	b = big.NewInt(3)
	a.Sub(b, a)
	fmt.Println("a:", a)
}*/

// add(vector_a,vector_b)
func CalVectorAdd(a []*big.Int, b []*big.Int) []*big.Int {
	P = fr.Modulus()
	var c []*big.Int

	for key, _ := range a {
		var tmp *big.Int
		tmp = big.NewInt(0)
		tmp.Add(a[key], b[key])
		tmp.Mod(tmp, P)
		c = append(c, tmp)
	}
	return c
}

// a*vector_b
func CalVectorTimes(a []*big.Int, b *big.Int) []*big.Int {
	P = fr.Modulus()
	var c []*big.Int

	for key, _ := range a {
		var tmp *big.Int
		tmp = big.NewInt(0)
		tmp.Mul(a[key], b)
		tmp.Mod(tmp, P)
		c = append(c, tmp)
	}
	return c
}

func CalHadamardVec(a []*big.Int, b []*big.Int) []*big.Int {
	P = fr.Modulus()
	var c []*big.Int

	for key, _ := range a {
		var tmp *big.Int
		tmp = big.NewInt(0)
		tmp.Mul(a[key], b[key])
		tmp.Mod(tmp, P)
		c = append(c, tmp)
	}

	return c
}

func addInP(a *big.Int, b *big.Int) *big.Int {
	var m, n fr.Element
	c := big.NewInt(0)

	m.SetInterface(a)
	n.SetInterface(b)

	m.Add(&m, &n)
	mbyte := m.Bytes()
	c.SetBytes(mbyte[:])
	return c
}

func inverseBig(a *big.Int) *big.Int {
	var m fr.Element
	b := big.NewInt(0)
	m.SetInterface(a)
	m.Inverse(&m)
	mbyte := m.Bytes()
	b.SetBytes(mbyte[:])
	return b
}

func negBig(a *big.Int) *big.Int {
	var m fr.Element
	b := big.NewInt(0)
	m.SetInterface(a)
	m.Neg(&m)
	mbyte := m.Bytes()
	b.SetBytes(mbyte[:])
	return b
}
