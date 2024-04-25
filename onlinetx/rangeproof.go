package onlinetx

import (
	"Asyn_CBDC/onlinetx/bulletproof"
	"crypto/rand"
	"math/big"
	"time"

	eccfr "github.com/consensys/gnark-crypto/ecc/bn254"
)

func (bp bulletProof) rangeproof(num *big.Int, bpPara bulletproof.BulletParams) (bulletProof, time.Duration) {
	v := num

	n := bpPara.N
	P := bpPara.P
	G := bpPara.G
	H := bpPara.H
	g := bpPara.Bg
	h := bpPara.Bh
	bp.bpPara = bpPara

	gamma, _ := rand.Int(rand.Reader, P)

	commitV := bulletproof.Commit(g, h, v, gamma)
	bp.commitV = commitV

	/* */
	starttime := time.Now()

	//generate commitA
	alpha, _ := rand.Int(rand.Reader, P)
	aL, _ := bulletproof.Generate_a_L(v, n)
	aR := bulletproof.Generate_a_R(aL)
	_commitA := bulletproof.CommitVectors(G, H, aL, aR)
	_commitA1 := bulletproof.CommitSingle(h, alpha)
	var commitA eccfr.G1Affine
	commitA.Add(&_commitA, &_commitA1)
	bp.commitA = commitA

	//generate commitS
	rho, _ := rand.Int(rand.Reader, P)
	sL := bulletproof.Generate_s(n)
	sR := bulletproof.Generate_s(n)
	_commitS := bulletproof.CommitVectors(G, H, sL, sR)
	_commitS1 := bulletproof.CommitSingle(h, rho)
	var commitS eccfr.G1Affine
	commitS.Add(&_commitS, &_commitS1)
	bp.commitS = commitS

	//generate challenge y,z
	y := bulletproof.Challenge_yz(commitV, g, h, commitA, commitS, int64(1))
	z := bulletproof.Challenge_yz(commitV, g, h, commitA, commitS, int64(2))
	bp.chall_y = y
	bp.chall_z = z

	//generate commitT1,commitT2
	tau1, _ := rand.Int(rand.Reader, P)
	tau2, _ := rand.Int(rand.Reader, P)
	//t1,t2
	yn := bulletproof.GenerateY(y, n)
	srYn := bulletproof.CalHadamardVec(sR, yn)
	//t2
	t2 := bulletproof.Inner_produ(sL, srYn)
	//t1
	sum := big.NewInt(0)
	//t11
	y2n := bulletproof.Generate2n(n)
	sl2n := bulletproof.Inner_produ(sL, y2n)
	z2 := big.NewInt(0)
	z2.Mul(&z, &z)
	z2.Mod(z2, P)
	t11 := big.NewInt(0)
	t11.Mul(z2, sl2n)
	t11.Mod(t11, P)
	//t12
	t12 := bulletproof.Inner_produ(sL, bulletproof.CalHadamardVec(yn, aR))
	//t13
	t13 := bulletproof.Inner_produ(bulletproof.CalVectorTimes(sL, &z), yn)
	//t14
	t14 := bulletproof.Inner_produ(bulletproof.CalVectorSub(aL, bulletproof.GenerateZ(z, n)), bulletproof.CalHadamardVec(yn, sR))
	_sum := big.NewInt(0)
	_sum.Add(t11, t12)
	_sum.Mod(_sum, P)
	sum.Add(t13, t14)
	sum.Mod(sum, P)
	t1 := big.NewInt(0)
	t1.Add(sum, _sum)
	t1.Mod(t1, P)
	commitT1 := bulletproof.Commit(g, h, t1, tau1)
	commitT2 := bulletproof.Commit(g, h, t2, tau2)
	bp.commitT1 = commitT1
	bp.commitT2 = commitT2

	//generate challenge x
	x := bulletproof.Challenge_x(commitV, g, h, commitA, commitS, commitT1, commitT2)
	bp.chall_x = x

	//generate response
	taux := bulletproof.Calculate_taux(tau1, tau2, x, z, gamma)
	miu := bulletproof.Calculate_miu(alpha, rho, x)
	lx := bulletproof.Calculate_lx(aL, z, n, sL, x)
	rx := bulletproof.Calculate_rx(yn, aR, z, n, sR, x)
	tx := bulletproof.Calculate_tx(lx, rx)
	bp.rp_taux = taux
	bp.rp_miu = miu
	bp.rp_lx = lx
	bp.rp_rx = rx
	bp.rp_tx = tx

	endtime := time.Now()

	//fmt.Println("bp----generate commitment,challenge,response cost:", endtime.Sub(starttime))

	return bp, endtime.Sub(starttime)
}
