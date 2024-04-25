package onlinetx

import (
	"Asyn_CBDC/offlinetx"
	"Asyn_CBDC/onlinetx/bulletproof"
	"Asyn_CBDC/onlinetx/sigma"
	"Asyn_CBDC/util"
	"crypto/rand"
	"math/big"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	ecctedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

type sender struct {
	dacc        offlinetx.DeriveAccount
	r_derivepk  util.Publickey
	v           big.Int  //witness,send to receiver
	beta        *big.Int //send to receiver
	r_txr       *big.Int //witness,send to receiver
	txr         transactionTX
	txs         transactionTX
	r_txs       *big.Int //witness
	bal         big.Int  //witness
	apk         util.Publickey
	r_bal       *big.Int
	r_v         *big.Int
	cipher_bal  []curve.PointAffine
	cipher_v    []curve.PointAffine
	_trans      curve.PointAffine
	h           curve.PointAffine
	dateg       curve.PointAffine
	dateh       curve.PointAffine
	commentdate curve.PointAffine
	commentr    *big.Int
	date        *big.Int
}

func (s sender) execution(params *twistededwards.CurveParams, r_txr *big.Int, r_txs *big.Int, r_pk util.Publickey, v big.Int, o offlinetx.Offline) sender {
	s.v = v
	s.dacc = o.Deriveacc
	s.r_txr = r_txr
	s.r_txs = r_txs
	s.bal = o.Bal
	s.apk = o.Apk
	s.dateg = o.CommentG
	s.dateh = o.CommentH
	s.commentdate = *o.Comment
	s.commentr = o.Commentr
	s.date = o.Date

	rb, _ := rand.Int(rand.Reader, params.Order)
	rb = rb.Add(rb, big.NewInt(int64(10))).Mod(rb, params.Order)
	rv, _ := rand.Int(rand.Reader, params.Order)
	rv = rv.Add(rv, big.NewInt(int64(10))).Mod(rv, params.Order)
	s.r_bal = rb
	s.r_v = rv

	plain := new(curve.PointAffine).ScalarMultiplication(&s.dacc.G0, &s.v)

	_txs := s.dacc.Keypair.DPk.Encrypt(plain, s.r_txs, s.dacc.H)
	s.txs = transactionTX{
		A: _txs[0],
		B: _txs[1],
	}

	beta, _ := rand.Int(rand.Reader, params.Order)
	s.beta = beta
	_pkr := new(curve.PointAffine).ScalarMultiplication(&r_pk.Pk, beta)
	s.r_derivepk = util.Publickey{Pk: *_pkr}

	_txr := s.r_derivepk.Encrypt(plain, s.r_txr, s.dacc.H)
	s.txr = transactionTX{
		A: _txr[0],
		B: _txr[1],
	}

	var _trans curve.PointAffine
	_trans.X.SetBigInt(params.Base[0])
	_trans.Y.SetBigInt(params.Base[1])
	s._trans = _trans
	aplain_bal := new(curve.PointAffine).ScalarMultiplication(&_trans, &s.bal)
	aplain_v := new(curve.PointAffine).ScalarMultiplication(&_trans, &s.v)
	var h curve.PointAffine
	h.X.SetBigInt(params.Base[0])
	h.Y.SetBigInt(params.Base[1])
	s.h = h
	s.cipher_bal = s.apk.Encrypt(aplain_bal, s.r_bal, s.h)
	s.cipher_v = s.apk.Encrypt(aplain_v, s.r_v, s.h)
	return s
}

func (s sender) sigmaprotocol(params *twistededwards.CurveParams, curveid ecctedwards.ID) (sigmaProof, sender, time.Duration) {
	//simulation receiver
	hashFunc := hash.MIMC_BN254
	var receiver_bal big.Int
	receiver_bal.SetString("200", 10)
	var receiver offlinetx.PrimitiveAccount
	receiver = receiver.GetAccount(params, hashFunc, receiver_bal, big.NewInt(1))
	r_pk := receiver.Pk

	/* */
	var v big.Int
	v.SetString("100", 10)

	r_txr, _ := rand.Int(rand.Reader, params.Order)
	r_txr = r_txr.Add(r_txr, big.NewInt(int64(10))).Mod(r_txr, params.Order)
	r_txs, _ := rand.Int(rand.Reader, params.Order)
	r_txs = r_txs.Add(r_txs, big.NewInt(int64(10))).Mod(r_txs, params.Order)

	var o offlinetx.Offline
	o = o.Execution(params, hashFunc, curveid)

	s = s.execution(params, r_txr, r_txs, r_pk, v, o)

	/* */
	starttime := time.Now()

	var commit sigma.CommitMent
	para_sh := commit.ParamsGen(params)
	para_rh := commit.ParamsGen(params)
	para_s := commit.ParamsGen(params)
	para_r := commit.ParamsGen(params)
	para_date := commit.ParamsGen(params)
	para_dater := commit.ParamsGen(params)

	para_bal := commit.ParamsGen(params)
	para_bal_r := commit.ParamsGen(params)
	para_v := commit.ParamsGen(params)
	para_v_r := commit.ParamsGen(params)

	commit_sh := commit.Commitmul(para_sh, &s.dacc.H)
	commit_rh := commit.Commitmul(para_rh, &s.dacc.H)
	commit_s := commit.Commitmuladd(para_sh, para_s, s.dacc.Keypair.DPk.Pk, s.dacc.G0)
	commit_r := commit.Commitmuladd(para_rh, para_r, s.r_derivepk.Pk, s.dacc.G0)
	commit_date := commit.Commitmuladd(para_date, para_dater, s.dateg, s.dateh)

	commit_bal := commit.CommitencValid(para_bal, para_bal_r, s.apk, s.h, s._trans)
	commit_v := commit.CommitencValid(para_v, para_v_r, s.apk, s.h, s._trans)

	hash := hashFunc.New()

	var data []byte
	data = append(data, commit_sh.Commit.Marshal()...)
	data = append(data, commit_rh.Commit.Marshal()...)
	data = append(data, commit_s.Commit.Marshal()...)
	data = append(data, commit_r.Commit.Marshal()...)
	data = append(data, s.txs.A.Marshal()...)
	data = append(data, s.txs.B.Marshal()...)
	data = append(data, s.txr.A.Marshal()...)
	data = append(data, s.txr.B.Marshal()...)
	data = append(data, commit_date.Commit.Marshal()...)
	data = append(data, s.commentdate.Marshal()...)
	data = append(data, commit_bal[0].Marshal()...)
	data = append(data, commit_bal[1].Marshal()...)
	data = append(data, commit_v[0].Marshal()...)
	data = append(data, commit_v[1].Marshal()...)

	hash.Write(data)
	_challenge := hash.Sum(nil)
	var challenge big.Int
	challenge.SetBytes(_challenge)

	var rp_sr sigma.Response
	rp_sr = rp_sr.Response(para_sh, challenge, s.r_txs)
	var rp_rr sigma.Response
	rp_rr = rp_rr.Response(para_rh, challenge, s.r_txr)
	var rp_sv sigma.Response
	rp_sv = rp_sv.Response(para_s, challenge, &s.v)
	var rp_rv sigma.Response
	rp_rv = rp_rv.Response(para_r, challenge, &s.v)
	var rp_bal sigma.Response
	rp_bal = rp_bal.Response(para_bal, challenge, &s.bal)
	var rp_v sigma.Response
	rp_v = rp_v.Response(para_v, challenge, &s.v)
	var rp_bal_r sigma.Response
	rp_bal_r = rp_bal_r.Response(para_bal_r, challenge, s.r_bal)
	var rp_v_r sigma.Response
	rp_v_r = rp_v_r.Response(para_v_r, challenge, s.r_v)

	var rp_date sigma.Response
	rp_date = rp_date.Response(para_date, challenge, s.date)
	var rp_dater sigma.Response
	rp_dater = rp_dater.Response(para_dater, challenge, s.commentr)

	endtime := time.Now()

	//fmt.Println("sigma----generate commitment,challenge,response cost:", endtime.Sub(starttime))

	return (sigmaProof{
		commit: []sigma.CommitMent{
			commit_s, commit_sh, commit_r, commit_rh, commit_date,
		},
		commitenc: [][]curve.PointAffine{
			commit_bal,
			commit_v,
		},
		response: []sigma.Response{
			rp_sr, rp_rr, rp_sv, rp_rv, rp_bal, rp_bal_r, rp_v, rp_v_r, rp_date, rp_dater,
		},
		challenge: challenge,
	}), s, endtime.Sub(starttime)
}

func (_ sender) zkpProof(params *twistededwards.CurveParams, curveid ecctedwards.ID, frmodulus *big.Int) (sender, sigmaProof, bulletProof, bulletProof, bulletProof, bulletProof, int64) {
	var s sender
	var sigmaproof sigmaProof
	var t_sigmagen time.Duration
	sigmaproof, s, t_sigmagen = s.sigmaprotocol(params, curveid)
	v := s.v
	bal_v := s.bal.Sub(&s.bal, &s.v)

	var bpPara bulletproof.BulletParams
	bpPara = bpPara.ParamsGen()

	var bp1 bulletProof
	var t_bp1 time.Duration
	bp1, t_bp1 = bp1.rangeproof(&v, bpPara)
	var bp2 bulletProof
	var t_bp2 time.Duration
	bp2, t_bp2 = bp2.rangeproof(bal_v, bpPara)
	var holding bulletProof
	var t_holding time.Duration
	holding, t_holding = holding.rangeproof(big.NewInt(200), bpPara)
	var date bulletProof
	var t_date time.Duration
	date, t_date = date.rangeproof(big.NewInt(200), bpPara)

	var totalzkptime int64
	totalzkptime = t_sigmagen.Microseconds() + t_bp1.Microseconds() + t_bp2.Microseconds() + t_holding.Microseconds() + t_date.Microseconds()
	return s, sigmaproof, bp1, bp2, holding, date, totalzkptime
}
