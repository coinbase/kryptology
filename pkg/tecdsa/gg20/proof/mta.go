//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Package proof contains the multiplicative-to-additive (MtA) subprotocol from [spec] §7

package proof

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"

	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
)

// ResponseProofParams encapsulates the values over which a range proof (2) is computed.
// [spec] §7.fig 8
type ResponseProofParams struct {
	Curve        elliptic.Curve
	DealerParams *dealer.ProofParams
	Pk           *paillier.PublicKey
	SmallB, C1   *big.Int
	B            *curves.EcPoint
}

// ResponseVerifyParams encapsulates the values over which a range proof (2) is verified.
// [spec] §7.fig 10
type ResponseVerifyParams struct {
	Curve        elliptic.Curve
	DealerParams *dealer.ProofParams
	Sk           *paillier.SecretKey
	C1           *big.Int
	B            *curves.EcPoint
}

// ResponseFinalizer captures the interface provided by a response proof
// [spec] fig 13
type ResponseFinalizer interface {
	Finalize(vp *ResponseVerifyParams) (*big.Int, error)
	FinalizeWc(vp *ResponseVerifyParams) (*big.Int, error)
}

// ResponseProof encapsulates the values over which a range proof (2) is computed
// and a portion of the random value is encrypted
// [spec] §7.fig 8
type ResponseProof struct {
	R2proof  *Range2Proof
	C2, Beta *big.Int
}

// Proof1Params encapsulates the values over which a range proof (1) is computed.
// [spec] fig 10
type Proof1Params struct {
	Curve        elliptic.Curve
	Pk           *paillier.PublicKey
	DealerParams *dealer.ProofParams
	A, C, R      *big.Int
}

// randProof1Params encapsulates the random values generated in proof (1)
// [spec] fig 10
type randProof1Params struct {
	alpha, beta, gamma, rho *big.Int
}

// Range1Proof encapsulates the results returned in proof (1)
// [spec] fig 10
type Range1Proof struct {
	z, e, s, s1, s2 *big.Int
}

// struct for JSON serialization
type range1ProofJSON struct {
	Z, E, S, S1, S2 *big.Int
}

// proof2Params encapsulates the values over which a range proof (2) is computed.
// [spec] fig 12
type proof2Params struct {
	curve           elliptic.Curve
	dealerParams    *dealer.ProofParams
	pk              *paillier.PublicKey
	y, r, c1, c2, x *big.Int
	X               *curves.EcPoint
}

// verifyProof2Params encapsulates the values over which a range proof (2) is computed.
// [spec] fig 12
type verifyProof2Params struct {
	curve        elliptic.Curve
	dealerParams *dealer.ProofParams
	pk           *paillier.PublicKey
	c1, c2       *big.Int
	X            *curves.EcPoint
}

// Range2Proof encapsulates the results returned in proof (2)
// [spec] fig 12
type randProof2Params struct {
	randProof1Params
	rhoTick, sigma, tau *big.Int
}

// Range2Proof encapsulates the values over which a range proof (2) is computed.
// [spec] fig 12
type Range2Proof struct {
	z, e, s, s1, s2 *big.Int
	t, t1, t2       *big.Int
}

// JSON struct for serialization
type range2ProofJSON struct {
	Z, E, S, S1, S2 *big.Int
	T, T1, T2       *big.Int
}

// MarshalJSON converts Range1Proof into JSON
func (r Range1Proof) MarshalJSON() ([]byte, error) {
	return json.Marshal(range1ProofJSON{
		Z:  r.z,
		E:  r.e,
		S:  r.s,
		S1: r.s1,
		S2: r.s2,
	})
}

// UnmarshalJSON converts json into a Range1Proof
func (r *Range1Proof) UnmarshalJSON(bytes []byte) error {
	var proof range1ProofJSON
	err := json.Unmarshal(bytes, &proof)
	if err != nil {
		return err
	}

	r.z = proof.Z
	r.e = proof.E
	r.s = proof.S
	r.s1 = proof.S1
	r.s2 = proof.S2
	return nil
}

// MarshalJSON converts Range2Proof into JSON format
func (rP2 Range2Proof) MarshalJSON() ([]byte, error) {
	data := range2ProofJSON{
		Z:  rP2.z,
		E:  rP2.e,
		S:  rP2.s,
		S1: rP2.s1,
		S2: rP2.s2,
		T:  rP2.t,
		T1: rP2.t1,
		T2: rP2.t2,
	}
	return json.Marshal(data)
}

// UnmarshalJSON converts json into a Range2Proof
func (rP2 *Range2Proof) UnmarshalJSON(bytes []byte) error {
	data := new(range2ProofJSON)

	err := json.Unmarshal(bytes, &data)
	if err != nil {
		return err
	}

	rP2.z = data.Z
	rP2.e = data.E
	rP2.s = data.S
	rP2.s1 = data.S1
	rP2.s2 = data.S2
	rP2.t = data.T
	rP2.t1 = data.T1
	rP2.t2 = data.T2

	return nil
}

// Prove computes a range proof over these parameters
// [spec] fig 11: MtaResponse
func (rp ResponseProofParams) Prove() (*ResponseProof, error) {
	return genResponseProof(rp, false)
}

// ProveWc computes:
// [spec] fig 11: MtaResponse_wc
func (rp ResponseProofParams) ProveWc() (*ResponseProof, error) {
	return genResponseProof(rp, true)
}

// genResponseProof computes both
// [spec] fig 11: MtAResponse and MtAResponse_wc
func genResponseProof(rp ResponseProofParams, wc bool) (*ResponseProof, error) {
	// 1. c_b = PaillierMultiply(SmallB, c_1)
	cb, err := rp.Pk.Mul(rp.SmallB, rp.C1)
	if err != nil {
		return nil, err
	}
	// 2. Set N = Pk.N

	// Draw from a smaller range to mitigate bit probing attack
	// The attack is described in section 4.1 from
	// https://info.fireblocks.com/hubfs/A_Note_on_the_Security_of_GG.pdf
	// The mitigation is described in section 3 from
	// https://eprint.iacr.org/2019/114.pdf
	// 3. \beta' = Z_{\mathbb{q5}}
	q5, err := core.Exp(rp.Curve.Params().N, big.NewInt(5), nil)
	if err != nil {
		return nil, err
	}
	betaTick, err := core.Rand(q5)
	if err != nil {
		return nil, err
	}
	// step 4
	cBeta, rBeta, err := rp.Pk.Encrypt(betaTick)
	if err != nil {
		return nil, err
	}
	// step 5
	c2, err := rp.Pk.Add(cb, cBeta)
	if err != nil {
		return nil, err
	}
	// step 6
	beta, err := core.Neg(betaTick, rp.Curve.Params().N)
	if err != nil {
		return nil, err
	}
	// step 7
	pp := proof2Params{
		curve:        rp.Curve,
		pk:           rp.Pk,
		dealerParams: rp.DealerParams,
		x:            rp.SmallB,
		y:            betaTick,
		r:            rBeta,
		c1:           rp.C1,
		c2:           c2,
		X:            rp.B,
	}
	var r2p *Range2Proof
	if wc {
		r2p, err = pp.ProveWc()
	} else {
		r2p, err = pp.Prove()
	}
	if err != nil {
		return nil, err
	}

	return &ResponseProof{
		r2p,
		c2,
		beta,
	}, nil
}

// Finalize checks a range (2) proof: [spec] fig 13: MtaFinalize
// and returns the paillier encrypted random value
func (rp ResponseProof) Finalize(vp *ResponseVerifyParams) (*big.Int, error) {
	v2Params := verifyProof2Params{
		curve:        vp.Curve,
		dealerParams: vp.DealerParams,
		pk: &paillier.PublicKey{
			N:  vp.Sk.N,
			N2: vp.Sk.N2,
		},
		c1: vp.C1,
		c2: rp.C2,
	}
	if err := rp.R2proof.Verify(&v2Params); err != nil {
		return nil, err
	}
	alpha, err := vp.Sk.Decrypt(rp.C2)
	if err != nil {
		return nil, err
	}

	return alpha.Mod(alpha, vp.Curve.Params().N), nil
}

// FinalizeWc checks a range (2) proof: [spec] fig 13: MtaFinalize_wc
// and returns the paillier encrypted random value
func (rp ResponseProof) FinalizeWc(vp *ResponseVerifyParams) (*big.Int, error) {
	v2Params := verifyProof2Params{
		curve:        vp.Curve,
		dealerParams: vp.DealerParams,
		pk: &paillier.PublicKey{
			N:  vp.Sk.N,
			N2: vp.Sk.N2,
		},
		c1: vp.C1,
		c2: rp.C2,
		X:  vp.B,
	}
	// 1. If MtaVerifyRange2_wc(...) = False, Return Error
	if err := rp.R2proof.VerifyWc(&v2Params); err != nil {
		return nil, err
	}
	// 2. Compute \alpha = Decrypt(sk, C2)
	alpha, err := vp.Sk.Decrypt(rp.C2)
	if err != nil {
		return nil, err
	}
	// 3. Return \alpha mod q
	return alpha.Mod(alpha, vp.Curve.Params().N), nil
}

// Prove computes a range proof over these parameters
// [spec] fig 10: MtaProveRange1
func (pp Proof1Params) Prove() (*Range1Proof, error) {
	if err := core.In(pp.A, pp.Curve.Params().N); err != nil {
		return nil, err
	}
	if err := core.In(pp.R, pp.Pk.N); err != nil {
		return nil, err
	}
	// Fetch our randomized values
	rp, err := rand1(pp.Pk.N, pp.DealerParams.N, pp.Curve.Params().N)
	if err != nil {
		return nil, err
	}
	// Compute and return the proof
	return genProof1(pp, rp)
}

// Fetches random values for use in range proof
// [spec] fig 10: MtaProveRange1
func rand1(N, Ntilde, q *big.Int) (*randProof1Params, error) {
	// Rings in which we'll operate
	// q^3
	q3, err := core.Exp(q, big.NewInt(3), nil)
	if err != nil {
		return nil, err
	}

	// q^3(N~)
	q3Ntilde, err := core.Mul(q3, Ntilde, nil)
	if err != nil {
		return nil, err
	}

	// q(N~)
	qNtilde, err := core.Mul(q, Ntilde, nil)
	if err != nil {
		return nil, err
	}

	// Select initial values
	// 1: \alpha \getsr Z_{q^3}
	alpha, err := core.Rand(q3)
	if err != nil {
		return nil, err
	}

	// 2: \beta \getsr Z^*_N
	beta, err := core.Rand(N)
	if err != nil {
		return nil, err
	}

	// 3: \gamma \getsr Z_{q^3N~}
	gamma, err := core.Rand(q3Ntilde)
	if err != nil {
		return nil, err
	}

	// 4: \rho \getsr Z_{q^N~}
	rho, err := core.Rand(qNtilde)
	if err != nil {
		return nil, err
	}

	// Success!
	return &randProof1Params{
		alpha, beta, gamma, rho,
	}, nil
}

// genProof1 deterministically computes a range proof
// [spec] fig 10: MtaProveRange1
func genProof1(in Proof1Params, rp *randProof1Params) (*Range1Proof, error) {
	// 6: z = h_1^a * h_2^\rho mod N~
	z, err := pedersen(in.DealerParams.H1, in.DealerParams.H2, in.A, rp.rho, in.DealerParams.N)
	if err != nil {
		return nil, err
	}

	// 7: u = (N+1)^alpha * \beta^N  mod N^2
	u, err := inc(rp.alpha, rp.beta, in.Pk.N)
	if err != nil {
		return nil, err
	}

	// 8: w = h_1^alpha & h_2^\gamma mod N~
	w, err := pedersen(in.DealerParams.H1, in.DealerParams.H2, rp.alpha, rp.gamma, in.DealerParams.N)
	if err != nil {
		return nil, err
	}

	// 9: e = H(g, q, Pk, N~, h_1, h_2, c, z, u, w)
	bytes, err := core.FiatShamir(in.Curve.Params().Gx, in.Curve.Params().Gy, in.Curve.Params().N, in.Pk.N, in.DealerParams.N, in.DealerParams.H1, in.DealerParams.H2, in.C, z, u, w)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(bytes)

	// 10: s = r^e*\beta mod N
	s, err := pedersen(in.R, rp.beta, e, core.One, in.Pk.N)
	if err != nil {
		return nil, err
	}

	// 11: s_1 = ea + \alpha
	s1, err := schnorr(e, in.A, rp.alpha)
	if err != nil {
		return nil, err
	}

	// 12: s_2 = e\rho + \gamma
	s2, err := schnorr(e, rp.rho, rp.gamma)
	if err != nil {
		return nil, err
	}

	// 13: \Pi = [z,u,w,s,s_1,s_2]
	pi := &Range1Proof{
		z:  z,
		e:  e,
		s:  s,
		s1: s1,
		s2: s2,
	}

	// 14: return \Pi
	return pi, nil
}

// Verify checks a range (1) proof: [spec] §7.fig 7: MtaVerifyRange1
func (pi Range1Proof) Verify(pp *Proof1Params) error {
	params := pp.Curve.Params()
	// Rings in which we'll operate
	q3, err := core.Exp(params.N, big.NewInt(3), nil) // q^3
	if err != nil {
		return err
	}

	// 1: Set N = pk.N

	// 2: Check range. s_1 > q^3 => return false
	if pi.s1.Cmp(q3) == 1 {
		return fmt.Errorf("s1 > q3")
	}

	// step 3
	uHat, err := pi.uHatConstruct(pp)
	if err != nil {
		return fmt.Errorf("u hat construction error: %s", err)
	}

	// step 4
	wHat, err := pi.wHatConstruct(pp)
	if err != nil {
		return fmt.Errorf("w hat construction error: %s", err)
	}

	// 5: Compute e = H(g,q,Pk,N~,h_1,h_2,c,z,uHat,wHat)
	bytes, err := core.FiatShamir(params.Gx, params.Gy, params.N, pp.Pk.N, pp.DealerParams.N, pp.DealerParams.H1, pp.DealerParams.H2, pp.C, pi.z, uHat, wHat)
	if err != nil {
		return err
	}
	eHat := new(big.Int).SetBytes(bytes)

	// 6: if e != eHat return false
	if !core.ConstantTimeEq(pi.e, eHat) {
		return fmt.Errorf("e != eHat")
	}

	// 7: return true
	return nil
}

func (pi Range1Proof) uHatConstruct(pp *Proof1Params) (*big.Int, error) {
	// 3: \hat{u} = (N+1)^{s_1}s^{N}c^{-e} mod N^2

	x, err := inc(pi.s1, pi.s, pp.Pk.N) // x = (N+1)^{s_1}(S^N) mod N^2
	if err != nil {
		return nil, err
	}
	cInv, err := core.Inv(pp.C, pp.Pk.N2) // cInv = c^{-1} mod N^2
	if err != nil {
		return nil, err
	}
	y, err := core.Exp(cInv, pi.e, pp.Pk.N2) // y = c^{-e} mod N^2
	if err != nil {
		return nil, err
	}
	uHat, err := core.Mul(x, y, pp.Pk.N2) // u' := xy = ((N+1)^{s_1}(S^N))(c^{-e}) mod N^2
	if err != nil {
		return nil, err
	}
	return uHat, nil
}

func (pi Range1Proof) wHatConstruct(pp *Proof1Params) (*big.Int, error) {
	// 4: \hat{w} = h_1^{s_1}*h_2^{s_2}*z^{-e} mod N~

	a, err := pedersen(pp.DealerParams.H1, pp.DealerParams.H2, pi.s1, pi.s2, pp.DealerParams.N) // a = h_1^{s_1}*h_2^{s_2} mod N~
	if err != nil {
		return nil, err
	}
	zInv, err := core.Inv(pi.z, pp.DealerParams.N) // zInv = z^{-1} mod N~
	if err != nil {
		return nil, err
	}
	b, err := core.Exp(zInv, pi.e, pp.DealerParams.N) // SmallB = z^{-e} mod N~
	if err != nil {
		return nil, err
	}
	wHat, err := core.Mul(a, b, pp.DealerParams.N) // wHat = ab = (h_1^{s_1}*h_2^{s_2})(z^{-e}) mod N~
	if err != nil {
		return nil, err
	}
	return wHat, nil
}

// Prove computes a range proof over these parameters
// [spec] fig 12: MtaProveRange2
func (pp proof2Params) Prove() (*Range2Proof, error) {
	randParams, err := rand2(pp.pk.N, pp.dealerParams.N, pp.curve.Params().N)
	if err != nil {
		return nil, err
	}
	return genProof2(pp, randParams, false)
}

// Prove computes a range proof over these parameters
// [spec] fig 12: MtaProveRange2_wc
func (pp proof2Params) ProveWc() (*Range2Proof, error) {
	if pp.X == nil {
		return nil, fmt.Errorf("X must have a value")
	}
	randParams, err := rand2(pp.pk.N, pp.dealerParams.N, pp.curve.Params().N)
	if err != nil {
		return nil, err
	}
	return genProof2(pp, randParams, true)
}

// genProof2 creates the proof for MtAProveRange2
func genProof2(pp proof2Params, rp *randProof2Params, wc bool) (*Range2Proof, error) {
	curveParams := pp.curve.Params()
	if err := core.In(pp.x, curveParams.N); err != nil {
		return nil, fmt.Errorf("x is not in q")
	}
	// γi ←$ Zq
	// calls MtAResponse    (γi,g, q, pkj,nTilde, h1, h2, cj) or
	// calls MtAResponse_wc (wi,g, q, pkj,nTilde, h1, h2, cj, Wi)
	// receives MtAResponse (SmallB, g, q, Pk, nTilde, h1, h2, C1)
	//1. Compute cb = PaillierMultiply(SmallB, C1 )
	//2. Choose β′ ←$ ZN
	//3. Compute (cβ,rβ) = PaillierEncryptAndReturnRandomness(Pk,β′)
	//4. Compute C2 = PaillierAdd(cb , cβ )
	//5. Compute β = −β′ mod q
	// calls    MtAProveRange2    (g, q, Pk, nTilde, h1, h2, SmallB, β ,rβ,C1, C2)
	// receives MtAProveRange2    (g, q, Pk, nTilde, h1, h2, x, y, r, C1, C2)
	// receives MtAProveRange2_wc (g, q, Pk, nTilde, h1, h2, x, y, r, C1, C2, X)

	var u *curves.EcPoint
	if wc {
		// u = g^\alpha
		ux, uy := pp.curve.ScalarBaseMult(rp.alpha.Bytes())
		u = &curves.EcPoint{
			Curve: pp.curve,
			X:     ux,
			Y:     uy,
		}
	}

	// z = h1^x * h2^rho mod N ̃
	z, err := pedersen(pp.dealerParams.H1, pp.dealerParams.H2, pp.x, rp.rho, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}

	// z' = h1^\alpha * h2^rho' mod N ̃
	zTick, err := pedersen(pp.dealerParams.H1, pp.dealerParams.H2, rp.alpha, rp.rhoTick, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}

	// t = h1^y * h2^\sigma mod N ̃
	t, err := pedersen(pp.dealerParams.H1, pp.dealerParams.H2, pp.y, rp.sigma, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}

	// v = C1^\alpha * (N + 1)^\gamma * \beta^N mod N^2
	vLhs, err := core.Exp(pp.c1, rp.alpha, pp.pk.N2)
	if err != nil {
		return nil, err
	}
	vRhs, err := inc(rp.gamma, rp.beta, pp.pk.N)
	if err != nil {
		return nil, err
	}
	v, err := core.Mul(vLhs, vRhs, pp.pk.N2)
	if err != nil {
		return nil, err
	}

	// w = h1^\gamma & h2^\tau mod N ̃
	w, err := pedersen(pp.dealerParams.H1, pp.dealerParams.H2, rp.gamma, rp.tau, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}

	var challenge []byte
	if wc {
		// g || q || Pk || N ̃ || h1 || h2 || X || C1 || C2 || u || z || z' || t || v || w
		challenge, err = core.FiatShamir(curveParams.Gx, curveParams.Gy, curveParams.N, pp.pk.N, pp.dealerParams.N, pp.dealerParams.H1, pp.dealerParams.H2, pp.X.X, pp.X.Y, pp.c1, pp.c2, u.X, u.Y, z, zTick, t, v, w)
		if err != nil {
			return nil, err
		}
	} else {
		// g || q || Pk || N ̃ || h1 || h2 || C1 || C2 || z || z' || t || v || w
		challenge, err = core.FiatShamir(curveParams.Gx, curveParams.Gy, curveParams.N, pp.pk.N, pp.dealerParams.N, pp.dealerParams.H1, pp.dealerParams.H2, pp.c1, pp.c2, z, zTick, t, v, w)
		if err != nil {
			return nil, err
		}
	}

	e := new(big.Int).SetBytes(challenge)

	// s = r^e * \beta mod N
	s, err := pedersen(pp.r, rp.beta, e, core.One, pp.pk.N)
	if err != nil {
		return nil, err
	}

	// s1 = ex + \alpha
	s1, err := schnorr(e, pp.x, rp.alpha)
	if err != nil {
		return nil, err
	}

	// s2 = e\rho + \rho'
	s2, err := schnorr(e, rp.rho, rp.rhoTick)
	if err != nil {
		return nil, err
	}

	// t1 = ey + \gamma
	t1, err := schnorr(e, pp.y, rp.gamma)
	if err != nil {
		return nil, err
	}

	// t2 = e\sigma + \tau
	t2, err := schnorr(e, rp.sigma, rp.tau)
	if err != nil {
		return nil, err
	}

	return &Range2Proof{
		z:  z,
		e:  e,
		s:  s,
		s1: s1,
		s2: s2,
		t:  t,
		t1: t1,
		t2: t2,
	}, nil
}

// Verify checks a range (2) proof: [spec] §7.fig 9: MtaVerifyRange2
func (pi Range2Proof) Verify(pp *verifyProof2Params) error {
	return verify2Proof(pi, pp, false)
}

// VerifyWc checks a range (2) proof: [spec] §7.fig 9: MtaVerifyRange2_wc
func (pi Range2Proof) VerifyWc(pp *verifyProof2Params) error {
	return verify2Proof(pi, pp, true)
}

func verify2Proof(pi Range2Proof, pp *verifyProof2Params, wc bool) error {
	// 1: Set N = pk.N

	// Rings in which we'll operate
	q3, err := core.Exp(pp.curve.Params().N, big.NewInt(3), nil) // q^3
	if err != nil {
		return err
	}

	q7, err := core.Exp(pp.curve.Params().N, big.NewInt(7), nil) // q^7
	if err != nil {
		return err
	}

	// 2: If s1 > q3, Return False
	if pi.s1.Cmp(q3) == 1 {
		return fmt.Errorf("s1 > q3")
	}

	// Mitigate bit probing attack
	// The attack is described in section 4.1 from
	// https://info.fireblocks.com/hubfs/A_Note_on_the_Security_of_GG.pdf
	// The mitigation is described in Appendix A.3 from
	// https://eprint.iacr.org/2019/114.pdf
	if pi.t1.Cmp(q7) == 1 {
		return fmt.Errorf("t1 > q7")
	}

	// steps 3 and 4 are needed only if wc: we check for X=g^x

	// step 5
	zHatTick, err := pi.zHatTickConstruct(pp)
	if err != nil {
		return fmt.Errorf("z hat tick construction error: %s", err)
	}
	// step 6
	vHat, err := pi.vHatConstruct(pp)
	if err != nil {
		return fmt.Errorf("v hat construction error: %s", err)
	}
	// step 7
	wHat, err := pi.wHatConstruct(pp)
	if err != nil {
		return fmt.Errorf("w hat construction error: %s", err)
	}

	var uHat *curves.EcPoint
	if wc {
		// steps 3, 4
		uHat, err = pi.uHatConstruct(pp)
		if err != nil {
			return fmt.Errorf("u hat construction error: %s", err)
		}
	}

	curveParams := pp.curve.Params()
	var challenge []byte
	if wc {
		// g || q || Pk || N ̃ || h1 || h2 || X || c1 || c2 || uHat || z || zHatTick || t || vHat || wHat
		challenge, err = core.FiatShamir(curveParams.Gx, curveParams.Gy, curveParams.N, pp.pk.N, pp.dealerParams.N, pp.dealerParams.H1, pp.dealerParams.H2, pp.X.X, pp.X.Y, pp.c1, pp.c2, uHat.X, uHat.Y, pi.z, zHatTick, pi.t, vHat, wHat)
		if err != nil {
			return err
		}
	} else {
		// g || q || Pk || N ̃ || h1 || h2 || c1 || c2 || z || zHatTick || t || vHat || wHat
		challenge, err = core.FiatShamir(curveParams.Gx, curveParams.Gy, curveParams.N, pp.pk.N, pp.dealerParams.N, pp.dealerParams.H1, pp.dealerParams.H2, pp.c1, pp.c2, pi.z, zHatTick, pi.t, vHat, wHat)
		if err != nil {
			return err
		}
	}

	eHat := new(big.Int).SetBytes(challenge)

	if !core.ConstantTimeEq(pi.e, eHat) {
		return fmt.Errorf("e != eHat")
	}

	return nil
}

func (pi Range2Proof) uHatConstruct(pp *verifyProof2Params) (*curves.EcPoint, error) {
	// 3. Compute s1' = s1 mod q
	s1Tick := new(big.Int).Mod(pi.s1, pp.curve.Params().N)

	// 4: \hat{u} = g^{s^\prime_1} . X^{-e} in G

	gS1Tick, err := curves.NewScalarBaseMult(pp.curve, s1Tick)
	if err != nil {
		return nil, err
	}

	negE := new(big.Int).Neg(pi.e)

	XnegE, err := pp.X.ScalarMult(negE)
	if err != nil {
		return nil, err
	}

	uHat, err := gS1Tick.Add(XnegE)
	if err != nil {
		return nil, err
	}
	return uHat, err
}

func (pi Range2Proof) zHatTickConstruct(pp *verifyProof2Params) (*big.Int, error) {
	// 5: \hat{z} = (h_1)^s_1 . (h_2)^{s_2}z^{-e} mod \tilde{N}

	// h_1^s_1 . h_2^s_2 mod \tilde{N}
	pedersenHS, err := pedersen(pp.dealerParams.H1, pp.dealerParams.H2, pi.s1, pi.s2, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}

	zInv, err := core.Inv(pi.z, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}
	zInvToE := new(big.Int).Exp(zInv, pi.e, pp.dealerParams.N)

	zHat, err := core.Mul(pedersenHS, zInvToE, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}
	return zHat, err
}

func (pi Range2Proof) vHatConstruct(pp *verifyProof2Params) (*big.Int, error) {
	// 6: \hat{v} = (c_1)^s_1 . s^N . (N+1)^t_1 . c^-e_2 mod N^2

	// s^N . (N+1)^t_1
	pedersenInc, err := inc(pi.t1, pi.s, pp.pk.N)
	if err != nil {
		return nil, err
	}

	c2Inv, err := core.Inv(pp.c2, pp.pk.N2)
	if err != nil {
		return nil, err
	}

	// c_1^s_1 . c^-e_2
	pedersenCSCE, err := pedersen(pp.c1, c2Inv, pi.s1, pi.e, pp.pk.N2)
	if err != nil {
		return nil, err
	}

	vHat, err := core.Mul(pedersenInc, pedersenCSCE, pp.pk.N2)
	if err != nil {
		return nil, err
	}
	return vHat, nil
}

func (pi Range2Proof) wHatConstruct(pp *verifyProof2Params) (*big.Int, error) {
	// 7: \hat{w} = (h_1)^t_1 . (h_2)^t_2 . t^-e mod \tilde{N}

	// h_1^t_1 . h_2^t_2 mod \tilde{N}
	pedersenHT, err := pedersen(pp.dealerParams.H1, pp.dealerParams.H2, pi.t1, pi.t2, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}

	tInv, err := core.Inv(pi.t, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}
	tInvToE := new(big.Int).Exp(tInv, pi.e, pp.dealerParams.N)

	wHat, err := core.Mul(pedersenHT, tInvToE, pp.dealerParams.N)
	if err != nil {
		return nil, err
	}
	return wHat, nil
}

// Fetches random values for use in range proof
// [spec] fig 12: MtaProveRange2
func rand2(N, Ntilde, q *big.Int) (*randProof2Params, error) {
	// Rings in which we'll operate
	q3, err := core.Exp(q, big.NewInt(3), nil) // q^3
	if err != nil {
		return nil, err
	}
	q7, err := core.Exp(q, big.NewInt(7), nil) // q^7
	if err != nil {
		return nil, err
	}
	q3Ntilde, err := core.Mul(q3, Ntilde, nil) // q^3(N~)
	if err != nil {
		return nil, err
	}
	qNtilde, err := core.Mul(q, Ntilde, nil) // q(N~)
	if err != nil {
		return nil, err
	}

	alpha, err := core.Rand(q3)
	if err != nil {
		return nil, err
	}
	rho, err := core.Rand(qNtilde)
	if err != nil {
		return nil, err
	}
	rhoTick, err := core.Rand(q3Ntilde)
	if err != nil {
		return nil, err
	}
	sigma, err := core.Rand(qNtilde)
	if err != nil {
		return nil, err
	}
	beta, err := core.Rand(N)
	if err != nil {
		return nil, err
	}

	// Draw from a smaller range to mitigate bit probing attack
	// The attack is described in section 4.1 from
	// https://info.fireblocks.com/hubfs/A_Note_on_the_Security_of_GG.pdf
	// The mitigation is described in Appendix A.3 from
	// https://eprint.iacr.org/2019/114.pdf
	gamma, err := core.Rand(q7)
	if err != nil {
		return nil, err
	}
	// Draw bigger random values to mitigate possible attack
	// from https://eprint.iacr.org/2021/1621.pdf.
	// See section 5
	tau, err := core.Rand(q3Ntilde)
	if err != nil {
		return nil, err
	}

	return &randProof2Params{
		randProof1Params: randProof1Params{
			alpha,
			beta,
			gamma,
			rho,
		},
		rhoTick: rhoTick,
		sigma:   sigma,
		tau:     tau,
	}, nil
}
