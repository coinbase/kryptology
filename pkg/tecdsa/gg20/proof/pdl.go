//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package proof contains the following implementations
//  - proof of discrete logarithm (PDL) subprotocol from [spec] §8
//  - multiplicative-to-additive (MtA) subprotocol from [spec] §7
//  - proof of knowledge of a discrete log modulo a composite (fig 16), i.e., ProveCompositeDL and VerifyCompositeDL
package proof

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"

	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"

	crypto "github.com/coinbase/kryptology/pkg/core"
	paillier "github.com/coinbase/kryptology/pkg/paillier"
)

// PdlProofParams encapsulates the parameters for ProvePDL in
// [spec] fig 14
type PdlProofParams struct {
	Curve               elliptic.Curve
	DealerParams        *dealer.ProofParams
	Pk                  *paillier.PublicKey
	ScalarX, ScalarR, C *big.Int
	PointX, PointR      *curves.EcPoint
}

// PdlProof is the proof generated in
// [spec] fig 14
type PdlProof struct {
	z, e, s, s1, s2 *big.Int
}

type pdlProofJSON struct {
	Z, E, S, S1, S2 *big.Int
}

func (pdlp PdlProof) MarshalJSON() ([]byte, error) {
	data := pdlProofJSON{
		Z:  pdlp.z,
		E:  pdlp.e,
		S:  pdlp.s,
		S1: pdlp.s1,
		S2: pdlp.s2,
	}
	return json.Marshal(data)
}

func (pdlp *PdlProof) UnmarshalJSON(bytes []byte) error {
	data := new(pdlProofJSON)

	err := json.Unmarshal(bytes, &data)
	if err != nil {
		return err
	}
	pdlp.z = data.Z
	pdlp.e = data.E
	pdlp.s = data.S
	pdlp.s1 = data.S1
	pdlp.s2 = data.S2

	return nil
}

// PdlVerifyParams encapsulates the parameters for VerifyPDL in
// [spec] fig 14
type PdlVerifyParams struct {
	Curve          elliptic.Curve
	DealerParams   *dealer.ProofParams
	Pk             *paillier.PublicKey
	PointX, PointR *curves.EcPoint
	C              *big.Int
}

// randPdlParams are the random values generated in
// [spec] fig 14
type randPdlParams struct {
	alpha, beta, gamma, rho *big.Int
}

// Prove generates a PdlProof as specified in
// [spec] fig 14
func (p PdlProofParams) Prove() (*PdlProof, error) {
	if p.C == nil || p.DealerParams == nil || p.PointR == nil || p.PointX == nil ||
		p.Pk == nil || p.Curve == nil || p.ScalarX == nil || p.ScalarR == nil {
		return nil, fmt.Errorf("invalid params")
	}
	// step 1
	// set N=pk.N

	// steps 2-5
	randParams, err := randPdl(p)
	if err != nil {
		return nil, err
	}

	// 6. Compute u=R^α in G
	u, err := p.PointR.ScalarMult(randParams.alpha)
	if err != nil {
		return nil, err
	}

	// 7. Compute z=h1^x h2^ρ mod N ̃
	z, err := pedersen(p.DealerParams.H1, p.DealerParams.H2, p.ScalarX, randParams.rho, p.DealerParams.N)
	if err != nil {
		return nil, err
	}

	// 8. Compute v=(N+1)^α β^N mod N^2
	v, err := inc(randParams.alpha, randParams.beta, p.Pk.N)
	if err != nil {
		return nil, err
	}

	// 9. Compute w = h1^α h2^γ mod N ̃
	w, err := pedersen(p.DealerParams.H1, p.DealerParams.H2, randParams.alpha, randParams.gamma, p.DealerParams.N)
	if err != nil {
		return nil, err
	}

	// 10. Compute e = H(pk,N~,h1,h2,g,q,R,X,c,u,z,v,w)
	challenge, err := crypto.FiatShamir(p.Pk.N, p.DealerParams.N, p.DealerParams.H1,
		p.DealerParams.H2, p.Curve.Params().Gx, p.Curve.Params().Gy,
		p.Curve.Params().N, p.PointR.X, p.PointR.Y, p.PointX.X, p.PointX.Y, p.C,
		u.X, u.Y, z, v, w)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(challenge)

	// 11. Computes s = r^e β mod N
	s, err := pedersen(p.ScalarR, randParams.beta, e, crypto.One, p.Pk.N)
	if err != nil {
		return nil, err
	}

	// 12. Compute s1 = ex + α
	s1, err := schnorr(e, p.ScalarX, randParams.alpha)
	if err != nil {
		return nil, err
	}

	// 13. Compute s2 = eρ + γ
	s2, err := schnorr(e, randParams.rho, randParams.gamma)
	if err != nil {
		return nil, err
	}

	// 14. set \Pi = [u, z, v, w, s, s1, s2]
	// 15. return \Pi
	return &PdlProof{
		z, e, s, s1, s2,
	}, nil
}

// Verify checks the PdlProof as specified in
// [spec] fig 14
func (p PdlProof) Verify(pv *PdlVerifyParams) error {
	if p.z == nil || p.e == nil || p.s1 == nil || p.s2 == nil || p.s == nil {
		return fmt.Errorf("proof values cannot be nil")
	}
	if pv == nil || pv.Curve == nil || pv.C == nil || pv.Pk == nil ||
		pv.PointX == nil || pv.PointR == nil || pv.DealerParams == nil {
		return fmt.Errorf("proof verify params cannot be nil")
	}
	// step 1
	// Set N = pk.N
	// ----

	q3, err := crypto.Exp(pv.Curve.Params().N, big.NewInt(3), nil)
	if err != nil {
		return err
	}

	// 2. If s1 > q3, Return False
	if p.s1.Cmp(q3) == 1 {
		return fmt.Errorf("s1 > q3")
	}

	// Steps 3 & 4
	uHat, err := p.uHatConstruct(pv)
	if err != nil {
		return fmt.Errorf("u hat construction error: %s", err)
	}

	// step 5
	vHat, err := p.vHatConstruct(pv)
	if err != nil {
		return fmt.Errorf("v hat construction error: %s", err)
	}

	// step 6
	wHat, err := p.wHatConstruct(pv)
	if err != nil {
		return fmt.Errorf("w hat construction error: %s", err)
	}

	// step 7
	challenge, err := crypto.FiatShamir(
		pv.Pk.N, pv.DealerParams.N, pv.DealerParams.H1, pv.DealerParams.H2,
		pv.Curve.Params().Gx, pv.Curve.Params().Gy, pv.Curve.Params().N,
		pv.PointR.X, pv.PointR.Y, pv.PointX.X, pv.PointX.Y, pv.C, uHat.X,
		uHat.Y, p.z, vHat, wHat)
	if err != nil {
		return err
	}
	eHat := new(big.Int).SetBytes(challenge)
	if !crypto.ConstantTimeEq(p.e, eHat) {
		return fmt.Errorf("e != eHat")
	}

	return nil
}

func (p PdlProof) uHatConstruct(pv *PdlVerifyParams) (*curves.EcPoint, error) {
	// 3. Compute s1' = s1 mod q
	s1Tick := new(big.Int).Mod(p.s1, pv.Curve.Params().N)

	// 4. \hat{u} = R^{s^\prime_1} . X^-e in G
	pointRtoS1Tick, err := pv.PointR.ScalarMult(s1Tick)
	if err != nil {
		return nil, err
	}
	negE := new(big.Int).Neg(p.e)
	pointXtoNegE, err := pv.PointX.ScalarMult(negE)
	if err != nil {
		return nil, err
	}
	uHat, err := pointRtoS1Tick.Add(pointXtoNegE)
	if err != nil {
		return nil, err
	}
	return uHat, err
}

func (p PdlProof) vHatConstruct(pv *PdlVerifyParams) (*big.Int, error) {
	// 5. \hat{v} = s^N . (N + 1)^s_1 . c^-e mod N^2

	// s^N . (N + 1)^s_1 mod N^2
	pedersenInc, err := inc(p.s1, p.s, pv.Pk.N)
	if err != nil {
		return nil, err
	}

	cInv, err := crypto.Inv(pv.C, pv.Pk.N2)
	if err != nil {
		return nil, err
	}
	cInvToE := new(big.Int).Exp(cInv, p.e, pv.Pk.N2)
	vHat, err := crypto.Mul(pedersenInc, cInvToE, pv.Pk.N2)
	if err != nil {
		return nil, err
	}
	return vHat, nil
}

func (p PdlProof) wHatConstruct(pv *PdlVerifyParams) (*big.Int, error) {
	// 6. \hat{w} = h_1^s_1 . h_2^s_2 . z^-e mod \tilde{N}

	// h_1^s_1 . h_2^s_2 mod \tilde{N}
	pedersenHS, err := pedersen(pv.DealerParams.H1, pv.DealerParams.H2, p.s1, p.s2, pv.DealerParams.N)
	if err != nil {
		return nil, err
	}

	zInv, err := crypto.Inv(p.z, pv.DealerParams.N)
	if err != nil {
		return nil, err
	}
	zInvToE := new(big.Int).Exp(zInv, p.e, pv.DealerParams.N)
	wHat, err := crypto.Mul(pedersenHS, zInvToE, pv.DealerParams.N)
	if err != nil {
		return nil, err
	}
	return wHat, nil
}

// randPdl computes the random values for Prove in
// [spec] fig 14
func randPdl(p PdlProofParams) (*randPdlParams, error) {
	// The rings in which to operate
	q3, err := crypto.Exp(p.Curve.Params().N, big.NewInt(3), nil)
	if err != nil {
		return nil, err
	}
	q3Ntilde := new(big.Int).Mul(q3, p.DealerParams.N)
	qNtilde := new(big.Int).Mul(p.Curve.Params().N, p.DealerParams.N)

	// 1. \alpha \getsr \Z_{q^3}
	alpha, err := crypto.Rand(q3)
	if err != nil {
		return nil, err
	}
	// 2. \beta \getsr \Z_{N*}
	beta, err := crypto.Rand(p.Pk.N)
	if err != nil {
		return nil, err
	}
	// 3. \gamma \getsr \Z_{q^3N~}
	gamma, err := crypto.Rand(q3Ntilde)
	if err != nil {
		return nil, err
	}
	// 4. \rho \getsr \Z_{qN~}
	rho, err := crypto.Rand(qNtilde)
	if err != nil {
		return nil, err
	}
	return &randPdlParams{
		alpha, beta, gamma, rho,
	}, nil
}
