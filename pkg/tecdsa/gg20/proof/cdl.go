//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Package proof contains the proof of knowledge of a discrete log modulo a composite (fig 16), i.e., ProveCompositeDL and VerifyCompositeDL

package proof

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"math/big"

	mod "github.com/coinbase/kryptology/pkg/core"
)

const ell = 128

// CdlProofParams encapsulates parameters for ProveCompositeDL in Fig.16
// Curve contains EC group generator g and EC group modulus q
// Pi, Qi are small p_i, q_i s.t. P_i = 2p_i+1, Q_i = 2q_i+1, which are Safe Primes
// ScalarX is a random element from Z_N~ and it should be kept as secret
// N is the field modulus
type CdlProofParams struct {
	Curve                      elliptic.Curve
	Pi, Qi, H1, H2, ScalarX, N *big.Int
}

type CdlProof struct {
	u, s []*big.Int
}

// U, S are small u, s in JSON format
type cdlProofJSON struct {
	U, S []*big.Int
}

func (cdlp CdlProof) MarshalJSON() ([]byte, error) {
	data := cdlProofJSON{
		U: cdlp.u,
		S: cdlp.s,
	}
	return json.Marshal(data)
}

func (cdlp *CdlProof) UnmarshalJSON(bytes []byte) error {
	data := new(cdlProofJSON)

	err := json.Unmarshal(bytes, &data)
	if err != nil {
		return err
	}
	cdlp.u = data.U
	cdlp.s = data.S
	return nil
}

type CdlVerifyParams struct {
	Curve     elliptic.Curve
	H1, H2, N *big.Int
}

// Prove generates a CdlProof as specified in
// [spec] §10.fig 16
func (p CdlProofParams) Prove() (*CdlProof, error) {
	if p.Curve == nil || p.H1 == nil || p.H2 == nil || p.Pi == nil || p.Qi == nil || p.ScalarX == nil || p.N == nil {
		return nil, fmt.Errorf("invalid params")
	}

	// Step 1
	// Set ell = 128

	// Step 2-4, create a array of alpha_i, prod = p_i*q_i
	prod := new(big.Int).Mul(p.Pi, p.Qi)
	alpha := make([]*big.Int, ell)
	fsInput := make([]*big.Int, ell+6)
	fsInput[0] = p.Curve.Params().Gx
	fsInput[1] = p.Curve.Params().Gy
	fsInput[2] = p.Curve.Params().N
	fsInput[3] = p.N
	fsInput[4] = p.H1
	fsInput[5] = p.H2

	for i := 6; i < ell+6; i++ {
		a, err := mod.Rand(prod)
		if err != nil {
			return nil, err
		}
		alpha[i-6] = a
		fsInput[i], err = mod.Exp(p.H1, a, p.N) // In the pseudocode, there is a typo which uses h, but it should be h_1 instead
		if err != nil {
			return nil, err
		}
	}
	// 5. Compute e = FS-HASH(g,q,N,h_1,h_2,[u_1...u_ell]
	challenge, err := mod.FiatShamir(fsInput...)
	if err != nil {
		return nil, err
	}
	e := new(big.Int).SetBytes(challenge)
	// Step 6-7. For i=[1...ell], compute s_i = alpha_i+x*e_i mod pq
	s := make([]*big.Int, ell)
	pq := new(big.Int).Mul(p.Pi, p.Qi)
	for i := 0; i < ell; i++ {
		ei := big.NewInt(int64(e.Bit(i)))
		s[i] = new(big.Int).Mod(new(big.Int).Add(alpha[i], new(big.Int).Mul(ei, p.ScalarX)), pq)
	}

	// 8. Set \Pi = [(u1,s1),...,(u_ell, s_ell)]
	// 9. Return \Pi
	u := fsInput[6:]
	return &CdlProof{
		u, s,
	}, nil
}

// Verify checks the CdlProof as specified in
// [spec] §10.fig 16
func (p CdlProof) Verify(cv *CdlVerifyParams) error {
	if p.u == nil || p.s == nil {
		return fmt.Errorf("proof values cannot be nil")
	}

	if cv == nil || cv.Curve == nil || cv.H1 == nil || cv.H2 == nil || cv.N == nil {
		return fmt.Errorf("proof verify params cannot be nil")
	}

	// When you multiply two numbers m and n, the number of bits in the product cannot be less than max(m,n) and cannot be more than (m+n).
	// (Unless one of the two numbers is a 0).
	if cv.N.BitLen() < 1024 {
		return fmt.Errorf("Modulus length is invalid")
	}

	// Step 1
	// Set ell = 128

	// 2. Compute e = FS-HASH(g,q,N,h1,h2,[u1,...,u_ell])
	fsInput := make([]*big.Int, ell+6)
	fsInput[0] = cv.Curve.Params().Gx
	fsInput[1] = cv.Curve.Params().Gy
	fsInput[2] = cv.Curve.Params().N
	fsInput[3] = cv.N
	fsInput[4] = cv.H1
	fsInput[5] = cv.H2
	copy(fsInput[6:], p.u)
	challenge, err := mod.FiatShamir(fsInput...)
	if err != nil {
		return err
	}

	e := new(big.Int).SetBytes(challenge)

	// Step 3-4
	for i := 0; i < ell; i++ {
		ei := big.NewInt(int64(e.Bit(i)))
		left := new(big.Int).Exp(cv.H1, p.s[i], cv.N)
		right := new(big.Int).Mod(new(big.Int).Mul(p.u[i], new(big.Int).Exp(cv.H2, ei, cv.N)), cv.N)
		if left.Cmp(right) != 0 {
			return fmt.Errorf("h1^si != ui*h2^ei")
		}
	}

	// Step 5
	return nil
}
