//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// This file contains proofs that Paillier moduli are square-free: [spec] fig 15

package paillier

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/internal"
	crypto "github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// [spec] 10.2 and ProvePSF, VerifyPSF fig.15
const PsfProofLength = 13

// PsfProofParams contains the inputs to ProvePSF
type PsfProofParams struct {
	Curve     elliptic.Curve
	SecretKey *SecretKey
	Pi        uint32
	Y         *curves.EcPoint
}

// PsfVerifyParams contains the inputs to VerifyPSF
type PsfVerifyParams struct {
	Curve     elliptic.Curve
	PublicKey *PublicKey
	Pi        uint32
	Y         *curves.EcPoint
}

// PsfProof is a slice of 13 big.Int's that prove that a Paillier modulus is square-free
type PsfProof []*big.Int

// Prove that a Paillier modulus is square-free
// [spec] §10.fig 15
func (p *PsfProofParams) Prove() (PsfProof, error) {
	// Verify that params are sane
	if p.Curve == nil ||
		p.SecretKey == nil ||
		p.Pi == 0 ||
		p.Y == nil {
		return nil, internal.ErrNilArguments
	}

	// 1. ell = 13
	// Note this is set above as PsfProofLength

	// 2. M = N^{-1} mod \phi(N)
	M, err := crypto.Inv(p.SecretKey.N, p.SecretKey.Totient)
	if err != nil {
		return nil, err
	}

	// 3. [x_1, ..., x_ell] <- GenerateChallenges(g,q,y,Pi,ell)
	// NOTE: spec doesn't include N, but it's an oversight--should be part of the
	// commitment
	x, err := generateChallenges(p.Curve.Params(), p.SecretKey.N, p.Pi, p.Y)
	if err != nil {
		return nil, err
	}
	if len(x) != PsfProofLength {
		return nil, fmt.Errorf("Challenges array is not correct length: want=%v got=%v", PsfProofLength, len(x))
	}

	// 4. For i = [1, ... \ell]
	// NOTE: typo in spec: says j = ... but uses subscript i in loop
	proof := make([]*big.Int, PsfProofLength)
	for i, xj := range x {
		// 5. Compute y_i = x_i^M mod N
		// NOTE: the pseudocode shows mod phi(N) which is incorrect
		// it should be mod N otherwise the reverse in Verify
		// will fail. Using phi(N) puts M in the wrong group.
		yi, err := crypto.Exp(xj, M, p.SecretKey.N)
		if err != nil {
			return nil, err
		}

		// 6. Set \Pi = [y_1, ..., y_\ell]
		// NOTE: typo in spec: says y_t not y_\ell
		proof[i] = yi
	}

	// 7. return \Pi
	return proof, nil
}

// Verify that a Paillier modulus is square-free
// [spec] §10.fig 15
func (p PsfProof) Verify(psf *PsfVerifyParams) error {
	// Verify that params are sane
	if psf == nil ||
		psf.Curve == nil ||
		psf.PublicKey == nil ||
		psf.Pi == 0 ||
		psf.Y == nil {
		return internal.ErrNilArguments
	}

	// 1. ell = 13
	// Note this is set above as PsfProofLength

	// 2. t = 1000
	// NOTE not used anywhere

	// 3. if q|N return false
	if new(big.Int).Mod(psf.PublicKey.N, psf.Curve.Params().N).Cmp(crypto.Zero) == 0 {
		return fmt.Errorf("paillier public key is a multiple of the curve subgroup")
	}

	// 4. [x_1, ..., x_ell] <- GenerateChallenges(g,q,y,Pi,ell)
	// NOTE: spec doesn't include N, but it's an oversight--should be part of the
	// commitment
	x, err := generateChallenges(psf.Curve.Params(), psf.PublicKey.N, psf.Pi, psf.Y)
	if err != nil {
		return err
	}
	if len(x) != PsfProofLength {
		return fmt.Errorf("challenges array is not correct length: want=%v got=%v", PsfProofLength, len(x))
	}

	// 5. for j in [1,...,l]
	for j, xj := range x {
		// 6. yj^N != x mod N return false
		// NOTE: pseudocode uses i when loop uses j
		lhs, err := crypto.Exp(p[j], psf.PublicKey.N, psf.PublicKey.N)
		if err != nil {
			return err
		}
		if lhs.Cmp(xj) != 0 {
			return fmt.Errorf("not equal at %d", j)
		}
	}

	return nil
}

// generateChallenges computes `l` deterministic numbers as
// challenges for PsfProof which proves that the Paillier modulus is square free
// [spec] fig.15 GenerateChallenges
func generateChallenges(params *elliptic.CurveParams, N *big.Int, pi uint32, y *curves.EcPoint) ([]*big.Int, error) {
	if params == nil ||
		y == nil ||
		pi == 0 {
		return nil, internal.ErrNilArguments
	}

	// 1. Set b = |N| // bit length of N
	b := N.BitLen()

	// a modulus that is too small turns this function into an infinite loop
	// need at least a byte to guarantee termination
	if b < 8 {
		return nil, internal.ErrNilArguments
	}

	// 2. h = output bit-length of fiat-shamir hash
	// See util.fiatShamir which uses sha256
	// So the output bit-length is 256 bits
	const h int = 256

	// 3. Compute s = ⌈b/h⌉ // number of hash outputs required to obtain b bits
	// i.e. the number of times we have to call fs-shamir to get the same bits as
	// `b`. Compute ceil as ceilVal = (a+b-1) / b
	s := int64((b + h - 1) / h)

	// 4. j = 0
	j := int64(0)

	// 5. m = 0
	m := big.NewInt(0)

	x := make([]*big.Int, PsfProofLength)

	Pi := new(big.Int).SetUint64(uint64(pi))
	// 6. while j ≤ l
	for j < PsfProofLength {

		bij := big.NewInt(j)
		var ej []byte

		// 7. for k = [1,...,s]
		for k := int64(1); k <= s; k++ {
			bik := big.NewInt(k)

			// 8. Compute e_jk = FS-HASH(g, q, y, p_i, j, k, m)
			res, err := crypto.FiatShamir(params.Gx, params.Gy, params.N, y.X, y.Y, Pi, bij, bik, m)
			if err != nil {
				return nil, err
			}
			// 9. Set x_j = eJ1 || ... || eJs
			// Pseudocode says to concatenate outside this loop
			// however, we just concatenate the bytes now instead of storing as temporary
			// variables
			ej = append(ej, res...)
		}
		// 10. Truncate ej to b bits
		xj := new(big.Int).SetBytes(ej[:b/8])

		// 11. if x_j < Z_N* i.e. 0 < x_j and x_j < N
		if xj.Cmp(crypto.Zero) == 1 && xj.Cmp(N) == -1 {
			x[j] = xj

			// 12 j = j + 1
			j++
			// 13 m = 0
			m = big.NewInt(0)
			// 14 else
		} else {
			// 15. Set m = m + 1
			m.Add(m, crypto.One)
		}
	}
	return x, nil
}
