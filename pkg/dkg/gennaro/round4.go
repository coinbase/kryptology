//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package gennaro

import (
	"math/big"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
)

// Round4 computes the public shares used by tECDSA during signing
// that are converted to additive shares once the signing participants
// are known. This function is idempotent
func (dp *Participant) Round4() (map[uint32]*curves.EcPoint, error) {
	// Check participant is not empty
	if dp == nil || dp.curve == nil {
		return nil, internal.ErrNilArguments
	}

	// Check participant has the correct dkg round number
	if dp.round != 4 {
		return nil, internal.ErrInvalidRound
	}

	n := len(dp.otherParticipantShares) + 1 //+1 to include self
	// Wj's
	publicShares := make(map[uint32]*curves.EcPoint, n)

	// 1. R = {{R1,...,Rt},{Rij,...,Rit}i!=j}
	r := make(map[uint32][]*v1.ShareVerifier, n)
	r[dp.id] = dp.pedersenResult.Verifiers
	for j := range dp.otherParticipantShares {
		r[j] = dp.otherParticipantShares[j].Verifiers
	}

	// 2. for j in 1,...,n
	for j, v := range r {
		// 3. Wj = Pk
		publicShares[j] = &curves.EcPoint{
			Curve: dp.verificationKey.Curve,
			X:     new(big.Int).Set(dp.verificationKey.X),
			Y:     new(big.Int).Set(dp.verificationKey.Y),
		}

		// 4. for k in 1,...,t
		for k := 0; k < len(dp.pedersenResult.Verifiers); k++ {
			// 5. ck = pj * k mod q
			pj := big.NewInt(int64(j))
			ck, err := core.Mul(pj, big.NewInt(int64(k+1)), dp.curve.Params().N)
			if err != nil {
				return nil, err
			}

			// 6a. t = ck * Rj
			t, err := v[k].ScalarMult(ck)
			if err != nil {
				return nil, err
			}

			// 6b. Wj = Wj + t
			publicShares[j], err = publicShares[j].Add(t)
			if err != nil {
				return nil, err
			}
		}
	}

	return publicShares, nil
}
