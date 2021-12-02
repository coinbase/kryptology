//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
)

// Round4Bcast are the values to be broadcast to the other players at the conclusion
// of signing round 4
type Round4Bcast struct {
	Witness *core.Witness
}

// SignRound4 performs the round 4 signing operation. It takes input
// the delta_j values broadcast from signers at the conclusion of
// round 3.
// Trusted Dealer Mode: see [spec] fig 7: SignRound4
// DKG Mode: see [spec] fig 8: SignRound4
func (s *Signer) SignRound4(deltas map[uint32]*Round3Bcast) (*Round4Bcast, error) {
	var err error
	if err = s.verifyStateMap(4, deltas); err != nil {
		return nil, err
	}

	// 1. Set δ = δ_i
	delta := new(big.Int).Set(s.state.deltai)

	// 2. For j=[1,...,t+1]
	for j, deltaj := range deltas {
		// 3. If i = j, Continue
		if j == s.id {
			continue
		}

		// 4. Compute δ = δ + δ_j mod q
		delta, err = core.Add(delta, deltaj.deltaElement, s.Curve.Params().N)
		if err != nil {
			return nil, err
		}
	}

	// 6. Return δ
	// Store δ as signer state
	s.state.delta = delta

	// Increment our round counter on success
	s.Round = 5

	// 5. Broadcast D_i to all other players
	return &Round4Bcast{
		s.state.Di,
	}, nil
}
