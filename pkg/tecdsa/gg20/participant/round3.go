//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"
)

// Round3Bcast represents the value to be broadcast to all players
// at the conclusion of round 3
type (
	Round3Bcast struct {
		// Note that deltaElement is some element of the entire δ vector.
		// In this round, it's δ_i. For the recepients of this message in the next round
		// this will be δ_j
		deltaElement *big.Int
		// The reason we can't do something straightforward like `type BetterRound3Bcast *big.int`
		// is that although `big.int` has some methods implementing marshaler,
		// they won't be accessible to `BetterRound3Bcast`. So the json.Marhsal uses the default methods
		// and since the two fields of `big.int` are not exported, the data of `BetterRound3Bcast`
		// won't actually be serialized and its deserialization results in nil.
	}

	Round3BcastJSON struct {
		DeltaElement *big.Int
	}
)

func (r3b Round3Bcast) MarshalJSON() ([]byte, error) {
	return json.Marshal(Round3BcastJSON{r3b.deltaElement})
}

func (r3b *Round3Bcast) UnmarshalJSON(data []byte) error {
	message := &Round3BcastJSON{}
	err := json.Unmarshal(data, message)
	if err != nil {
		return err
	}
	r3b.deltaElement = message.DeltaElement
	return nil
}

// SignRound3 performs the round 3 signing operation according to
// Trusted Dealer Mode: see [spec] fig 7: SignRound3
// DKG Mode: see [spec] fig 8: SignRound3
func (s *Signer) SignRound3(in map[uint32]*P2PSend) (*Round3Bcast, error) {
	if err := s.verifyStateMap(3, in); err != nil {
		return nil, err
	}

	// 1. Compute δ_i = k_i γ_i mod q
	deltai, err := core.Mul(s.state.ki, s.state.gammai, s.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	// 2. Compute σ_i = k_i w_i mod q
	sigmai, err := core.Mul(s.state.ki, s.share.Value.BigInt(), s.Curve.Params().N)
	if err != nil {
		return nil, err
	}

	// 3. For j=[1,...,t+1]
	verifyParams := &proof.ResponseVerifyParams{
		Curve:        s.Curve,
		DealerParams: s.state.keyGenType.GetProofParams(s.id),
		Sk:           s.sk,
		C1:           s.state.ci,
	}

	for j, value := range in {

		// 4. if i == j Continue
		if j == s.id {
			continue
		}

		if value == nil {
			return nil, fmt.Errorf("P2P message for participant %v cannot be nil", j)
		}

		// 5. Compute α_ij = MtAFinalize(g,q,sk_i,pk_i,N~,h1,h2,c_i,c_ij,π_ij)
		alphaij, err := value.Proof2.Finalize(verifyParams)

		// 6. If α_ij = ⊥, Abort
		if err != nil {
			return nil, err
		}

		// 7. Compute μ_ij = MtAFinalize_wc(g,q,sk_i,pk_i,N~,h1,h2,c_i,c_ij,π_ij,W_j)
		verifyParams.B = s.publicSharesMap[j].Point
		mu, err := value.Proof3.FinalizeWc(verifyParams)

		// 8. If μ_ij = ⊥, Abort
		if err != nil {
			return nil, err
		}

		// 9. Compute δ_i = δ_i + α_ij + β_ji  mod q
		deltai, err = core.Add(deltai, alphaij, s.Curve.Params().N)
		if err != nil {
			return nil, err
		}
		deltai, err = core.Add(deltai, s.state.betaj[j], s.Curve.Params().N)
		if err != nil {
			return nil, err
		}

		// 10. Compute σ_i = σ_i + μ_ij + ν_ji  mod q
		sigmai, err = core.Add(sigmai, mu, s.Curve.Params().N)
		if err != nil {
			return nil, err
		}
		sigmai, err = core.Add(sigmai, s.state.vuj[j], s.Curve.Params().N)
		if err != nil {
			return nil, err
		}

	}

	// 12. Return δ_i, σ_i
	// Store \delta_i, \sigma_i for future rounds
	s.state.deltai = deltai
	s.state.sigmai = sigmai

	// Increment the round counter
	s.Round = 4

	// 11. Broadcast δ_i to all other players
	return &Round3Bcast{deltai}, nil
}
