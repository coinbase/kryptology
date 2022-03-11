//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"fmt"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"
)

// Round5Bcast are the values to be broadcast to the other players at the conclusion
// of signing round 5
type Round5Bcast struct {
	Rbar  *curves.EcPoint
	Proof *proof.PdlProof
}

// Round5P2PSend are the values sent to each participant at the conclusion of
// signing round 5
type Round5P2PSend = proof.PdlProof

// SignRound5 performs the round 5 signing operation. It takes input
// the Witness values broadcast from signers at the conclusion of
// round 4.
// Trusted Dealer Mode: see [spec] fig 7: SignRound5
// DKG Mode: see [spec] fig 8: SignRound5
func (signer *Signer) SignRound5(witnesses map[uint32]*Round4Bcast) (*Round5Bcast, map[uint32]*Round5P2PSend, error) {
	if err := signer.verifyStateMap(5, witnesses); err != nil {
		return nil, nil, err
	}

	// 1. Compute R = g^{γ_i} in G
	R := signer.state.Gammai

	// 2. For j = [1,...,t+1]
	for j, d := range witnesses {
		if d == nil {
			return nil, nil, fmt.Errorf("input witnesses cannot be nil")
		}
		// 3. If i == j, continue
		if j == signer.id {
			continue
		}

		// FUTURE: match commitment with identifier instead of index
		// 4. Compute Γ_j = Open(C_j , D_j)
		ok, err := core.Open(signer.state.Cj[j], *d.Witness)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			return nil, nil, fmt.Errorf("commitment couldn't be opened")
		}

		// 5. If Γ_j = ⊥, Abort
		Gammaj, err := curves.PointFromBytesUncompressed(signer.Curve, d.Witness.Msg)
		if err != nil {
			return nil, nil, err
		}

		// 6. Compute R = R · Γ_j in G
		R, err = R.Add(Gammaj)
		if err != nil {
			return nil, nil, err
		}
	}

	// 7. Compute R= R^{δ^{−1}} in G
	deltaInv, err := core.Inv(signer.state.delta, signer.Curve.Params().N)
	if err != nil {
		return nil, nil, err
	}
	R, err = R.ScalarMult(deltaInv)
	if err != nil {
		return nil, nil, err
	}

	// 9. Compute \overline{R_i} = R^{k_i}
	Rbari, err := R.ScalarMult(signer.state.ki)
	if err != nil {
		return nil, nil, err
	}

	// Sanity check
	Rbark, err := R.ScalarMult(signer.state.sigmai)
	if err != nil {
		return nil, nil, err
	}

	bcast := &Round5Bcast{Rbari, nil}
	p2p := make(map[uint32]*Round5P2PSend)
	pdlParams := proof.PdlProofParams{
		Curve:   signer.Curve,
		Pk:      &signer.sk.PublicKey,
		ScalarX: signer.state.ki,
		PointX:  Rbari,
		C:       signer.state.ci,
		ScalarR: signer.state.ri,
		PointR:  R,
	}

	if signer.state.keyGenType.IsTrustedDealer() {
		// 10. TrustedDealer - Compute π^{kCONSIST}_i = ProvePDL(g, q, R, pk_i, N~, h1, h2, k_i, \overline{R_i}, c_i, r_i)
		pdlParams.DealerParams = signer.state.keyGenType.GetProofParams(0) //note ID is ignored for trusted dealer
		bcast.Proof, err = pdlParams.Prove()
		if err != nil {
			return nil, nil, err
		}
	} else {
		// 10. DKG - for j = [1,...,t+1]
		for id := range signer.state.cosigners {
			// 11. DKG if i == j, continue
			if signer.id == id {
				continue
			}
			pdlParams.DealerParams = signer.state.keyGenType.GetProofParams(id)
			if pdlParams.DealerParams == nil {
				return nil, nil, fmt.Errorf("no proof params found for cosigner %d", id)
			}
			// 12. DKG - Compute π^{kCONSIST}_ij = ProvePDL(g, q, R, pk_i, N~_j, h1_j, h2_j, k_i, \overline{R_i}, c_i, r_i)
			pdl, err := pdlParams.Prove()
			if err != nil {
				return nil, nil, err
			}
			// 13. P2PSend π^{kCONSIST}_ij to Pj
			p2p[id] = pdl
		}
	}

	// Used in Round 6
	signer.state.R = R

	// 8. Set r = R_x
	signer.state.r = R.X

	// 12. Set \overline{R}_i
	signer.state.Rbari = Rbari
	signer.state.Rbark = Rbark

	signer.Round = 6

	// 11. TrustedDealer - Broadcast {R_i, π^{kCONSIST}_i} to all other players
	// 13. DKG - Broadcast R_i to all other players, P2PSend π^{kCONSIST}_ij
	return bcast, p2p, nil
}
