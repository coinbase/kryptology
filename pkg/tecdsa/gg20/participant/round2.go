//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"encoding/json"
	"math/big"

	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
)

// P2PSend is all the values that need to be sent to each player
type P2PSend struct {
	Proof2, Proof3 proof.ResponseFinalizer
}

// UnmarshalJSON explicitly unmarshals into ResponseProofs instead of ResponsFinalizer interface
func (p2ps *P2PSend) UnmarshalJSON(bytes []byte) error {
	// Temporary struct used to explicitly unmarshal into ResponseProofs instead of ResponseFinalizer
	data := struct {
		Proof2, Proof3 proof.ResponseProof
	}{}

	err := json.Unmarshal(bytes, &data)
	if err != nil {
		return err
	}

	p2ps.Proof2 = data.Proof2
	p2ps.Proof3 = data.Proof3

	return nil
}

// SignRound2 performs round 2 signing operations for a single signer
// Trusted Dealer Mode: see [spec] fig 7: SignRound2
// DKG Mode: see [spec] fig 8: SignRound2
func (signer *Signer) SignRound2(params map[uint32]*Round1Bcast, p2p map[uint32]*Round1P2PSend) (map[uint32]*P2PSend, error) {
	if err := signer.verifyStateMap(2, params); err != nil {
		return nil, err
	}
	// In dearlerless version, p2p map must contain one message from each cosigner.
	if !signer.state.keyGenType.IsTrustedDealer() {
		if err := signer.verifyStateMap(2, p2p); err != nil {
			return nil, err
		}
	}

	cnt := signer.threshold - 1
	p2PSend := make(map[uint32]*P2PSend, cnt)
	signer.state.betaj = make(map[uint32]*big.Int, cnt)
	signer.state.vuj = make(map[uint32]*big.Int, cnt)
	signer.state.cj = make(map[uint32]paillier.Ciphertext, cnt)
	signer.state.Cj = make(map[uint32]core.Commitment, cnt)

	// This is outside the loop for efficiency since the only changing value is the
	// params ciphertext
	pp := &proof.Proof1Params{
		Curve:        signer.Curve,
		DealerParams: signer.state.keyGenType.GetProofParams(signer.id),
	}
	rpp := proof.ResponseProofParams{
		Curve: signer.Curve,
		B:     signer.publicSharesMap[signer.id].Point,
	}

	// 1. For j = [1 ... t+1]
	for j, param := range params {
		// 2. if i == j, continue
		if param == nil || j == signer.id {
			continue
		}

		// 3. if MtAVerifyRange(\pi_j^{Range1}, g, q, N~, h1, h2, c_j) == False then Abort
		pp.Pk = signer.state.pks[j]
		pp.C = param.Ctxt

		if signer.state.keyGenType.IsTrustedDealer() {
			if err := param.Proof.Verify(pp); err != nil {
				return nil, err
			}
		} else {
			// The case using DKG, verify range proof in P2PSend
			if err := p2p[j].Verify(pp); err != nil {
				return nil, err
			}
		}

		// 4. Compute c^{\gamma}_{ji}, \beta_{ji}, \pi^{Range2}_{ji} = MtaResponse(γ_i,g,q,pk_j,N~,h1,h2,c_j)
		rpp.C1 = param.Ctxt
		rpp.DealerParams = signer.state.keyGenType.GetProofParams(j)
		rpp.SmallB = signer.state.gammai
		rpp.Pk = signer.state.pks[j]
		proofGamma, err := rpp.Prove()
		if err != nil {
			return nil, err
		}

		// 5. Compute c^{w}_{ji}, \vu_{ji}, \pi^{Range3}_{ji} = MtaResponse_wc(w_i,W_i,g,q,pk_j,N~,h1,h2,c_j)
		rpp.SmallB = signer.share.Value.BigInt()
		proofW, err := rpp.ProveWc()
		if err != nil {
			return nil, err
		}

		// Store the values for later rounds
		signer.state.cj[j] = param.Ctxt
		signer.state.betaj[j] = proofGamma.Beta
		signer.state.vuj[j] = proofW.Beta
		signer.state.Cj[j] = param.C

		// Beta and vu are not sent to other signers
		proofGamma.Beta = nil
		proofW.Beta = nil

		// 6. P2PSend(c^{gamma}_{ji}, c_^{W}_{ji}, \pi^{Range2}_{ji}, \pi^{Range3}_{ji})
		p2PSend[j] = &P2PSend{
			Proof2: proofGamma,
			Proof3: proofW,
		}
	}
	signer.Round = 3
	return p2PSend, nil
}
