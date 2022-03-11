//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"fmt"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"
)

// DkgRound2Bcast contains value that will be echo broadcast to all other players.
type DkgRound2Bcast struct {
	Di *core.Witness
}

// DkgRound2P2PSend contains value that will be P2PSend to all other player Pj
type DkgRound2P2PSend struct {
	xij *v1.ShamirShare
}

// DkgRound2 implements distributed key generation round 2
// [spec] fig 5: DistKeyGenRound2
func (dp *DkgParticipant) DkgRound2(params map[uint32]*DkgRound1Bcast) (*DkgRound2Bcast, map[uint32]*DkgRound2P2PSend, error) {
	// Make sure dkg participant is not empty
	if dp == nil || dp.Curve == nil {
		return nil, nil, internal.ErrNilArguments
	}

	// Check DkgParticipant has the correct dkg round number
	if err := dp.verifyDkgRound(2); err != nil {
		return nil, nil, err
	}

	// Check the total number of parties
	cnt := 0
	for id := range params {
		if params[id] == nil {
			continue
		}
		if id == dp.id {
			continue
		}
		cnt++
	}
	if uint32(cnt) != dp.state.Limit-1 {
		return nil, nil, internal.ErrIncorrectCount
	}

	// Initiate P2P channel to other parties
	p2PSend := make(map[uint32]*DkgRound2P2PSend)

	// Initiate two CdlVerifyParams that will be used in CDL verification.
	cdlParams1 := proof.CdlVerifyParams{
		Curve: dp.Curve,
	}
	cdlParams2 := proof.CdlVerifyParams{
		Curve: dp.Curve,
	}

	dp.state.otherParticipantData = make(map[uint32]*dkgParticipantData)

	// For j = [1...n]
	expKeySize := 2 * paillier.PaillierPrimeBits
	for id, param := range params {
		// If i = j, Continue
		if id == dp.id {
			continue
		}

		// Mitigate possible attack from
		// https://eprint.iacr.org/2021/1621.pdf
		// by checking that paillier keys are the correct size
		// See section 5
		bitlen := param.Pki.N.BitLen()
		if bitlen != expKeySize &&
			bitlen != expKeySize-1 {
			return nil, nil, fmt.Errorf("invalid paillier keys")
		}

		// If VerifyCompositeDL(pi_1j^CDL, g, q, h1j, h2j, tildeN_j) = False, Abort
		cdlParams1.H1 = param.H1i
		cdlParams1.H2 = param.H2i
		cdlParams1.N = param.Ni
		if err := param.Proof1i.Verify(&cdlParams1); err != nil {
			return nil, nil, err
		}

		// If VerifyCompositeDL(pi_2j^CDL, g, q, h2j, h1j, tildeN_j) = False, Abort
		// Note the position of h1j and h2j, they are reversed in the second verification!
		cdlParams2.H1 = param.H2i
		cdlParams2.H2 = param.H1i
		cdlParams2.N = param.Ni
		if err := param.Proof2i.Verify(&cdlParams2); err != nil {
			return nil, nil, err
		}

		// P2PSend xij to player Pj
		if dp.state.X == nil || dp.state.X[id-1] == nil {
			return nil, nil, fmt.Errorf("Missing Shamir share to P2P send")
		}
		p2PSend[id] = &DkgRound2P2PSend{
			xij: dp.state.X[id-1],
		}

		// Store other parties data
		dp.state.otherParticipantData[id] = &dkgParticipantData{
			PublicKey:  param.Pki,
			Commitment: param.Ci,
			ProofParams: &dealer.ProofParams{
				N:  param.Ni,
				H1: param.H1i,
				H2: param.H2i,
			},
		}
	}

	// Assign dkg round to 3
	dp.Round = 3

	// EchoBroadcast Di to all other players. Also return it with P2PSend
	return &DkgRound2Bcast{
		Di: dp.state.D,
	}, p2PSend, nil

}
