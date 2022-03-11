//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package gennaro

import (
	"fmt"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
)

type Round2Bcast = []*v1.ShareVerifier

// Round2 computes the second round for Gennaro DKG
// Algorithm 3 - Gennaro DKG Round 2
// bcast contains all Round1 broadcast from other participants to this participant
// p2p contains all Round1 P2P send message from other participants to this participant
func (dp *Participant) Round2(bcast map[uint32]Round1Bcast, p2p map[uint32]*Round1P2PSendPacket) (Round2Bcast, error) {

	// Check participant is not empty
	if dp == nil || dp.curve == nil {
		return nil, internal.ErrNilArguments
	}

	// Check participant has the correct dkg round number
	if dp.round != 2 {
		return nil, internal.ErrInvalidRound
	}

	// Check the input is valid
	if bcast == nil || p2p == nil || len(bcast) == 0 || len(p2p) == 0 {
		return nil, internal.ErrNilArguments
	}

	// 1. set sk = x_{ii}
	sk := dp.pedersenResult.SecretShares[dp.id-1].Value

	// 2. for j in 1,...,n
	for id := range bcast {

		// 3. if i = j continue
		if id == dp.id {
			continue
		}

		// Ensure a valid p2p entry exists
		if p2p[id] == nil {
			return nil, fmt.Errorf("missing p2p packet for id=%v", id)
		}

		// 4. If PedersenVerify(E, Q, x_ji, r_ji, {X_ji,...,X_jt}) = false, abort
		xji := p2p[id].SecretShare
		rji := p2p[id].BlindingShare
		bvs := bcast[id]
		if ok, err := dp.pedersen.Verify(xji, rji, bvs); !ok {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("invalid share for participant id=%v", id)
			}
		}

		// Store other participants' shares xji for usage in round 3
		dp.otherParticipantShares[id].Share = p2p[id].SecretShare

		// 5. sk = (sk+xji) mod q
		// NOTE: we use the EcScalar class to add instead of
		// just using big.Int Add and Mod
		// because Ed25519 will fail with the big.Int Add and Mod
		// and Ed25519 uses different little endian vs big endian
		// in big.Int
		t1 := sk.BigInt()
		t2 := xji.Value.BigInt()
		r := dp.scalar.Add(t1, t2)

		sk = sk.Field().NewElement(r)
	}

	// Update internal state
	dp.round = 3

	// 7. Store ski as participant i's secret key share
	dp.skShare = sk

	// 6. EchoBroadcast {R_1,...,R_t} to all other participants.
	return dp.pedersenResult.Verifiers, nil
}
