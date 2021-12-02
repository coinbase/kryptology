//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package gennaro

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/sharing/v1"

	"github.com/coinbase/kryptology/internal"
)

// Round3Bcast contains values that will be broadcast to other participants.
type Round3Bcast = v1.ShareVerifier

// Round3 computes the third round for Gennaro DKG
// Algorithm 4 - Gennaro DKG Round 3
// bcast contains all Round2 broadcast from other participants to this participant.
func (dp *Participant) Round3(bcast map[uint32]Round2Bcast) (*Round3Bcast, *v1.ShamirShare, error) {
	// Check participant is not empty
	if dp == nil || dp.curve == nil {
		return nil, nil, internal.ErrNilArguments
	}

	// Check participant has the correct dkg round number
	if dp.round != 3 {
		return nil, nil, internal.ErrInvalidRound
	}

	// Check the input is valid
	if len(bcast) == 0 {
		return nil, nil, internal.ErrNilArguments
	}

	// 1. SetBigInt Pk = R_i1
	Pk := dp.pedersenResult.Verifiers[0]

	// 2. for j in 1,...,n
	for id := range bcast {
		// 3. if i = j continue
		if id == dp.id {
			continue
		}

		// 4. If FeldmanVerify(E, xji, {R_j1,...,R_jt}) = false; abort
		xji := dp.otherParticipantShares[id].Share
		vs := bcast[id]
		if ok, err := dp.feldman.Verify(xji, vs); !ok {
			if err != nil {
				return nil, nil, err
			} else {
				return nil, nil, fmt.Errorf("invalid share for participant #{id}")
			}
		}

		// Store the feldman verifiers for round 4
		dp.otherParticipantShares[id].Verifiers = vs

		// 5. Pk = Pk+R_j1
		temp, err := Pk.Add(bcast[id][0])
		if err != nil {
			return nil, nil, fmt.Errorf("error in computing Pk+R_j1")
		} //nolint:errcheck
		Pk = temp
	}

	// This is a sanity check to make sure nothing went wrong
	// when computing the public key
	if !Pk.IsOnCurve() || Pk.IsIdentity() {
		return nil, nil, fmt.Errorf("invalid public key")
	}

	// 6. Store Pk as the public verification key
	dp.verificationKey = Pk

	// Update internal state
	dp.round = 4

	skShare := v1.ShamirShare{
		Identifier: dp.id,
		Value:      dp.skShare,
	}

	// Output Pk as the public verification key
	return Pk, &skShare, nil
}
