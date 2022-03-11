//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package gennaro

import (
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
)

// Round1Bcast are the values that are broadcast to all other participants
// after round1 completes
type Round1Bcast = []*v1.ShareVerifier

// Round1P2PSend are the values that are sent to individual participants based
// on the id
type Round1P2PSend = map[uint32]*Round1P2PSendPacket

// Round1P2PSendPacket are the shares generated from the secret for a specific participant
type Round1P2PSendPacket struct {
	SecretShare   *v1.ShamirShare
	BlindingShare *v1.ShamirShare
}

// Round1 computes the first round for the DKG
// `secret` can be nil
// NOTE: if `secret` is nil, a new secret is generated which creates a new key
// if `secret` is set, then this performs key resharing aka proactive secret sharing update
func (dp *Participant) Round1(secret []byte) (Round1Bcast, Round1P2PSend, error) {
	if dp.round != 1 {
		return nil, nil, internal.ErrInvalidRound
	}

	if secret == nil {
		// 1. x $← Zq∗
		s, err := dp.scalar.Random()
		if err != nil {
			return nil, nil, err
		}
		secret = s.Bytes()
	} else {
		s := new(big.Int).SetBytes(secret)
		if !dp.scalar.IsValid(s) {
			return nil, nil, fmt.Errorf("invalid secret value")
		}
		if s.Cmp(core.Zero) == 0 {
			return nil, nil, internal.ErrZeroValue
		}
	}

	var err error
	// 2. {X1,...,Xt},{R1,...,Rt},{x1,...,xn},{r1,...,rn}= PedersenFeldmanShare(E,Q,x,t,{p1,...,pn})
	dp.pedersenResult, err = dp.pedersen.Split(secret)

	if err != nil {
		return nil, nil, err
	}

	// 4. P2PSend x_j,r_j to participant p_j in {p_1,...,p_n}_{i != j}
	p2pSend := make(Round1P2PSend, len(dp.otherParticipantShares))
	for id := range dp.otherParticipantShares {
		p2pSend[id] = &Round1P2PSendPacket{
			SecretShare:   dp.pedersenResult.SecretShares[id-1],
			BlindingShare: dp.pedersenResult.BlindingShares[id-1],
		}
	}

	// Update internal state
	dp.round = 2

	// 3. EchoBroadcast {X_1,...,X_t} to all other participants.
	return dp.pedersenResult.BlindedVerifiers, p2pSend, nil
}
