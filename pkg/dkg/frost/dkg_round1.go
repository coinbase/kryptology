//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	crand "crypto/rand"
	"fmt"
	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"reflect"
)

// Round1Bcast are values that are broadcast to all other participants
// after round1 completes
type Round1Bcast struct {
	Verifiers *sharing.FeldmanVerifier
	Wi, Ci    curves.Scalar
}

// Round1P2PSend are values that are P2PSend to all other participants
// after round1 completes
type Round1P2PSend = map[uint32]*sharing.ShamirShare

// Round1 implements dkg round 1 of FROST
func (dp *DkgParticipant) Round1(secret []byte) (*Round1Bcast, Round1P2PSend, error) {
	// Make sure dkg participant is not empty
	if dp == nil || dp.Curve == nil {
		return nil, nil, internal.ErrNilArguments
	}

	// Make sure round number is correct
	if dp.round != 1 {
		return nil, nil, internal.ErrInvalidRound
	}

	// Check number of participants
	if uint32(len(dp.otherParticipantShares)+1) > dp.feldman.Limit || uint32(len(dp.otherParticipantShares)+1) < dp.feldman.Threshold {
		return nil, nil, fmt.Errorf("length of dp.otherParticipantShares + 1 should be equal to feldman limit")
	}

	// If secret is nil, sample a new one
	// If not, check secret is valid
	var s curves.Scalar
	var err error
	if secret == nil {
		s = dp.Curve.Scalar.Random(crand.Reader)
	} else {
		s, err = dp.Curve.Scalar.SetBytes(secret)
		if err != nil {
			return nil, nil, err
		}
		if s.IsZero() {
			return nil, nil, internal.ErrZeroValue
		}
	}

	// Step 1 - (Aj0,...Ajt), (xi1,...,xin) <- FeldmanShare(s)
	// We should validate types of Feldman curve scalar and participant's curve scalar.
	if reflect.TypeOf(dp.feldman.Curve.Scalar) != reflect.TypeOf(dp.Curve.Scalar) {
		return nil, nil, fmt.Errorf("feldman scalar should have the same type as the dkg participant scalar")
	}
	verifiers, shares, err := dp.feldman.Split(s, crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Store Verifiers and shares
	dp.verifiers = verifiers
	dp.secretShares = shares

	// Step 2 - Sample ki <- Z_q
	ki := dp.Curve.Scalar.Random(crand.Reader)

	// Step 3 - Compute Ri = ki*G
	Ri := dp.Curve.ScalarBaseMult(ki)

	// Step 4 - Compute Ci = H(i, CTX, g^{a_(i,0)}, R_i), where CTX is fixed context string
	var msg []byte
	// Append participant id
	msg = append(msg, byte(dp.Id))
	// Append CTX
	msg = append(msg, dp.ctx)
	// Append a_{i,0}*G
	msg = append(msg, verifiers.Commitments[0].ToAffineCompressed()...)
	// Append Ri
	msg = append(msg, Ri.ToAffineCompressed()...)
	// Hash the message and get Ci
	ci := dp.Curve.Scalar.Hash(msg)

	// Step 5 - Compute Wi = ki+a_{i,0}*c_i mod q. Note that a_{i,0} is the secret.
	// Note: We have to compute scalar in the following way when using ed25519 curve, rather than scalar := dp.Scalar.Mul(s, Ci)
	// there is an invalid encoding error when we compute scalar as above.
	wi := s.MulAdd(ci, ki)

	// Step 6 - Broadcast (Ci, Wi, Ci) to other participants
	round1Bcast := &Round1Bcast{
		verifiers,
		wi,
		ci,
	}

	// Step 7 - P2PSend f_i(j) to each participant Pj and keep (i, f_j(i)) for himself
	p2pSend := make(Round1P2PSend, len(dp.otherParticipantShares))
	for id := range dp.otherParticipantShares {
		p2pSend[id] = shares[id-1]
	}

	// Update internal state
	dp.round = 2

	// return
	return round1Bcast, p2pSend, nil
}
