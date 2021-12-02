//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"fmt"
	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

// Round2Bcast are values that are broadcast to all other participants
// after round2 completes
type Round2Bcast struct {
	VerificationKey curves.Point
	VkShare         curves.Point
}

// Round2 implements dkg round 2 of FROST
func (dp *DkgParticipant) Round2(bcast map[uint32]*Round1Bcast, p2psend map[uint32]*sharing.ShamirShare) (*Round2Bcast, error) {
	// Make sure dkg participant is not empty
	if dp == nil || dp.Curve == nil {
		return nil, internal.ErrNilArguments
	}

	// Check dkg participant has the correct dkg round number
	if dp.round != 2 {
		return nil, internal.ErrInvalidRound
	}

	// Check the input is valid
	if bcast == nil || p2psend == nil || len(p2psend) == 0 {
		return nil, internal.ErrNilArguments
	}

	// Check length of bcast and p2psend
	if uint32(len(bcast)) > dp.feldman.Limit || uint32(len(bcast)) < dp.feldman.Threshold-1 {
		return nil, fmt.Errorf("invalid broadcast length")
	}

	if uint32(len(p2psend)) > dp.feldman.Limit-1 || uint32(len(p2psend)) < dp.feldman.Threshold-1 {
		return nil, fmt.Errorf("invalid p2pSend length")
	}

	// We should validate Wi and Ci values in Round1Bcast
	for id := range bcast {
		// ci should be within the range 1 to q-1, q is the group order.
		if bcast[id].Ci.IsZero() {
			return nil, fmt.Errorf("ci should not be zero from participant %d\n", id)
		}
	}
	// Validate each received commitment is on curve
	for id := range bcast {
		for _, com := range bcast[id].Verifiers.Commitments {
			if !com.IsOnCurve() || com.IsIdentity() {
				return nil, fmt.Errorf("some commitment is not on curve from participant %d\n", id)
			}
		}
	}

	var err error

	// Step 2 - for j in 1,...,n
	for id := range bcast {

		// Step 3 - if j == i, continue
		if id == dp.Id {
			continue
		}

		// Step 4 - Check equation c_j = H(j, CTX, A_{j,0}, g^{w_j}*A_{j,0}^{-c_j}
		// Get Aj0
		Aj0 := bcast[id].Verifiers.Commitments[0]
		// Compute g^{w_j}
		prod1 := dp.Curve.ScalarBaseMult(bcast[id].Wi)
		// Compute A_{j,0}^{-c_j}
		prod2 := Aj0.Mul(bcast[id].Ci.Neg())

		// We need to check Aj0 and prod2 are points on the same curve.
		if !Aj0.IsOnCurve() || Aj0.IsIdentity() || !prod2.IsOnCurve() || prod2.IsIdentity() || Aj0.CurveName() != prod2.CurveName() {
			return nil, fmt.Errorf("invalid Aj0 or prod2 which is not on the same curve")
		}
		if prod2 == nil {
			return nil, fmt.Errorf("invalid should not be nil")
		}

		prod := prod1.Add(prod2)
		var msg []byte
		// Append participant id
		msg = append(msg, byte(id))
		// Append CTX
		msg = append(msg, dp.ctx)
		// Append Aj0
		msg = append(msg, Aj0.ToAffineCompressed()...)
		// Append prod
		msg = append(msg, prod.ToAffineCompressed()...)
		// Hash the message and get cj
		cj := dp.Curve.Scalar.Hash(msg)
		// Check equation
		if cj.Cmp(bcast[id].Ci) != 0 {
			return nil, fmt.Errorf("Hash check fails for participant with id %d\n", id)
		}

		// Step 5 - FeldmanVerify
		fji := p2psend[id]
		if err = bcast[id].Verifiers.Verify(fji); err != nil {
			return nil, fmt.Errorf("feldman verify fails for participant with id %d\n", id)
		}
	}

	sk, err := dp.Curve.Scalar.SetBytes(dp.secretShares[dp.Id-1].Value)
	if err != nil {
		return nil, err
	}
	vk := dp.verifiers.Commitments[0]
	// Step 6 - Compute signing key share ski = \sum_{j=1}^n xji
	for id := range bcast {
		if id == dp.Id {
			continue
		}
		t2, err := dp.Curve.Scalar.SetBytes(p2psend[id].Value)
		if err != nil {
			return nil, err
		}
		sk = sk.Add(t2)
	}

	// Step 8 - Compute verification key vk = sum(A_{j,0}), j = 1,...,n
	for id := range bcast {
		if id == dp.Id {
			continue
		}
		vk = vk.Add(bcast[id].Verifiers.Commitments[0])
	}

	// Store signing key share
	dp.SkShare = sk

	// Step 7 - Compute verification key share vki = ski*G and store
	dp.VkShare = dp.Curve.ScalarBaseMult(sk)

	// Store verification key
	dp.VerificationKey = vk

	// Update round number
	dp.round = 3

	// Broadcast
	return &Round2Bcast{
		vk,
		dp.VkShare,
	}, nil
}
