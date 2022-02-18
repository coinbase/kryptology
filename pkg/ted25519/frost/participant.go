//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package frost is an implementation of t-of-n threshold signature of https://eprint.iacr.org/2020/852.pdf
package frost

import (
	"fmt"
	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/dkg/frost"
)

// Signer is a tSchnorr player performing the signing operation.
type Signer struct {
	skShare          curves.Scalar // secret signing share for this signer
	vkShare          curves.Point  // store verification key share
	verificationKey  curves.Point  // verification key
	id               uint32        // The ID assigned to this signer's shamir share
	threshold        uint32
	curve            *curves.Curve
	round            uint
	lCoeffs          map[uint32]curves.Scalar // lCoeffs are Lagrange coefficients of each cosigner.
	cosigners        []uint32
	state            *state // Accumulated intermediate values associated with signing
	challengeDeriver ChallengeDerive
}

type state struct {
	// Round 1
	capD, capE     curves.Point  // capD, capE are commitments this signer generates in signing round 1
	smallD, smallE curves.Scalar // smallD, smallE are scalars this signer generates in signing round 1

	// Round 2
	commitments map[uint32]*Round1Bcast // Store commitments broadcast after signing round 1
	msg         []byte
	c           curves.Scalar
	capRs       map[uint32]curves.Point
	sumR        curves.Point
}

// NewSigner create a signer from a dkg participant
// Note that we can pre-assign Lagrange coefficients lcoeffs of each cosigner. This optimizes performance.
// See paragraph 3 of section 3 in the draft - https://tools.ietf.org/pdf/draft-komlo-frost-00.pdf
func NewSigner(info *frost.DkgParticipant, id, thresh uint32, lcoeffs map[uint32]curves.Scalar, cosigners []uint32, challengeDeriver ChallengeDerive) (*Signer, error) {
	if info == nil || len(cosigners) == 0 || len(lcoeffs) == 0 {
		return nil, internal.ErrNilArguments
	}

	if thresh > uint32(len(cosigners)) {
		return nil, fmt.Errorf("threshold is higher than number of signers")
	}

	if len(lcoeffs) != len(cosigners) {
		return nil, fmt.Errorf("expected coefficients to be equal to number of cosigners")
	}

	// Check if cosigners and lcoeffs contain the same IDs
	for i := 0; i < len(cosigners); i++ {
		id := cosigners[i]
		if _, ok := lcoeffs[id]; !ok {
			return nil, fmt.Errorf("lcoeffs and cosigners have inconsistent ID")
		}
	}

	return &Signer{
		skShare:          info.SkShare,
		vkShare:          info.VkShare,
		verificationKey:  info.VerificationKey,
		id:               id,
		threshold:        thresh,
		curve:            info.Curve,
		round:            1,
		lCoeffs:          lcoeffs,
		cosigners:        cosigners,
		state:            &state{},
		challengeDeriver: challengeDeriver,
	}, nil
}
