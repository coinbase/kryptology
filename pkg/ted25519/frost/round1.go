//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	crand "crypto/rand"
	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Round1Bcast contains values to be broadcast to all players after the completion of signing round 1.
type Round1Bcast struct {
	Di, Ei curves.Point
}

func (signer *Signer) SignRound1() (*Round1Bcast, error) {
	// Make sure signer is not empty
	if signer == nil || signer.curve == nil {
		return nil, internal.ErrNilArguments
	}

	// Make sure round number is correct
	if signer.round != 1 {
		return nil, internal.ErrInvalidRound
	}

	// Step 1 - Sample di, ei
	di := signer.curve.Scalar.Random(crand.Reader)

	ei := signer.curve.Scalar.Random(crand.Reader)

	// Step 2 - Compute Di, Ei
	Di := signer.curve.ScalarBaseMult(di)

	Ei := signer.curve.ScalarBaseMult(ei)

	// Update round number
	signer.round = 2

	// Store di, ei, Di, Ei locally and broadcast Di, Ei
	signer.state.capD = Di
	signer.state.capE = Ei
	signer.state.smallD = di
	signer.state.smallE = ei
	return &Round1Bcast{
		Di,
		Ei,
	}, nil
}
