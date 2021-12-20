//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/pkg/errors"
)

// Round1Bcast contains values to be broadcast to all players after the completion of signing round 1.
type Round1Bcast struct {
	Di, Ei curves.Point
}

func (result *Round1Bcast) Encode() ([]byte, error) {
	gob.Register(result.Di) // just the point for now
	gob.Register(result.Ei)
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(result); err != nil {
		return nil, errors.Wrap(err, "couldn't encode round 1 broadcast")
	}
	return buf.Bytes(), nil
}

func (result *Round1Bcast) Decode(input []byte) error {
	buf := bytes.NewBuffer(input)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(result); err != nil {
		return errors.Wrap(err, "couldn't encode round 1 broadcast")
	}
	return nil
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
