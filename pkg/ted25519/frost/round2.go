//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/pkg/errors"
)

// Round2Bcast contains values that will be broadcast to other signers after completion of round 2.
type Round2Bcast struct {
	Zi  curves.Scalar
	Vki curves.Point
}

func (result *Round2Bcast) Encode() ([]byte, error) {
	gob.Register(result.Zi)
	gob.Register(result.Vki) // just the point for now
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(result); err != nil {
		return nil, errors.Wrap(err, "couldn't encode round 1 broadcast")
	}
	return buf.Bytes(), nil
}

func (result *Round2Bcast) Decode(input []byte) error {
	buf := bytes.NewBuffer(input)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(result); err != nil {
		return errors.Wrap(err, "couldn't encode round 1 broadcast")
	}
	return nil
}

// SignRound2 implements FROST signing round 2.
func (signer *Signer) SignRound2(msg []byte, round2Input map[uint32]*Round1Bcast) (*Round2Bcast, error) {
	// Make sure necessary items of signer are not empty
	if signer == nil || signer.curve == nil || signer.state == nil {
		return nil, internal.ErrNilArguments
	}

	// Make sure those private d is not empty and not zero
	if signer.state.smallD == nil || signer.state.smallD.IsZero() {
		return nil, fmt.Errorf("empty d or d is zero")
	}

	// Make sure those private e is not empty and not zero
	if signer.state.smallE == nil || signer.state.smallE.IsZero() {
		return nil, fmt.Errorf("empty e or e is zero")
	}

	// Make sure msg is not empty
	if len(msg) == 0 {
		return nil, internal.ErrNilArguments
	}

	// Make sure the round number is correct
	if signer.round != 2 {
		return nil, internal.ErrInvalidRound
	}

	// Check length of round2Input
	if uint32(len(round2Input)) != signer.threshold {
		return nil, fmt.Errorf("Invalid length of round2Input")
	}

	// Step 2 - Check Dj, Ej on the curve and Store round2Input
	for id, input := range round2Input {
		if input == nil || input.Di == nil || input.Ei == nil {
			return nil, fmt.Errorf("round2Input is nil from participant with id %d\n", id)
		}
		if !input.Di.IsOnCurve() || input.Di.IsIdentity() {
			return nil, fmt.Errorf("commitment Di is not on the curve with id %d\n", id)
		}
		if !input.Ei.IsOnCurve() || input.Ei.IsIdentity() {
			return nil, fmt.Errorf("commitment Ei is not on the curve with id %d\n", id)
		}
	}
	// Store Dj, Ej for further usage.
	signer.state.commitments = round2Input

	// Step 3-6
	R := signer.curve.NewIdentityPoint()
	var ri curves.Scalar
	Rs := make(map[uint32]curves.Point, signer.threshold)
	for id, data := range round2Input {
		// Construct the blob (j, m, {Dj, Ej})
		blob := concatHashArray(id, msg, round2Input, signer.cosigners)

		// Step 4 - rj = H(j,m,{Dj,Ej}_{j in [1...t]})
		rj := signer.curve.Scalar.Hash(blob)
		if signer.id == id {
			ri = rj
		}

		// Step 5 - R_j = D_j + r_j*E_j
		rjEj := data.Ei.Mul(rj)
		Rj := rjEj.Add(data.Di)
		// assign Rj
		Rs[id] = Rj

		// Step 6 - R = R+Rj
		R = R.Add(Rj)
	}

	// Step 7 - c = H(m, R)
	c, err := signer.challengeDeriver.DeriveChallenge(msg, signer.verificationKey, R)
	if err != nil {
		return nil, err
	}

	// Step 8 - Record c, R, Rjs
	signer.state.c = c
	signer.state.capRs = Rs
	signer.state.sumR = R

	// Step 9 - zi = di + ei*ri + Li*ski*c
	Li := signer.lCoeffs[signer.id]
	Liski := Li.Mul(signer.skShare)

	Liskic := Liski.Mul(c)

	if R.IsNegative() {
		signer.state.smallE = signer.state.smallE.Neg()
		signer.state.smallD = signer.state.smallD.Neg()
	}

	eiri := signer.state.smallE.Mul(ri)

	// Compute zi = di+ei*ri+Li*ski*c
	zi := Liskic.Add(eiri)
	zi = zi.Add(signer.state.smallD)

	// Update round number and store message
	signer.round = 3
	signer.state.msg = msg

	// set smallD and smallE to zero since they are one-time use
	signer.state.smallD = signer.curve.NewScalar()
	signer.state.smallE = signer.curve.NewScalar()

	// Step 10 - Broadcast zi, vki to other participants
	return &Round2Bcast{
		zi,
		signer.vkShare,
	}, nil
}

// concatHashArray puts id, msg and (Dj,Ej), j=1...t into a byte array
func concatHashArray(id uint32, msg []byte, round2Input map[uint32]*Round1Bcast, cosigners []uint32) []byte {
	var blob []byte
	// Append identity id
	blob = append(blob, byte(id))

	// Append message msg
	blob = append(blob, msg...)

	// Append (Dj, Ej) for all j in [1...t]
	for i := 0; i < len(cosigners); i++ {
		id := cosigners[i]
		bytesDi := round2Input[id].Di.ToAffineCompressed()
		bytesEi := round2Input[id].Ei.ToAffineCompressed()

		// Following the spec, we should add each party's identity.
		blob = append(blob, byte(id))
		blob = append(blob, bytesDi...)
		blob = append(blob, bytesEi...)
	}
	return blob
}
