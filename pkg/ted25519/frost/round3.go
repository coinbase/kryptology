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
)

// Round3Bcast contains the output of FROST signature, i.e., it contains FROST signature (z,c) and the
// corresponding message msg.
type Round3Bcast struct {
	R    curves.Point
	Z, C curves.Scalar
	msg  []byte
}

// Define frost signature type
type Signature struct {
	Z curves.Scalar
	C curves.Scalar
}

func (signer *Signer) SignRound3(round3Input map[uint32]*Round2Bcast) (*Round3Bcast, error) {
	// Make sure signer is not empty
	if signer == nil || signer.curve == nil {
		return nil, internal.ErrNilArguments
	}

	// Make sure signer's smallD and smallE are zero
	if !signer.state.smallD.IsZero() || !signer.state.smallE.IsZero() {
		return nil, fmt.Errorf("signer's private smallD and smallE should be zero since one-time use")
	}

	// Make sure the signer has had the msg
	if len(signer.state.msg) == 0 {
		return nil, internal.ErrNilArguments
	}

	// Validate Round3Input
	if round3Input == nil {
		return nil, internal.ErrNilArguments
	}
	for _, data := range round3Input {
		if data == nil {
			return nil, internal.ErrNilArguments
		}
	}

	// Make sure the signer has commitments stored at the end of round 1.
	if signer.state.commitments == nil || len(signer.state.commitments) != len(round3Input) {
		return nil, internal.ErrNilArguments
	}

	// Make sure the round number is correct
	if signer.round != 3 {
		return nil, internal.ErrInvalidRound
	}

	// Round2 Input has different length of threshold
	if uint32(len(round3Input)) != signer.threshold {
		return nil, fmt.Errorf("invalid length of round3Input")
	}

	// Step 1-3
	// Step 1: For j in [1...t]
	z := signer.curve.NewScalar()
	negate := signer.state.sumR.IsNegative()
	for id, data := range round3Input {
		zj := data.Zi
		vkj := data.Vki

		// Step 2: Verify zj*G = Rj + c*Lj*vkj
		// zj*G
		zjG := signer.curve.ScalarBaseMult(zj)

		// c*Lj
		cLj := signer.state.c.Mul(signer.lCoeffs[id])

		// cLjvkj
		cLjvkj := vkj.Mul(cLj)

		// Rj + c*Lj*vkj
		Rj := signer.state.capRs[id]
		if negate {
			Rj = Rj.Neg()
		}
		right := cLjvkj.Add(Rj)

		// Check equation
		if !zjG.Equal(right) {
			return nil, fmt.Errorf("zjG != right with participant id %d\n", id)
		}

		// Step 3 - z = z+zj
		z = z.Add(zj)
	}

	// Step 4 - 7: Self verify the signature (z, c)
	// Step 5 - R' = z*G + (-c)*vk
	zG := signer.curve.ScalarBaseMult(z)
	cvk := signer.verificationKey.Mul(signer.state.c.Neg())
	tempR := zG.Add(cvk)
	// Step 6 - c' = H(m, R')
	tempC, err := signer.challengeDeriver.DeriveChallenge(signer.state.msg, signer.verificationKey, tempR)
	if err != nil {
		return nil, err
	}

	// Step 7 - Check c = c'
	if tempC.Cmp(signer.state.c) != 0 {
		return nil, fmt.Errorf("invalid signature: c != c'")
	}

	// Updating round number
	signer.round = 4

	// Step 8 - Broadcast signature and message
	return &Round3Bcast{
		signer.state.sumR,
		z,
		signer.state.c,
		signer.state.msg,
	}, nil
}

// Method to verify a frost signature.
func (signer *Signer) Verify(vk curves.Point, message []byte, signature *Signature) (bool, error) {
	if vk == nil || message == nil || signature.Z == nil || signature.C == nil {
		return false, fmt.Errorf("invalid input!")
	}
	z := signature.Z
	c := signature.C
	// R' = z*G + (-c)*vk
	zG := signer.curve.ScalarBaseMult(z)
	cvk := vk.Mul(c.Neg())
	tempR := zG.Add(cvk)
	// Step 6 - c' = H(m, R')
	tempC, err := signer.challengeDeriver.DeriveChallenge(signer.state.msg, signer.verificationKey, tempR)
	if err != nil {
		return false, err
	}

	// Step 7 - Check c = c'
	if tempC.Cmp(c) != 0 {
		return false, fmt.Errorf("invalid signature: c != c'")
	}

	return true, nil
}
