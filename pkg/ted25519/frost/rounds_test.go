//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	testCurve = curves.ED25519()
	ctx       = "string to prevent replay attack"
)

// Create two DKG participants.
func PrepareDkgOutput(t *testing.T) (*dkg.DkgParticipant, *dkg.DkgParticipant) {
	// Initiate two participants and running DKG round 1
	p1, err := dkg.NewDkgParticipant(1, 2, ctx, testCurve, 2)
	require.NoError(t, err)
	p2, err := dkg.NewDkgParticipant(2, 2, ctx, testCurve, 1)
	require.NoError(t, err)
	bcast1, p2psend1, _ := p1.Round1(nil)
	bcast2, p2psend2, _ := p2.Round1(nil)
	bcast := make(map[uint32]*dkg.Round1Bcast)
	p2p1 := make(map[uint32]*sharing.ShamirShare)
	p2p2 := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p1[2] = p2psend2[1]
	p2p2[1] = p2psend1[2]

	// Running DKG round 2
	_, _ = p1.Round2(bcast, p2p1)
	_, _ = p2.Round2(bcast, p2p2)
	return p1, p2
}

// Test FROST signing round 1
func TestSignRound1Works(t *testing.T) {
	p1, p2 := PrepareDkgOutput(t)
	require.NotNil(t, p1)
	require.NotNil(t, p2)

	scheme, _ := sharing.NewShamir(2, 2, testCurve)
	lCoeffs, _ := scheme.LagrangeCoeffs(map[uint32]*sharing.ShamirShare{
		p1.Id: {Id: p1.Id, Value: p1.SkShare.Bytes()},
		p2.Id: {Id: p2.Id, Value: p2.SkShare.Bytes()},
	})

	signer1, err := NewSigner(p1, 1, 2, lCoeffs, []uint32{1, 2}, &Ed25519ChallengeDeriver{})
	require.NoError(t, err)
	round1Out, _ := signer1.SignRound1()
	require.NotNil(t, round1Out.Ei)
	require.NotNil(t, round1Out.Di)
	require.NotNil(t, signer1.state.smallE)
	require.NotNil(t, signer1.state.smallD)
	require.NotNil(t, signer1.state.capD)
	require.NotNil(t, signer1.state.capE)
	require.Equal(t, signer1.round, uint(2))
	require.Equal(t, signer1.cosigners, []uint32{1, 2})
}

func TestSignRound1RepeatCall(t *testing.T) {
	p1, p2 := PrepareDkgOutput(t)
	scheme, _ := sharing.NewShamir(2, 2, testCurve)
	lCoeffs, _ := scheme.LagrangeCoeffs(map[uint32]*sharing.ShamirShare{
		p1.Id: {Id: p1.Id, Value: p1.SkShare.Bytes()},
		p2.Id: {Id: p2.Id, Value: p2.SkShare.Bytes()},
	})
	signer1, _ := NewSigner(p1, 1, 2, lCoeffs, []uint32{1, 2}, &Ed25519ChallengeDeriver{})
	_, err := signer1.SignRound1()
	require.NoError(t, err)
	_, err = signer1.SignRound1()
	require.Error(t, err)
}

func PrepareNewSigners(t *testing.T) (*Signer, *Signer) {
	threshold := uint32(2)
	limit := uint32(2)
	p1, p2 := PrepareDkgOutput(t)
	require.Equal(t, p1.VerificationKey, p2.VerificationKey)
	scheme, err := sharing.NewShamir(threshold, limit, testCurve)
	// field = sharing.NewField(p1.curve.Params().N)
	require.NotNil(t, scheme)
	require.NoError(t, err)
	lCoeffs, err := scheme.LagrangeCoeffs(map[uint32]*sharing.ShamirShare{
		p1.Id: {Id: p1.Id, Value: p1.SkShare.Bytes()},
		p2.Id: {Id: p2.Id, Value: p2.SkShare.Bytes()},
	})
	require.NotNil(t, lCoeffs[1])
	require.NotNil(t, lCoeffs[2])
	require.NoError(t, err)
	signer1, err := NewSigner(p1, p1.Id, threshold, lCoeffs, []uint32{p1.Id, p2.Id}, &Ed25519ChallengeDeriver{})
	require.NotNil(t, signer1)
	require.NoError(t, err)
	signer2, err := NewSigner(p2, p2.Id, threshold, lCoeffs, []uint32{p1.Id, p2.Id}, &Ed25519ChallengeDeriver{})
	require.NotNil(t, signer2)
	require.NoError(t, err)
	return signer1, signer2
}

func TestSignRound2Works(t *testing.T) {
	// Preparing round 2 inputs
	signer1, signer2 := PrepareNewSigners(t)
	require.Equal(t, signer1.verificationKey, signer2.verificationKey)
	require.NotNil(t, signer1)
	require.NotNil(t, signer2)
	round1Out1, _ := signer1.SignRound1()
	round1Out2, _ := signer2.SignRound1()
	round2Input := make(map[uint32]*Round1Bcast)
	round2Input[signer1.id] = round1Out1
	round2Input[signer2.id] = round1Out2

	// Actual Test
	msg := []byte("message")
	round2Out, err := signer1.SignRound2(msg, round2Input)
	require.NotNil(t, round2Out)
	require.NoError(t, err)
	require.Equal(t, signer1.round, uint(3))
	require.NotNil(t, signer1.state.commitments)
	require.Equal(t, signer1.state.msg, msg)
	require.True(t, signer1.state.smallD.IsZero())
	require.True(t, signer1.state.smallE.IsZero())
}

func TestSignRound2RepeatCall(t *testing.T) {
	// Preparing round 2 inputs
	signer1, signer2 := PrepareNewSigners(t)
	require.NotNil(t, signer1)
	require.NotNil(t, signer2)
	round1Out1, _ := signer1.SignRound1()
	round1Out2, _ := signer2.SignRound1()
	round2Input := make(map[uint32]*Round1Bcast)
	round2Input[signer1.id] = round1Out1
	round2Input[signer2.id] = round1Out2

	// Actual Test
	msg := []byte("message")
	_, err := signer1.SignRound2(msg, round2Input)
	require.NoError(t, err)
	_, err = signer1.SignRound2(msg, round2Input)
	require.Error(t, err)
}

func TestSignRound2BadInput(t *testing.T) {
	// Preparing round 2 inputs
	signer1, signer2 := PrepareNewSigners(t)
	_, _ = signer1.SignRound1()
	round1Out2, _ := signer2.SignRound1()
	round2Input := make(map[uint32]*Round1Bcast)

	// Actual Test: Set an input to nil
	round2Input[signer1.id] = nil
	round2Input[signer2.id] = round1Out2
	msg := []byte("message")
	_, err := signer1.SignRound2(msg, round2Input)
	require.Error(t, err)

	// Preparing round 2 inputs
	signer1, signer2 = PrepareNewSigners(t)
	round1Out1, _ := signer1.SignRound1()
	round1Out2, _ = signer2.SignRound1()
	round2Input = make(map[uint32]*Round1Bcast)
	round2Input[signer1.id] = round1Out1
	round2Input[signer2.id] = round1Out2
	// Actual Test: Nil message
	_, err = signer1.SignRound2(nil, round2Input)
	require.Error(t, err)

	// Preparing round 2 inputs
	signer1, signer2 = PrepareNewSigners(t)
	round1Out1, _ = signer1.SignRound1()
	round1Out2, _ = signer2.SignRound1()
	round2Input = make(map[uint32]*Round1Bcast)

	// Actual Test: Set invalid round2Input length
	round2Input[signer1.id] = round1Out1
	round2Input[signer2.id] = round1Out2
	round2Input[3] = round1Out2
	_, err = signer1.SignRound2(msg, round2Input)
	require.Error(t, err)

	// Preparing round 2 inputs
	signer1, signer2 = PrepareNewSigners(t)
	round1Out1, _ = signer1.SignRound1()
	round1Out2, _ = signer2.SignRound1()
	round2Input = make(map[uint32]*Round1Bcast)

	// Actual Test: Set invalid round2Input length
	round1Out2.Ei = nil
	round2Input[signer1.id] = round1Out1
	round2Input[signer2.id] = round1Out2
	_, err = signer1.SignRound2(msg, round2Input)
	require.Error(t, err)

	// Preparing round 2 inputs
	signer1, signer2 = PrepareNewSigners(t)
	round1Out1, _ = signer1.SignRound1()
	round1Out2, _ = signer2.SignRound1()
	round2Input = make(map[uint32]*Round1Bcast)
	round2Input[signer1.id] = round1Out1
	round2Input[signer2.id] = round1Out2

	// Actual Test: Set nil smallD and smallE
	signer1.state.smallD = testCurve.NewScalar()
	signer1.state.smallE = nil
	_, err = signer1.SignRound2(msg, round2Input)
	require.Error(t, err)
}

func PrepareRound3Input(t *testing.T) (*Signer, *Signer, map[uint32]*Round2Bcast) {
	// Running sign round 1
	threshold := uint32(2)
	limit := uint32(2)
	p1, p2 := PrepareDkgOutput(t)
	require.Equal(t, p1.VerificationKey, p2.VerificationKey)
	scheme, err := sharing.NewShamir(threshold, limit, testCurve)
	require.NotNil(t, scheme)
	require.NoError(t, err)
	lCoeffs, err := scheme.LagrangeCoeffs(map[uint32]*sharing.ShamirShare{
		p1.Id: {Id: p1.Id, Value: p1.SkShare.Bytes()},
		p2.Id: {Id: p2.Id, Value: p2.SkShare.Bytes()},
	})
	require.NotNil(t, lCoeffs[1])
	require.NotNil(t, lCoeffs[2])
	require.NoError(t, err)

	signer1, err := NewSigner(p1, p1.Id, threshold, lCoeffs, []uint32{p1.Id, p2.Id}, &Ed25519ChallengeDeriver{})
	require.NotNil(t, signer1)
	require.NoError(t, err)
	signer2, err := NewSigner(p2, p2.Id, threshold, lCoeffs, []uint32{p1.Id, p2.Id}, &Ed25519ChallengeDeriver{})
	require.NotNil(t, signer2)
	require.NoError(t, err)

	round1Out1, _ := signer1.SignRound1()
	round1Out2, _ := signer2.SignRound1()
	round2Input := make(map[uint32]*Round1Bcast, threshold)
	round2Input[signer1.id] = round1Out1
	round2Input[signer2.id] = round1Out2

	// Running sign round 2
	msg := []byte("message")
	round2Out1, _ := signer1.SignRound2(msg, round2Input)
	round2Out2, _ := signer2.SignRound2(msg, round2Input)
	round3Input := make(map[uint32]*Round2Bcast, threshold)
	round3Input[signer1.id] = round2Out1
	round3Input[signer2.id] = round2Out2
	return signer1, signer2, round3Input
}

func TestSignRound3Works(t *testing.T) {
	signer1, signer2, round3Input := PrepareRound3Input(t)
	round3Out1, err := signer1.SignRound3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out1)
	round3Out2, err := signer2.SignRound3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out2)
	// signer1 and signer2 outputs the same signature
	require.Equal(t, round3Out1.Z, round3Out2.Z)
	require.Equal(t, round3Out1.C, round3Out2.C)
}

func TestSignRound3RepeatCall(t *testing.T) {
	signer1, _, round3Input := PrepareRound3Input(t)
	_, err := signer1.SignRound3(round3Input)
	require.NoError(t, err)
	_, err = signer1.SignRound3(round3Input)
	require.Error(t, err)
}

func TestSignRound3BadInput(t *testing.T) {
	signer1, _, round3Input := PrepareRound3Input(t)

	// Actual test: nil input
	round3Input[signer1.id] = nil
	_, err := signer1.SignRound3(round3Input)
	require.Error(t, err)
	round3Input = nil
	_, err = signer1.SignRound3(round3Input)
	require.Error(t, err)

	// Actual test: set invalid length of round3Input
	signer1, _, round3Input = PrepareRound3Input(t)
	round3Input[100] = round3Input[signer1.id]
	_, err = signer1.SignRound3(round3Input)
	require.Error(t, err)

	// Actual test: maul the round3Input
	signer1, _, round3Input = PrepareRound3Input(t)
	round3Input[signer1.id].zi = round3Input[signer1.id].zi.Add(testCurve.Scalar.New(2))
	_, err = signer1.SignRound3(round3Input)
	require.Error(t, err)

	// Actual test: set non-zero smallD and smallE
	signer1, _, round3Input = PrepareRound3Input(t)
	signer1.state.smallD = testCurve.Scalar.New(1)
	_, err = signer1.SignRound3(round3Input)
	require.Error(t, err)
}

func TestFullRoundsWorks(t *testing.T) {
	// Give a full-round test (FROST DKG + FROST Signing) with threshold = 3 and limit = 5, same as the test of tECDSA
	threshold := 3
	limit := 5

	// Prepare DKG participants
	participants := make(map[uint32]*dkg.DkgParticipant, limit)
	for i := 1; i <= limit; i++ {
		otherIds := make([]uint32, limit-1)
		idx := 0
		for j := 1; j <= limit; j++ {
			if i == j {
				continue
			}
			otherIds[idx] = uint32(j)
			idx++
		}
		p, err := dkg.NewDkgParticipant(uint32(i), uint32(threshold), ctx, testCurve, otherIds...)
		require.NoError(t, err)
		participants[uint32(i)] = p
	}

	// FROST DKG round 1
	rnd1Bcast := make(map[uint32]*dkg.Round1Bcast, len(participants))
	rnd1P2p := make(map[uint32]dkg.Round1P2PSend, len(participants))
	for id, p := range participants {
		bcast, p2psend, err := p.Round1(nil)
		require.NoError(t, err)
		rnd1Bcast[id] = bcast
		rnd1P2p[id] = p2psend
	}

	// FROST DKG round 2
	for id := range rnd1Bcast {
		rnd1P2pForP := make(map[uint32]*sharing.ShamirShare)
		for jid := range rnd1P2p {
			if jid == id {
				continue
			}
			rnd1P2pForP[jid] = rnd1P2p[jid][id]
		}
		_, err := participants[id].Round2(rnd1Bcast, rnd1P2pForP)
		require.NoError(t, err)
	}

	// Prepare Lagrange coefficients
	scheme, _ := sharing.NewShamir(uint32(threshold), uint32(limit), testCurve)
	lCoeffs, _ := scheme.LagrangeCoeffs(map[uint32]*sharing.ShamirShare{
		participants[1].Id: {Id: participants[1].Id, Value: participants[1].SkShare.Bytes()},
		participants[2].Id: {Id: participants[2].Id, Value: participants[2].SkShare.Bytes()},
		participants[3].Id: {Id: participants[3].Id, Value: participants[3].SkShare.Bytes()},
	})

	// Using signer 1, 2 and 3 as cosigners
	var err error
	signers := make(map[uint32]*Signer, threshold)
	for i := 1; i <= threshold; i++ {
		signers[uint32(i)], err = NewSigner(participants[uint32(i)], uint32(i), uint32(threshold), lCoeffs, []uint32{1, 2, 3}, &Ed25519ChallengeDeriver{})
		require.NoError(t, err)
		require.NotNil(t, signers[uint32(i)].skShare)
	}

	// Running sign round 1
	round2Input := make(map[uint32]*Round1Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		round1Out, err := signers[uint32(i)].SignRound1()
		require.NoError(t, err)
		round2Input[signers[uint32(i)].id] = round1Out
	}

	// Running sign round 2
	msg := []byte("message")
	round3Input := make(map[uint32]*Round2Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		round2Out, err := signers[uint32(i)].SignRound2(msg, round2Input)
		require.NoError(t, err)
		round3Input[signers[uint32(i)].id] = round2Out
	}

	// Running sign round 3
	result := make(map[uint32]*Round3Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		round3Out, err := signers[uint32(i)].SignRound3(round3Input)
		require.NoError(t, err)
		result[signers[uint32(i)].id] = round3Out
	}

	// Every signer has the same output Schnorr signature
	z := result[1].Z
	require.Equal(t, z, result[2].Z)
	require.Equal(t, z, result[3].Z)
	c := result[1].C
	require.Equal(t, c, result[2].C)
	require.Equal(t, c, result[3].C)
}
