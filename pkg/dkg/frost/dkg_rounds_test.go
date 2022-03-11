//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package frost

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
)

var (
	testCurve = curves.ED25519()
	Ctx       = "string to prevent replay attack"
)

// Test dkg round1 works for 2 participants
func TestDkgRound1Works(t *testing.T) {
	p1, err := NewDkgParticipant(1, 2, Ctx, testCurve, 2)
	require.NoError(t, err)
	bcast, p2psend, err := p1.Round1(nil)
	require.NoError(t, err)
	require.NotNil(t, bcast)
	require.NotNil(t, p2psend)
	require.NotNil(t, p1.ctx)
	require.Equal(t, len(p2psend), 1)
	require.Equal(t, p1.round, 2)
	_, ok := p2psend[2]
	require.True(t, ok)
}

func TestDkgRound1RepeatCall(t *testing.T) {
	p1, err := NewDkgParticipant(1, 2, Ctx, testCurve, 2)
	require.NoError(t, err)
	_, _, err = p1.Round1(nil)
	require.NoError(t, err)
	_, _, err = p1.Round1(nil)
	require.Error(t, err)
}

func TestDkgRound1BadSecret(t *testing.T) {
	p1, err := NewDkgParticipant(1, 2, Ctx, testCurve, 2)
	require.NoError(t, err)
	// secret == 0
	secret := []byte{0}
	_, _, err = p1.Round1(secret)
	require.Error(t, err)
	// secret too big
	secret = []byte{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7}
	_, _, err = p1.Round1(secret)
	require.Error(t, err)
}

func PrepareRound2Input(t *testing.T) (*DkgParticipant, *DkgParticipant, *Round1Bcast, *Round1Bcast, Round1P2PSend, Round1P2PSend) {
	// Prepare round 1 output of 2 participants
	p1, err := NewDkgParticipant(1, 2, Ctx, testCurve, 2)
	require.NoError(t, err)
	require.Equal(t, p1.otherParticipantShares[2].Id, uint32(2))
	p2, err := NewDkgParticipant(2, 2, Ctx, testCurve, 1)
	require.NoError(t, err)
	require.Equal(t, p2.otherParticipantShares[1].Id, uint32(1))
	bcast1, p2psend1, _ := p1.Round1(nil)
	bcast2, p2psend2, _ := p2.Round1(nil)
	return p1, p2, bcast1, bcast2, p2psend1, p2psend2
}

// Test FROST DKG round 2 works
func TestDkgRound2Works(t *testing.T) {
	// Prepare Dkg Round1 output
	p1, _, bcast1, bcast2, _, p2psend2 := PrepareRound2Input(t)
	// Actual Test
	require.NotNil(t, bcast1)
	require.NotNil(t, bcast2)
	require.NotNil(t, p2psend2[1])
	bcast := make(map[uint32]*Round1Bcast)
	p2p := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	round2Out, err := p1.Round2(bcast, p2p)
	require.NoError(t, err)
	require.NotNil(t, round2Out)
	require.NotNil(t, p1.SkShare)
	require.NotNil(t, p1.VkShare)
	require.NotNil(t, p1.VerificationKey)
	require.NotNil(t, p1.otherParticipantShares)
}

// Test FROST DKG round 2 repeat call
func TestDkgRound2RepeatCall(t *testing.T) {
	// Prepare round 1 output
	p1, _, bcast1, bcast2, _, p2psend2 := PrepareRound2Input(t)
	// Actual Test
	require.NotNil(t, bcast1)
	require.NotNil(t, bcast2)
	require.NotNil(t, p2psend2[1])
	bcast := make(map[uint32]*Round1Bcast)
	p2p := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	_, err := p1.Round2(bcast, p2p)
	require.NoError(t, err)
	_, err = p1.Round2(bcast, p2p)
	require.Error(t, err)
}

// Test FROST Dkg Round 2 Bad Input
func TestDkgRound2BadInput(t *testing.T) {
	// Prepare Dkg Round 1 output
	p1, _, _, _, _, _ := PrepareRound2Input(t)
	bcast := make(map[uint32]*Round1Bcast)
	p2p := make(map[uint32]*sharing.ShamirShare)

	// Test empty bcast and p2p
	_, err := p1.Round2(bcast, p2p)
	require.Error(t, err)

	// Test nil bcast and p2p
	p1, _, _, _, _, _ = PrepareRound2Input(t)
	_, err = p1.Round2(nil, nil)
	require.Error(t, err)

	// Test tampered input bcast and p2p
	p1, _, bcast1, bcast2, _, p2psend2 := PrepareRound2Input(t)
	bcast = make(map[uint32]*Round1Bcast)
	p2p = make(map[uint32]*sharing.ShamirShare)

	// Tamper p2psend2 by doubling the value
	tmp, _ := testCurve.Scalar.SetBytes(p2psend2[1].Value)
	p2psend2[1].Value = tmp.Double().Bytes()
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	_, err = p1.Round2(bcast, p2p)
	require.Error(t, err)
}

// Test full round works
func TestFullDkgRoundsWorks(t *testing.T) {
	// Initiate two participants and running round 1
	p1, p2, bcast1, bcast2, p2psend1, p2psend2 := PrepareRound2Input(t)
	bcast := make(map[uint32]*Round1Bcast)
	p2p1 := make(map[uint32]*sharing.ShamirShare)
	p2p2 := make(map[uint32]*sharing.ShamirShare)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p1[2] = p2psend2[1]
	p2p2[1] = p2psend1[2]

	// Running round 2
	round2Out1, _ := p1.Round2(bcast, p2p1)
	round2Out2, _ := p2.Round2(bcast, p2p2)
	require.Equal(t, round2Out1.VerificationKey, round2Out2.VerificationKey)
	s, _ := sharing.NewShamir(2, 2, testCurve)
	sk, err := s.Combine(&sharing.ShamirShare{Id: p1.Id, Value: p1.SkShare.Bytes()},
		&sharing.ShamirShare{Id: p2.Id, Value: p2.SkShare.Bytes()})
	require.NoError(t, err)

	vk := testCurve.ScalarBaseMult(sk)
	require.True(t, vk.Equal(p1.VerificationKey))
}
