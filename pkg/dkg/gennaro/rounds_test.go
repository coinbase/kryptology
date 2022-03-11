//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package gennaro

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	v1 "github.com/coinbase/kryptology/pkg/sharing/v1"
)

func TestParticipantRound1Works(t *testing.T) {
	p1, err := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
	require.NoError(t, err)
	bcast, p2psend, err := p1.Round1(nil)
	require.NoError(t, err)
	require.NotNil(t, bcast)
	require.NotNil(t, p2psend)
	require.Equal(t, len(p2psend), 1)
	require.Equal(t, len(bcast), 2)
	require.NotNil(t, p1.pedersenResult)
	require.Equal(t, p1.round, 2)
	_, ok := p2psend[2]
	require.True(t, ok)
}

func TestParticipantRound1RepeatCall(t *testing.T) {
	p1, err := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
	require.NoError(t, err)
	_, _, err = p1.Round1(nil)
	require.NoError(t, err)
	_, _, err = p1.Round1(nil)
	require.Error(t, err)
}

func TestParticipantRound1BadSecret(t *testing.T) {
	p1, err := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
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

func PrepareRound2Input(t *testing.T) (*Participant, *Participant, Round1Bcast, Round1Bcast, Round1P2PSend) {
	// Prepare round 1 output of 2 participants
	p1, err := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
	require.NoError(t, err)
	require.Equal(t, p1.otherParticipantShares[2].Id, uint32(2))
	p2, err := NewParticipant(2, 2, testGenerator, curves.NewK256Scalar(), 1)
	require.NoError(t, err)
	require.Equal(t, p2.otherParticipantShares[1].Id, uint32(1))
	bcast1, _, _ := p1.Round1(nil)
	bcast2, p2psend2, _ := p2.Round1(nil)
	return p1, p2, bcast1, bcast2, p2psend2
}

// Test Gennaro DKG round2 works
func TestParticipantRound2Works(t *testing.T) {
	// Prepare Dkg Round 1 output
	p1, _, bcast1, bcast2, p2psend2 := PrepareRound2Input(t)
	// Actual Test
	require.NotNil(t, bcast1)
	require.NotNil(t, bcast2)
	require.NotNil(t, p2psend2[1])
	bcast := make(map[uint32]Round1Bcast)
	p2p := make(map[uint32]*Round1P2PSendPacket)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	round2Out, err := p1.Round2(bcast, p2p)
	require.NoError(t, err)
	require.NotNil(t, round2Out)
	require.Equal(t, len(round2Out), 2)
	require.NotNil(t, p1.skShare)
	require.Equal(t, p1.round, 3)
	require.NotNil(t, p1.otherParticipantShares)
}

// Test Gennaro DKG round 2 repeat call
func TestParticipantRound2RepeatCall(t *testing.T) {
	// Prepare Dkg Round 1 output
	p1, _, bcast1, bcast2, p2psend2 := PrepareRound2Input(t)
	// Actual Test
	require.NotNil(t, bcast1)
	require.NotNil(t, bcast2)
	require.NotNil(t, p2psend2[1])
	bcast := make(map[uint32]Round1Bcast)
	p2p := make(map[uint32]*Round1P2PSendPacket)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	_, err := p1.Round2(bcast, p2p)
	require.NoError(t, err)
	_, err = p1.Round2(bcast, p2p)
	require.Error(t, err)
}

// Test Gennaro Dkg Round 2 Bad Input
func TestParticipantRound2BadInput(t *testing.T) {
	// Prepare Dkg Round 1 output
	p1, _, _, _, _ := PrepareRound2Input(t)
	bcast := make(map[uint32]Round1Bcast)
	p2p := make(map[uint32]*Round1P2PSendPacket)

	// Test empty bcast and p2p
	_, err := p1.Round2(bcast, p2p)
	require.Error(t, err)

	// Test nil bcast and p2p
	p1, _, _, _, _ = PrepareRound2Input(t)
	_, err = p1.Round2(nil, nil)
	require.Error(t, err)

	// Test tampered input bcast and p2p
	p1, _, bcast1, bcast2, p2psend2 := PrepareRound2Input(t)
	bcast = make(map[uint32]Round1Bcast)
	p2p = make(map[uint32]*Round1P2PSendPacket)

	// Tamper bcast1 and p2psend2 by doubling their value
	bcast1[1].Y = bcast1[1].Y.Add(bcast1[1].Y, bcast1[1].Y)
	p2psend2[1].SecretShare.Value = p2psend2[1].SecretShare.Value.Add(p2psend2[1].SecretShare.Value)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p[2] = p2psend2[1]
	_, err = p1.Round2(bcast, p2p)
	require.Error(t, err)
}

func PrepareRound3Input(t *testing.T) (*Participant, *Participant, map[uint32]Round2Bcast) {
	p1, _ := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
	p2, _ := NewParticipant(2, 2, testGenerator, curves.NewK256Scalar(), 1)
	bcast1, p2psend1, _ := p1.Round1(nil)
	bcast2, p2psend2, _ := p2.Round1(nil)
	bcast := make(map[uint32]Round1Bcast)
	p2p1 := make(map[uint32]*Round1P2PSendPacket)
	p2p2 := make(map[uint32]*Round1P2PSendPacket)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p1[2] = p2psend2[1]
	p2p2[1] = p2psend1[2]
	round2Out1, _ := p1.Round2(bcast, p2p1)
	round2Out2, _ := p2.Round2(bcast, p2p2)
	round3Input := make(map[uint32]Round2Bcast)
	round3Input[1] = round2Out1
	round3Input[2] = round2Out2
	return p1, p2, round3Input
}

// Test Gennaro Dkg Round 3 Works
func TestParticipantRound3Works(t *testing.T) {
	// Prepare Gennaro Dkg Round 3 Input
	p1, p2, round3Input := PrepareRound3Input(t)

	// Actual Test
	round3Out1, _, err := p1.Round3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out1)
	round3Out2, _, err := p2.Round3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out2)
	require.Equal(t, p1.round, 4)
	require.Equal(t, p2.round, 4)
	require.Equal(t, p1.verificationKey, p2.verificationKey)

	// Test if shares recombine properly
	s, _ := v1.NewShamir(2, 2, curves.NewField(btcec.S256().N))
	sk, err := s.Combine(&v1.ShamirShare{Identifier: p1.id, Value: p1.skShare},
		&v1.ShamirShare{Identifier: p2.id, Value: p2.skShare})
	require.NoError(t, err)

	// Test verification keys are G * sk
	x, y := btcec.S256().ScalarBaseMult(sk)
	tmp := &curves.EcPoint{
		Curve: btcec.S256(),
		X:     x,
		Y:     y,
	}
	require.True(t, tmp.Equals(p1.verificationKey))
	require.True(t, tmp.Equals(p2.verificationKey))
}

// Test Gennaro Dkg Round3 Repeat Call
func TestParticipantRound3RepeatCall(t *testing.T) {
	// Prepare Round 3 Input
	p1, _, round3Input := PrepareRound3Input(t)

	// Actual Test
	_, _, err := p1.Round3(round3Input)
	require.NoError(t, err)
	_, _, err = p1.Round3(round3Input)
	require.Error(t, err)
}

// Test Gennaro DKG Round 3 Bad Input
func TestParticipantRound3BadInput(t *testing.T) {
	// Test empty round 3 input
	p1, _, _ := PrepareRound3Input(t)
	emptyInput := make(map[uint32]Round2Bcast)
	_, _, err := p1.Round3(emptyInput)
	require.Error(t, err)

	// Test nil round 3 input
	p1, _, _ = PrepareRound3Input(t)
	_, _, err = p1.Round3(nil)
	require.Error(t, err)

	// Test tampered round 3 input
	p1, _, round3Input := PrepareRound3Input(t)
	// Tamper participant2's broadcast
	round3Input[2][0], _ = round3Input[2][0].Add(round3Input[2][1])
	_, _, err = p1.Round3(round3Input)
	require.Error(t, err)
}

// Test Gennaro Dkg Round 4 Works
func TestParticipantRound4Works(t *testing.T) {
	// Prepare Gennaro Dkg Round 3 Input
	p1, p2, round3Input := PrepareRound3Input(t)
	round3Out1, _, err := p1.Round3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out1)
	round3Out2, _, err := p2.Round3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out2)

	// Actual test
	publicShares1, err := p1.Round4()
	require.NoError(t, err)
	require.NotNil(t, publicShares1)
	publicShares2, err := p2.Round4()
	require.NoError(t, err)
	require.NotNil(t, publicShares2)

	require.Equal(t, publicShares1, publicShares2)
}

// Test Gennaro Dkg Round 4 Works
func TestParticipantRound4RepeatCall(t *testing.T) {
	// Prepare Gennaro Dkg Round 3 Input
	p1, p2, round3Input := PrepareRound3Input(t)
	round3Out1, _, err := p1.Round3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out1)
	round3Out2, _, err := p2.Round3(round3Input)
	require.NoError(t, err)
	require.NotNil(t, round3Out2)

	// Actual test
	publicShares1, err := p1.Round4()
	require.NoError(t, err)
	require.NotNil(t, publicShares1)
	publicShares2, err := p1.Round4()
	require.NoError(t, err)
	require.NotNil(t, publicShares2)

	require.Equal(t, publicShares1, publicShares2)
}

// Test all Gennaro DKG rounds
func TestAllGennaroDkgRounds(t *testing.T) {
	// Initiate two participants
	p1, _ := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
	p2, _ := NewParticipant(2, 2, testGenerator, curves.NewK256Scalar(), 1)

	// Running round 1
	bcast1, p2psend1, _ := p1.Round1(nil)
	bcast2, p2psend2, _ := p2.Round1(nil)
	bcast := make(map[uint32]Round1Bcast)
	p2p1 := make(map[uint32]*Round1P2PSendPacket)
	p2p2 := make(map[uint32]*Round1P2PSendPacket)
	bcast[1] = bcast1
	bcast[2] = bcast2
	p2p1[2] = p2psend2[1]
	p2p2[1] = p2psend1[2]

	// Running round 2
	round2Out1, _ := p1.Round2(bcast, p2p1)
	round2Out2, _ := p2.Round2(bcast, p2p2)
	round3Input := make(map[uint32]Round2Bcast)
	round3Input[1] = round2Out1
	round3Input[2] = round2Out2

	// Running round 3
	round3Out1, _, _ := p1.Round3(round3Input)
	round3Out2, _, _ := p2.Round3(round3Input)
	require.NotNil(t, round3Out1)
	require.NotNil(t, round3Out2)

	// Running round 4
	publicShares1, _ := p1.Round4()
	publicShares2, _ := p2.Round4()

	// Test output of all rounds
	require.Equal(t, publicShares1, publicShares2)
	s, _ := v1.NewShamir(2, 2, curves.NewField(btcec.S256().N))
	sk, err := s.Combine(&v1.ShamirShare{Identifier: p1.id, Value: p1.skShare},
		&v1.ShamirShare{Identifier: p2.id, Value: p2.skShare})
	require.NoError(t, err)

	x, y := btcec.S256().ScalarBaseMult(sk)
	tmp := &curves.EcPoint{
		Curve: btcec.S256(),
		X:     x,
		Y:     y,
	}
	require.True(t, tmp.Equals(p1.verificationKey))
	require.True(t, tmp.Equals(p2.verificationKey))
}

// Ensure correct functioning when input is missing
func TestParticipant2BadInput(t *testing.T) {
	//
	// Setup
	//
	p1, _ := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
	p2, _ := NewParticipant(2, 2, testGenerator, curves.NewK256Scalar(), 1)
	bcast1, _, _ := p1.Round1(nil)
	bcast2, p2psend2, _ := p2.Round1(nil)
	bcast := make(map[uint32]Round1Bcast)
	p2p1 := make(map[uint32]*Round1P2PSendPacket)
	bcast[1] = bcast1
	bcast[2] = bcast2
	// Exclude p2p 2>1
	p2p1[4] = p2psend2[1]

	// Run round 2
	_, err := p1.Round2(bcast, p2p1)
	require.Error(t, err)
}

func TestValidIDs(t *testing.T) {
	err := fmt.Errorf("")
	tests := []struct {
		name     string
		in       []uint32
		expected error
	}{
		{"positive-1,2", []uint32{1, 2}, nil},
		{"positive-2,1", []uint32{2, 1}, nil},
		{"positive-1-10", []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil},
		{"positive-1-10-random", []uint32{10, 9, 6, 5, 3, 2, 8, 7, 1, 4}, nil},
		{"negative-1,3", []uint32{1, 3}, err},
		{"negative-1-10-missing-5", []uint32{10, 9, 6, 3, 2, 8, 7, 1, 4}, err},
	}
	// Run all the tests!
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validIds(test.in)
			if test.expected == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Test newParticipant with arbitrary IDs
func TestParticipantArbitraryIds(t *testing.T) {
	_, err := NewParticipant(3, 2, testGenerator, curves.NewK256Scalar(), 4)
	require.Error(t, err)
	_, err = NewParticipant(0, 2, testGenerator, curves.NewK256Scalar(), 1)
	require.Error(t, err)
	_, err = NewParticipant(2, 2, testGenerator, curves.NewK256Scalar(), 2, 3, 5)
	require.Error(t, err)
	_, err = NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 4)
	require.Error(t, err)
}
