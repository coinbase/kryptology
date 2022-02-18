//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package gennaro2p

import (
	"crypto/elliptic"
	"fmt"
	"reflect"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	v1 "github.com/coinbase/kryptology/pkg/sharing/v1"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

var (
	curveScalar = curves.NewK256Scalar()
	curve       = btcec.S256()
)

const (
	clientId = 1
	serverId = 2
)

// Benchmark full DKG including blind selection and setup
func BenchmarkDkg(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}

	for i := 0; i < b.N; i++ {
		_, _, err := dkg()
		require.NoError(b, err)
	}
}

// Run a DKG and reports the client/server results
func dkg() (*DkgResult, *DkgResult, error) {
	// Create client/server
	blind, _ := newBlind(curveScalar, curve)

	client, err := NewParticipant(clientId, serverId, blind, curveScalar, curve)
	if err != nil {
		return nil, nil, err
	}

	server, err := NewParticipant(serverId, clientId, blind, curveScalar, curve)
	if err != nil {
		return nil, nil, err
	}

	// R1
	clientR1, err := client.Round1(nil)
	if err != nil {
		return nil, nil, err
	}

	serverR1, err := server.Round1(nil)
	if err != nil {
		return nil, nil, err
	}

	// R2
	clientR2, err := client.Round2(serverR1)
	if err != nil {
		return nil, nil, err
	}

	serverR2, err := server.Round2(clientR1)
	if err != nil {
		return nil, nil, err
	}

	// Finalize
	clientResult, err := client.Finalize(serverR2)
	if err != nil {
		return nil, nil, err
	}

	serverResult, err := server.Finalize(clientR2)
	if err != nil {
		return nil, nil, err
	}

	return clientResult, serverResult, nil
}

// Run a full DKG and verify the absence of errors and valid results
func TestDkg(t *testing.T) {
	// Setup and ensure no errors
	clientResult, serverResult, err := dkg()
	require.NoError(t, err)
	require.NotNil(t, clientResult)
	require.NotNil(t, serverResult)

	// Now run tests
	t.Run("produce the same public key", func(t *testing.T) {
		require.Equal(t, clientResult.PublicKey, serverResult.PublicKey)
	})
	t.Run("produce identical public shares", func(t *testing.T) {
		require.True(t, reflect.DeepEqual(clientResult.PublicShares, serverResult.PublicShares))
	})
	t.Run("produce distinct secret shares", func(t *testing.T) {
		require.NotEqual(t, clientResult.SecretShare, serverResult.SecretShare)
	})
	t.Run("produce distinct secret shares", func(t *testing.T) {
		require.NotEqual(t, clientResult.SecretShare, serverResult.SecretShare)
	})
	t.Run("shares sum to expected public key", func(t *testing.T) {
		pubkey, err := reconstructPubkey(
			clientResult.SecretShare,
			serverResult.SecretShare,
			curve)
		require.NoError(t, err)
		require.Equal(t, serverResult.PublicKey, pubkey)
	})
}

// Reconstruct the pubkey from 2 shares
func reconstructPubkey(s1, s2 *v1.ShamirShare, curve elliptic.Curve) (*curves.EcPoint, error) {
	s, err := v1.NewShamir(2, 2, s1.Value.Field())
	if err != nil {
		return nil, err
	}

	sk, err := s.Combine(s1, s2)
	if err != nil {
		return nil, err
	}

	x, y := curve.ScalarBaseMult(sk)
	return &curves.EcPoint{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// Test blind generator helper function produces a value on the expected curve
func TestNewBlindOnCurve(t *testing.T) {
	const n = 1024
	for i := 0; i < n; i++ {
		b, err := newBlind(curveScalar, curve)
		require.NoError(t, err)
		require.NotNil(t, b)

		// Valid point?
		require.True(t, b.IsOnCurve() && b.IsValid())
		require.True(t, b.IsValid())
		require.False(t, b.IsIdentity())
		require.False(t, b.IsBasePoint())
	}
}

func TestNewBlindProvidesDistinctPoints(t *testing.T) {
	const n = 1024
	seen := make(map[string]bool, n)
	// seen := make(map[core.EcPoint]bool, n)

	for i := 0; i < n; i++ {
		b, err := newBlind(curveScalar, curve)
		require.NoError(t, err)

		// serialize so the point is hashable
		txt := fmt.Sprintf("%#v", b)

		// We shouldn't see the same point twice
		ok := seen[txt]
		require.False(t, ok)

		// store
		seen[txt] = true
	}
}
