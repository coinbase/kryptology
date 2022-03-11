//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	v1 "github.com/coinbase/kryptology/pkg/sharing/v1"
)

func TestGenerateEd25519Key(t *testing.T) {
	config := ShareConfiguration{T: 2, N: 3}

	// Generate and verify correct number of shares are produced
	pub, shares, _, err := GenerateSharedKey(&config)
	require.NoError(t, err)
	require.Equal(t, config.N, len(shares))

	// Verify reconstuction works for all permutations of shares
	shareVec := make([]*KeyShare, 2)
	shareVec[0] = shares[0]
	shareVec[1] = shares[1]
	secret1, err := Reconstruct(shareVec, &config)
	require.Nil(t, err)
	shareVec[0] = shares[1]
	shareVec[1] = shares[2]
	secret2, err := Reconstruct(shareVec, &config)
	require.Nil(t, err)
	shareVec[0] = shares[0]
	shareVec[1] = shares[2]
	secret3, err := Reconstruct(shareVec, &config)
	require.Nil(t, err)
	require.Equal(t, secret1, secret2)
	require.Equal(t, secret2, secret3)

	// Need to reverse secret1
	secret1 = reverseBytes(secret1)
	var secret1Bytes [32]byte
	copy(secret1Bytes[:], secret1)
	scalar1, err := new(curves.ScalarEd25519).SetBytesCanonical(secret1Bytes[:])
	require.NoError(t, err)
	ed25519 := curves.ED25519()
	pubFromSeed := ed25519.Point.Generator().Mul(scalar1)

	require.NoError(t, err)
	require.Equal(t, pubFromSeed.ToAffineCompressed(), pub.Bytes())
}

func TestGenerateEd25519KeyInvalidConfig(t *testing.T) {
	invalidConfig := ShareConfiguration{T: 1, N: 1}
	_, _, _, err := GenerateSharedKey(&invalidConfig)
	require.NotNil(t, err)
	require.Error(t, err)

	invalidConfig = ShareConfiguration{T: 2, N: 1}
	_, _, _, err = GenerateSharedKey(&invalidConfig)
	require.NotNil(t, err)
	require.Error(t, err)
}

func TestVerifyVSSEd25519(t *testing.T) {

	config := ShareConfiguration{T: 2, N: 3}
	pubKey1, shares1, commitments1, err := GenerateSharedKey(&config)
	require.NoError(t, err)
	pubKey2, shares2, commitments2, err := GenerateSharedKey(&config)
	require.NoError(t, err)

	require.Equal(t, pubKey1.Bytes(), commitments1[0].ToAffineCompressed())
	require.Equal(t, pubKey2.Bytes(), commitments2[0].ToAffineCompressed())

	for _, s := range shares1 {
		ok, err := s.VerifyVSS(commitments1, &config)
		require.NoError(t, err)
		require.True(t, ok)
		ok, _ = s.VerifyVSS(commitments2, &config)
		require.True(t, !ok)
	}

	for _, s := range shares2 {
		ok, err := s.VerifyVSS(commitments2, &config)
		require.NoError(t, err)
		require.True(t, ok)
		ok, _ = s.VerifyVSS(commitments1, &config)
		require.True(t, !ok)
	}
}

func TestCommitmentsFromBytes(t *testing.T) {
	config := ShareConfiguration{T: 2, N: 3}
	_, _, comms, err := GenerateSharedKey(&config)
	require.NoError(t, err)

	recoveredComms, err := CommitmentsFromBytes(comms.CommitmentsToBytes())
	require.NoError(t, err)
	require.Equal(t, len(comms), len(recoveredComms))
	for i := range comms {
		require.True(t, comms[i].Equal(recoveredComms[i]))
	}
	_, err = CommitmentsFromBytes([][]byte{{0x01}})
	require.Error(t, err)
}

func TestPublicKeyFromBytes(t *testing.T) {
	_, err := PublicKeyFromBytes([]byte{0x01})
	require.EqualError(t, err, "invalid public key size: 1")
}

func TestKeyShareFromBytes(t *testing.T) {
	field := curves.NewField(curves.Ed25519Order())
	share := &v1.ShamirShare{
		Identifier: 2,
		Value:      field.NewElement(big.NewInt(3)),
	}
	shareBytes := share.Bytes()
	recoveredShare := KeyShareFromBytes(shareBytes)
	require.Equal(t, recoveredShare.ShamirShare, share)
}
