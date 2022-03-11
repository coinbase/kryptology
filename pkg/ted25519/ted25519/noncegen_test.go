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

func TestNonceShareFromBytes(t *testing.T) {
	field := curves.NewField(curves.Ed25519Order())
	share := &v1.ShamirShare{
		Identifier: 2,
		Value:      field.NewElement(big.NewInt(3)),
	}
	shareBytes := share.Bytes()
	recoveredShare := NonceShareFromBytes(shareBytes)
	require.Equal(t, recoveredShare.ShamirShare, share)
	require.Equal(t, share.Identifier, uint32(2))
}

func TestGenerateSharedNonce_congruence(t *testing.T) {
	config := &ShareConfiguration{T: 2, N: 3}
	message := []byte("fnord!")
	pubKey, keyShares, _, err := GenerateSharedKey(config)
	require.NoError(t, err)
	nonceCommitment, nonceShares, _, err := GenerateSharedNonce(config, keyShares[0], pubKey, message)
	require.NoError(t, err)
	field := curves.NewField(curves.Ed25519Order())
	shamir, err := v1.NewShamir(config.T, config.N, field)
	require.NoError(t, err)
	nonce, err := shamir.Combine(toShamirShare(nonceShares)...)
	require.NoError(t, err)

	nonce = reverseBytes(nonce)
	var nonceBytes [32]byte
	copy(nonceBytes[:], nonce)
	nonceScalar, err := new(curves.ScalarEd25519).SetBytesCanonical(nonceBytes[:])
	require.NoError(t, err)
	ed25519 := curves.ED25519()
	recoveredCommitment := ed25519.Point.Generator().Mul(nonceScalar)
	require.Equal(t, recoveredCommitment.ToAffineCompressed(), nonceCommitment.Bytes())
}

func TestGenerateNonce_non_determinism(t *testing.T) {
	config := &ShareConfiguration{T: 2, N: 3}
	message := []byte("fnord!")
	pubKey, keyShares, _, err := GenerateSharedKey(config)
	require.NoError(t, err)

	_, nonceShares1, _, err := GenerateSharedNonce(config, keyShares[0], pubKey, message)
	require.NoError(t, err)
	field := curves.NewField(curves.Ed25519Order())
	shamir, err := v1.NewShamir(config.T, config.N, field)
	require.NoError(t, err)
	nonce1, err := shamir.Combine(toShamirShare(nonceShares1)...)
	require.NoError(t, err)

	_, nonceShares2, _, err := GenerateSharedNonce(config, keyShares[1], pubKey, message)
	require.NoError(t, err)
	nonce2, err := shamir.Combine(toShamirShare(nonceShares2)...)
	require.NoError(t, err)

	_, nonceShares3, _, err := GenerateSharedNonce(config, keyShares[0], pubKey, message)
	require.NoError(t, err)
	nonce3, err := shamir.Combine(toShamirShare(nonceShares3)...)
	require.NoError(t, err)

	require.NotEqual(t, nonce1, nonce2)
	require.NotEqual(t, nonce1, nonce3)
}

func TestNonceSharesAdd(t *testing.T) {
	one := NewNonceShare(0, []byte{0x01})
	two := NewNonceShare(0, []byte{0x02})

	// basic addition
	sum := one.Add(two)
	require.Equal(t, uint32(0), sum.Identifier)
	require.Equal(t, []byte{0x03}, sum.Value.Bytes())
}

func TestNonceSharesAdd_errors(t *testing.T) {
	one := NewNonceShare(0, []byte{0x01})
	two := NewNonceShare(1, []byte{0x02})
	require.PanicsWithValue(t, "identifiers must match for valid addition", func() {
		one.Add(two)
	})
}

func toShamirShare(nonceShares []*NonceShare) []*v1.ShamirShare {
	shamirShares := make([]*v1.ShamirShare, len(nonceShares))
	for i, n := range nonceShares {
		shamirShares[i] = n.ShamirShare
	}
	return shamirShares
}
