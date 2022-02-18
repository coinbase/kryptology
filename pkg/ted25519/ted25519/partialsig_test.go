//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
)

func TestPartialSignNormalSignature(t *testing.T) {
	pub, priv, err := generateSharableKey()
	require.NoError(t, err)
	keyShare := NewKeyShare(0, priv)
	r := big.NewInt(123456789).Bytes()
	nonceShare := NewNonceShare(0, r)

	r = reverseBytes(r)
	var rInput [32]byte
	copy(rInput[:], r)
	scalar, err := new(curves.ScalarEd25519).SetBytesCanonical(rInput[:])
	require.NoError(t, err)
	noncePub := curves.ED25519().Point.Generator().Mul(scalar)

	message := []byte("test message")
	wrongMessage := []byte("wrong message")
	sig := TSign(message, keyShare, pub, nonceShare, noncePub.ToAffineCompressed())

	ok, _ := Verify(pub, message, sig.Sig)
	require.True(t, ok)
	ok, _ = Verify(pub, wrongMessage, sig.Sig)
	require.False(t, ok)
}

func TestNewPartialSignature(t *testing.T) {
	s := []byte("11111111111111111111111111111111")
	r := []byte("22222222222222222222222222222222")
	sigBytes := []byte("2222222222222222222222222222222211111111111111111111111111111111")
	sig := NewPartialSignature(1, sigBytes)

	require.Equal(t, byte(1), sig.ShareIdentifier)
	require.Equal(t, s, sig.S())
	require.Equal(t, r, sig.R())
	require.Equal(t, sigBytes, sig.Bytes())

	require.PanicsWithValue(t, "ted25519: invalid partial signature length: 3", func() {
		NewPartialSignature(1, []byte("sig"))
	})
}
