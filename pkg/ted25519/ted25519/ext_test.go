//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	v1 "github.com/coinbase/kryptology/pkg/sharing/v1"
)

const expectedSeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
const expectedPrivKeyHex = "307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f"

func TestExpandSeed(t *testing.T) {
	seedBytes, err := hex.DecodeString(expectedSeedHex)
	require.NoError(t, err)
	privKeyHex := hex.EncodeToString(ExpandSeed(seedBytes))
	require.Equal(t, expectedPrivKeyHex, privKeyHex)
}

func TestThresholdSign(t *testing.T) {
	pub, priv, err := generateKey()
	require.NoError(t, err)
	field := curves.NewField(curves.Ed25519Order())
	keyShare := v1.NewShamirShare(0, priv, field)
	r := big.NewInt(123456789).Bytes()
	nonceShare := v1.NewShamirShare(0, r, field)

	r = reverseBytes(r)
	var rInput [32]byte
	copy(rInput[:], r)
	scalar, err := new(curves.ScalarEd25519).SetBytesCanonical(rInput[:])
	require.NoError(t, err)
	noncePub := curves.ED25519().Point.Generator().Mul(scalar)

	message := []byte("fnord!")
	wrongMessage := []byte("23")
	sig := ThresholdSign(reverseBytes(keyShare.Value.Bytes()), pub, message, reverseBytes(nonceShare.Value.Bytes()), noncePub.ToAffineCompressed())

	ok, _ := Verify(pub, message, sig)
	require.True(t, ok)
	ok, _ = Verify(pub, wrongMessage, sig)
	require.False(t, ok)
}

func TestThresholdSign_invalid_secrets(t *testing.T) {
	message := []byte("fnord!")

	secret := []byte{0x02}
	secret = reverseBytes(secret)
	var sInput [32]byte
	copy(sInput[:], secret)
	scalar, err := new(curves.ScalarEd25519).SetBytesCanonical(sInput[:])
	require.NoError(t, err)
	pub := curves.ED25519().Point.Generator().Mul(scalar)

	nonce := []byte{0x03}
	nonce = reverseBytes(nonce)
	var nInput [32]byte
	copy(nInput[:], nonce)
	nScalar, err := new(curves.ScalarEd25519).SetBytesCanonical(nInput[:])
	require.NoError(t, err)
	noncePub := curves.ED25519().Point.Generator().Mul(nScalar)

	require.PanicsWithValue(t, "ed25519: bad key share length: 0",
		func() {
			ThresholdSign(make([]byte, 0), pub.ToAffineCompressed(), message, nonce, noncePub.ToAffineCompressed())
		},
	)

	require.PanicsWithValue(t, "ed25519: bad key share length: 33",
		func() {
			ThresholdSign(make([]byte, 33), pub.ToAffineCompressed(), message, nonce, noncePub.ToAffineCompressed())
		},
	)

	require.PanicsWithValue(t, "ed25519: bad nonce share length: 0",
		func() {
			ThresholdSign(secret, pub.ToAffineCompressed(), message, make([]byte, 0), noncePub.ToAffineCompressed())
		},
	)

	require.PanicsWithValue(t, "ed25519: bad nonce share length: 33",
		func() {
			ThresholdSign(secret, pub.ToAffineCompressed(), message, make([]byte, 33), noncePub.ToAffineCompressed())
		},
	)
}

// generateKey is the same as generateSharableKey, but used only for testing
func generateKey() (PublicKey, []byte, error) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	seed := priv.Seed()
	expandedSeed := reverseBytes(ExpandSeed(seed))
	field := &curves.Field{Int: curves.Ed25519Order()}
	expandedSeedReduced := field.ReducedElementFromBytes(expandedSeed)
	return pub, expandedSeedReduced.Bytes(), nil
}
