//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"crypto/sha512"
	core "github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
	"testing"

	"filippo.io/edwards25519"
	"github.com/coinbase/kryptology/internal"
	"github.com/stretchr/testify/assert"
)

var (
	ed25519BasePoint    = &core.EcPoint{Curve: Ed25519(), X: Ed25519().Gx, Y: Ed25519().Gy}
	testPointEd25519, _ = core.NewScalarBaseMult(Ed25519(), big.NewInt(2222))
)

func TestEd25519PedersenSplitInvalidArgs(t *testing.T) {
	_, err := NewPedersen(0, 0, nil)
	assert.NotNil(t, err)
	_, err = NewPedersen(3, 2, nil)
	assert.NotNil(t, err)
	_, err = NewPedersen(1, 10, nil)
	assert.NotNil(t, err)
	_, err = NewPedersen(2, 3, nil)
	assert.NotNil(t, err)
	scheme, err := NewPedersen(2, 3, ed25519BasePoint)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Split([]byte{})
	assert.NotNil(t, err)
	// test that split doesn't work on secrets bigger than the modulus
	_, err = scheme.Split([]byte{0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65})
	assert.NotNil(t, err)
}

func TestEd25519PedersenCombineNoShares(t *testing.T) {
	scheme, err := NewPedersen(2, 3, ed25519BasePoint)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Combine()
	assert.NotNil(t, err)
}

func TestEd25519PedersenCombineDuplicateShare(t *testing.T) {
	scheme, err := NewPedersen(2, 3, ed25519BasePoint)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Combine([]*ShamirShare{
		{
			Identifier: 1,
			Value:      field.NewElement(big.NewInt(3)),
		},
		{
			Identifier: 1,
			Value:      field.NewElement(big.NewInt(3)),
		},
	}...)
	assert.NotNil(t, err)
}

func TestEd25519PedersenCombineBadIdentifier(t *testing.T) {
	scheme, err := NewPedersen(2, 3, ed25519BasePoint)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	shares := []*ShamirShare{
		{
			Identifier: 0,
			Value:      field.NewElement(big.NewInt(3)),
		},
		{
			Identifier: 2,
			Value:      field.NewElement(big.NewInt(3)),
		},
	}
	_, err = scheme.Combine(shares...)
	assert.NotNil(t, err)
	shares[0] = &ShamirShare{
		Identifier: 4,
		Value:      field.NewElement(big.NewInt(3)),
	}
	_, err = scheme.Combine(shares...)
	assert.Error(t, err)
}

func TestEd25519PedersenCombineSingle(t *testing.T) {
	scheme, err := NewPedersen(2, 3, testPointEd25519)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	hBytes := sha512.Sum512([]byte("test"))
	var arr [32]byte
	copy(arr[:], hBytes[:])
	sc, err := edwards25519.NewScalar().SetBytesWithClamping(arr[:])
	assert.Nil(t, err)
	result, err := scheme.Split(internal.ReverseScalarBytes(sc.Bytes()))
	assert.Nil(t, err)
	assert.NotNil(t, result)
	for i, s := range result.SecretShares {
		ok, err := scheme.Verify(s, result.BlindingShares[i], result.BlindedVerifiers)
		assert.Nil(t, err)
		assert.True(t, ok)
	}
	secret, err := scheme.Combine(result.SecretShares...)
	assert.Nil(t, err)
	assert.Equal(t, internal.ReverseScalarBytes(secret), sc.Bytes())
}

func TestEd25519PedersenAllCombinations(t *testing.T) {
	scheme, err := NewPedersen(3, 5, testPointEd25519)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	secret := []byte("test")
	result, err := scheme.Split(secret)
	for i, s := range result.SecretShares {
		ok, err := scheme.Verify(s, result.BlindingShares[i], result.BlindedVerifiers)
		assert.Nil(t, err)
		assert.True(t, ok)
	}
	assert.Nil(t, err)
	assert.NotNil(t, result)
	// There are 5*4*3 possible combinations
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if i == j {
				continue
			}
			for k := 0; k < 5; k++ {
				if i == k || j == k {
					continue
				}

				rSecret, err := scheme.Combine(result.SecretShares[i], result.SecretShares[j], result.SecretShares[k])
				assert.Nil(t, err)
				assert.NotNil(t, rSecret)
				assert.Equal(t, rSecret, secret)

				bSecret, err := scheme.Combine(result.BlindingShares[i], result.BlindingShares[j], result.BlindingShares[k])
				assert.Nil(t, err)
				assert.NotNil(t, bSecret)
				assert.Equal(t, bSecret, result.Blinding.Bytes())
			}
		}
	}
}
