//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	core "github.com/coinbase/kryptology/pkg/core/curves"
)

var (
	k256BasePoint    = &core.EcPoint{Curve: btcec.S256(), X: btcec.S256().Gx, Y: btcec.S256().Gy}
	testPointK256, _ = core.NewScalarBaseMult(btcec.S256(), big.NewInt(2222))
)

func TestK256PedersenSplitInvalidArgs(t *testing.T) {
	_, err := NewPedersen(0, 0, nil)
	require.NotNil(t, err)
	_, err = NewPedersen(3, 2, nil)
	require.NotNil(t, err)
	_, err = NewPedersen(1, 10, nil)
	require.NotNil(t, err)
	_, err = NewPedersen(2, 3, nil)
	require.NotNil(t, err)
	scheme, err := NewPedersen(2, 3, k256BasePoint)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Split([]byte{})
	require.NotNil(t, err)
	// test that split doesn't work on secrets bigger than the modulus
	_, err = scheme.Split([]byte{0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65})
	require.NotNil(t, err)
}

func TestK256PedersenCombineNoShares(t *testing.T) {
	scheme, err := NewPedersen(2, 3, k256BasePoint)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.NotNil(t, err)
}

func TestK256PedersenCombineDuplicateShare(t *testing.T) {
	scheme, err := NewPedersen(2, 3, k256BasePoint)
	require.Nil(t, err)
	require.NotNil(t, scheme)
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
	require.NotNil(t, err)
}

func TestK256PedersenCombineBadIdentifier(t *testing.T) {
	scheme, err := NewPedersen(2, 3, k256BasePoint)
	require.Nil(t, err)
	require.NotNil(t, scheme)
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
	require.NotNil(t, err)
	shares[0] = &ShamirShare{
		Identifier: 4,
		Value:      field.NewElement(big.NewInt(3)),
	}
	_, err = scheme.Combine(shares...)
	require.Error(t, err)
}

func TestK256GeneratorFromHashedBytes(t *testing.T) {
	x, y, err := K256GeneratorFromHashedBytes([]byte("Fair is foul, and foul is fair: Hover through the fog and filthy air."))
	require.NoError(t, err)
	require.NotNil(t, x)
	require.NotNil(t, y)
	require.True(t, btcec.S256().IsOnCurve(x, y))
}

func TestK256PedersenCombineSingle(t *testing.T) {
	scheme, err := NewPedersen(2, 3, testPointK256)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	result, err := scheme.Split([]byte("test"))
	require.Nil(t, err)
	require.NotNil(t, result)
	for i, s := range result.SecretShares {
		ok, err := scheme.Verify(s, result.BlindingShares[i], result.BlindedVerifiers)
		require.Nil(t, err)
		require.True(t, ok)
	}
	secret, err := scheme.Combine(result.SecretShares...)
	require.Nil(t, err)
	require.Equal(t, secret, []byte("test"))
}

func TestK256PedersenAllCombinations(t *testing.T) {
	scheme, err := NewPedersen(3, 5, testPointK256)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := []byte("test")
	result, err := scheme.Split(secret)
	for i, s := range result.SecretShares {
		ok, err := scheme.Verify(s, result.BlindingShares[i], result.BlindedVerifiers)
		require.Nil(t, err)
		require.True(t, ok)
	}
	require.Nil(t, err)
	require.NotNil(t, result)
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
				require.Nil(t, err)
				require.NotNil(t, rSecret)
				require.Equal(t, rSecret, secret)

				bSecret, err := scheme.Combine(result.BlindingShares[i], result.BlindingShares[j], result.BlindingShares[k])
				require.Nil(t, err)
				require.NotNil(t, bSecret)
				require.Equal(t, bSecret, result.Blinding.Bytes())
			}
		}
	}
}
