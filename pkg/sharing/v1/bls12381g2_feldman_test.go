//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBls12381G2FeldmanSplitInvalidArgs(t *testing.T) {
	_, err := NewFeldman(0, 0, Bls12381G2())
	require.NotNil(t, err)
	_, err = NewFeldman(3, 2, Bls12381G2())
	require.NotNil(t, err)
	_, err = NewFeldman(1, 10, Bls12381G2())
	require.NotNil(t, err)
	scheme, err := NewFeldman(2, 3, Bls12381G2())
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, _, err = scheme.Split([]byte{})
	require.NotNil(t, err)
	_, _, err = scheme.Split([]byte{0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65})
	require.NotNil(t, err)
}

func TestBls12381G2FeldmanCombineNoShares(t *testing.T) {
	scheme, err := NewFeldman(2, 3, Bls12381G2())
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.NotNil(t, err)
}

func TestBls12381G2FeldmanCombineDuplicateShare(t *testing.T) {
	scheme, err := NewFeldman(2, 3, Bls12381G2())
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

func TestBls12381G2FeldmanCombineBadIdentifier(t *testing.T) {
	scheme, err := NewFeldman(2, 3, Bls12381G2())
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
	require.NotNil(t, err)
}

func TestBls12381G2FeldmanCombineSingle(t *testing.T) {
	scheme, err := NewFeldman(2, 3, Bls12381G2())
	require.Nil(t, err)
	require.NotNil(t, scheme)

	verifiers, shares, err := scheme.Split([]byte("test"))
	require.Nil(t, err)
	require.NotNil(t, shares)
	for _, s := range shares {
		ok, err := scheme.Verify(s, verifiers)
		require.Nil(t, err)
		require.True(t, ok)
	}
	secret, err := scheme.Combine(shares...)
	require.Nil(t, err)
	require.Equal(t, secret, []byte("test"))
}

func TestBls12381G2FeldmanAllCombinations(t *testing.T) {
	scheme, err := NewFeldman(3, 5, Bls12381G2())
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := []byte("test")
	verifiers, shares, err := scheme.Split(secret)
	for _, s := range shares {
		ok, err := scheme.Verify(s, verifiers)
		require.Nil(t, err)
		require.True(t, ok)
	}
	require.Nil(t, err)
	require.NotNil(t, shares)
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

				rSecret, err := scheme.Combine(shares[i], shares[j], shares[k])
				require.Nil(t, err)
				require.NotNil(t, rSecret)
				require.Equal(t, rSecret, secret)
			}
		}
	}
}
