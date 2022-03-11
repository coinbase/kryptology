//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sharing

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

var testCurve = curves.ED25519()

func TestEd25519FeldmanSplitInvalidArgs(t *testing.T) {
	_, err := NewFeldman(0, 0, testCurve)
	require.NotNil(t, err)
	_, err = NewFeldman(3, 2, testCurve)
	require.NotNil(t, err)
	_, err = NewFeldman(1, 10, testCurve)
	require.NotNil(t, err)
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, _, err = scheme.Split(testCurve.NewScalar(), crand.Reader)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineNoShares(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineDuplicateShare(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine([]*ShamirShare{
		{
			Id:    1,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
		{
			Id:    1,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
	}...)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineBadIdentifier(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)
	shares := []*ShamirShare{
		{
			Id:    0,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
		{
			Id:    2,
			Value: testCurve.Scalar.New(3).Bytes(),
		},
	}
	_, err = scheme.Combine(shares...)
	require.NotNil(t, err)
	shares[0] = &ShamirShare{
		Id:    4,
		Value: testCurve.Scalar.New(3).Bytes(),
	}
	_, err = scheme.Combine(shares...)
	require.NotNil(t, err)
}

func TestEd25519FeldmanCombineSingle(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := testCurve.Scalar.Hash([]byte("test"))
	verifiers, shares, err := scheme.Split(secret, crand.Reader)
	require.Nil(t, err)
	require.NotNil(t, shares)
	for _, s := range shares {
		err = verifiers.Verify(s)
		require.Nil(t, err)
	}
	secret2, err := scheme.Combine(shares...)
	require.Nil(t, err)
	require.Equal(t, secret2, secret)
}

func TestEd25519FeldmanAllCombinations(t *testing.T) {
	scheme, err := NewFeldman(3, 5, testCurve)
	require.Nil(t, err)
	require.NotNil(t, scheme)

	secret := testCurve.Scalar.Hash([]byte("test"))
	verifiers, shares, err := scheme.Split(secret, crand.Reader)
	for _, s := range shares {
		err = verifiers.Verify(s)
		require.Nil(t, err)
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
