//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sharing

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirSplitInvalidArgs(t *testing.T) {
	curve := curves.ED25519()
	_, err := NewShamir(0, 0, curve)
	assert.NotNil(t, err)
	_, err = NewShamir(3, 2, curve)
	assert.NotNil(t, err)
	_, err = NewShamir(1, 10, curve)
	assert.NotNil(t, err)
	scheme, err := NewShamir(2, 3, curve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Split(curve.NewScalar(), crand.Reader)
	assert.NotNil(t, err)
}

func TestShamirCombineNoShares(t *testing.T) {
	curve := curves.ED25519()
	scheme, err := NewShamir(2, 3, curve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Combine()
	assert.NotNil(t, err)
}

func TestShamirCombineDuplicateShare(t *testing.T) {
	curve := curves.ED25519()
	scheme, err := NewShamir(2, 3, curve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Combine([]*ShamirShare{
		{
			Id:    1,
			Value: curve.NewScalar().New(3).Bytes(),
		},
		{
			Id:    1,
			Value: curve.NewScalar().New(3).Bytes(),
		},
	}...)
	assert.NotNil(t, err)
}

func TestShamirCombineBadIdentifier(t *testing.T) {
	curve := curves.ED25519()
	scheme, err := NewShamir(2, 3, curve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	shares := []*ShamirShare{
		{
			Id:    0,
			Value: curve.NewScalar().New(3).Bytes(),
		},
		{
			Id:    2,
			Value: curve.NewScalar().New(3).Bytes(),
		},
	}
	_, err = scheme.Combine(shares...)
	assert.NotNil(t, err)
	shares[0] = &ShamirShare{
		Id:    4,
		Value: curve.NewScalar().New(3).Bytes(),
	}
	_, err = scheme.Combine(shares...)
	assert.NotNil(t, err)
}

func TestShamirCombineSingle(t *testing.T) {
	curve := curves.ED25519()
	scheme, err := NewShamir(2, 3, curve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	shares, err := scheme.Split(curve.NewScalar().Hash([]byte("test")), crand.Reader)
	assert.Nil(t, err)
	assert.NotNil(t, shares)
	secret, err := scheme.Combine(shares...)
	assert.Nil(t, err)
	assert.Equal(t, secret, curve.NewScalar().Hash([]byte("test")))
}

// Test ComputeL function to compute Lagrange coefficients.
func TestShamirComputeL(t *testing.T) {
	curve := curves.ED25519()
	scheme, err := NewShamir(2, 2, curve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	secret := curve.Scalar.Hash([]byte("test"))
	shares, err := scheme.Split(secret, crand.Reader)
	assert.Nil(t, err)
	assert.NotNil(t, shares)
	lCoeffs, err := scheme.LagrangeCoeffs(map[uint32]*ShamirShare{1: shares[0], 2: shares[1]})
	assert.Nil(t, err)
	assert.NotNil(t, lCoeffs)

	// Checking we can reconstruct the same secret using Lagrange coefficients.
	result := curve.NewScalar()
	for _, r := range shares {
		rc, _ := curve.Scalar.SetBytes(r.Value)
		result = result.Add(rc.Mul(lCoeffs[r.Id]))
	}
	assert.Equal(t, result.Bytes(), secret.Bytes())
}

func TestShamirAllCombinations(t *testing.T) {
	curve := curves.ED25519()
	scheme, err := NewShamir(3, 5, curve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	secret := curve.Scalar.Hash([]byte("test"))
	shares, err := scheme.Split(secret, crand.Reader)
	assert.Nil(t, err)
	assert.NotNil(t, shares)
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
				assert.Nil(t, err)
				assert.NotNil(t, rSecret)
				assert.Equal(t, rSecret, secret)
			}
		}
	}
}

// Ensures that ShamirShare's un/marshal successfully.
func TestMarshalJsonRoundTrip(t *testing.T) {
	curve := curves.ED25519()
	shares := []ShamirShare{
		{0, curve.Scalar.New(300).Bytes()},
		{2, curve.Scalar.New(300000).Bytes()},
		{20, curve.Scalar.New(12812798).Bytes()},
		{31, curve.Scalar.New(17).Bytes()},
		{57, curve.Scalar.New(5066680).Bytes()},
		{128, curve.Scalar.New(3005).Bytes()},
		{19, curve.Scalar.New(317).Bytes()},
		{7, curve.Scalar.New(323).Bytes()},
		{222, curve.NewScalar().New(-1).Bytes()},
	}
	// Run all the tests!
	for _, in := range shares {
		input, err := json.Marshal(in)
		require.NoError(t, err)
		require.NotNil(t, input)

		// Unmarshal and test
		out := &ShamirShare{}
		//out.Value = curve.NewScalar()
		err = json.Unmarshal(input, &out)
		require.NoError(t, err)
		assert.Equal(t, in.Id, out.Id)
		assert.Equal(t, bytes.Compare(in.Value, out.Value), 0)
	}
}
