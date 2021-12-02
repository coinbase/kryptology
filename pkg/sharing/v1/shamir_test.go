//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirSplitInvalidArgs(t *testing.T) {
	_, err := NewShamir(0, 0, field)
	assert.NotNil(t, err)
	_, err = NewShamir(3, 2, field)
	assert.NotNil(t, err)
	_, err = NewShamir(1, 10, field)
	assert.NotNil(t, err)
	scheme, err := NewShamir(2, 3, field)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Split([]byte{})
	assert.NotNil(t, err)
	_, err = scheme.Split([]byte{0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65})
	assert.NotNil(t, err)
}

func TestShamirCombineNoShares(t *testing.T) {
	scheme, err := NewShamir(2, 3, field)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Combine()
	assert.NotNil(t, err)
}

func TestShamirCombineDuplicateShare(t *testing.T) {
	scheme, err := NewShamir(2, 3, field)
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

func TestShamirCombineBadIdentifier(t *testing.T) {
	scheme, err := NewShamir(2, 3, field)
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
	assert.NotNil(t, err)
}

func TestShamirCombineSingle(t *testing.T) {
	scheme, err := NewShamir(2, 3, field)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	shares, err := scheme.Split([]byte("test"))
	assert.Nil(t, err)
	assert.NotNil(t, shares)
	secret, err := scheme.Combine(shares...)
	assert.Nil(t, err)
	assert.Equal(t, secret, []byte("test"))
}

// Test ComputeL function to compute Lagrange coefficients.
func TestShamirComputeL(t *testing.T) {
	scheme, err := NewShamir(2, 2, field)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	secret := []byte("test")
	shares, err := scheme.Split(secret)
	assert.Nil(t, err)
	assert.NotNil(t, shares)
	lCoeffs, err := scheme.ComputeL(shares[0], shares[1])
	assert.Nil(t, err)
	assert.NotNil(t, lCoeffs)

	// Checking we can reconstruct the same secret using Lagrange coefficients.
	inputShares := [2]*ShamirShare{shares[0], shares[1]}
	yCoordinates := make([]*curves.Element, 2)
	for i := 0; i < 2; i++ {
		r := inputShares[i]
		yCoordinates[i] = r.Value
	}
	result := yCoordinates[0].Field().Zero()
	for i := 0; i < 2; i++ {
		result = result.Add(yCoordinates[i].Mul(lCoeffs[i]))
	}
	assert.Equal(t, result.Bytes(), secret)
}

func TestShamirAllCombinations(t *testing.T) {
	scheme, err := NewShamir(3, 5, field)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	secret := []byte("test")
	shares, err := scheme.Split(secret)
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
	oneBelowModulus := new(big.Int).Sub(modulus, big.NewInt(1))
	shares := []ShamirShare{
		{0, field.NewElement(big.NewInt(300))},
		{2, field.NewElement(big.NewInt(300000))},
		{20, field.NewElement(big.NewInt(12812798))},
		{31, field.NewElement(big.NewInt(17))},
		{57, field.NewElement(big.NewInt(5066680))},
		{128, field.NewElement(big.NewInt(3005))},
		{19, field.NewElement(big.NewInt(317))},
		{7, field.NewElement(big.NewInt(323))},
		{222, field.NewElement(oneBelowModulus)},
	}
	// Run all the tests!
	for _, in := range shares {
		bytes, err := json.Marshal(in)
		require.NoError(t, err)
		require.NotNil(t, bytes)

		// Unmarshal and test
		out := &ShamirShare{}
		err = json.Unmarshal(bytes, &out)
		require.NoError(t, err)
		assert.Equal(t, in.Identifier, out.Identifier)
		assert.Equal(t, in.Value.Value.Bytes(), out.Value.Value.Bytes())
	}
}

func TestSharesAdd(t *testing.T) {
	finiteField := curves.NewField(big.NewInt(7))
	one := NewShamirShare(0, []byte{0x01}, finiteField)
	two := NewShamirShare(0, []byte{0x02}, finiteField)

	// basic addition
	sum := one.Add(two)
	assert.Equal(t, uint32(0), sum.Identifier)
	assert.Equal(t, []byte{0x03}, sum.Value.Bytes())

	// addition is performed within the globalField
	sum = two.Add(NewShamirShare(0, []byte{0x06}, finiteField))
	assert.Equal(t, uint32(0), sum.Identifier)
	assert.Equal(t, []byte{0x01}, sum.Value.Bytes())
}

func TestSharesAdd_errors(t *testing.T) {
	finiteField := curves.NewField(big.NewInt(7))
	one := NewShamirShare(0, []byte{0x01}, finiteField)
	two := NewShamirShare(1, []byte{0x02}, finiteField)
	assert.PanicsWithValue(t, "identifiers must match for valid addition", func() {
		one.Add(two)
	})
}
