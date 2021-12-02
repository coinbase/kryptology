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
	"github.com/stretchr/testify/assert"
)

func TestK256FeldmanSplitInvalidArgs(t *testing.T) {
	_, err := NewFeldman(0, 0, btcec.S256())
	assert.NotNil(t, err)
	_, err = NewFeldman(3, 2, btcec.S256())
	assert.NotNil(t, err)
	_, err = NewFeldman(1, 10, btcec.S256())
	assert.NotNil(t, err)
	scheme, err := NewFeldman(2, 3, btcec.S256())
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, _, err = scheme.Split([]byte{})
	assert.NotNil(t, err)
	_, _, err = scheme.Split([]byte{0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65})
	assert.NotNil(t, err)
}

func TestK256FeldmanCombineNoShares(t *testing.T) {
	scheme, err := NewFeldman(2, 3, btcec.S256())
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Combine()
	assert.NotNil(t, err)
}

func TestK256FeldmanCombineDuplicateShare(t *testing.T) {
	scheme, err := NewFeldman(2, 3, btcec.S256())
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

func TestK256FeldmanCombineBadIdentifier(t *testing.T) {
	scheme, err := NewFeldman(2, 3, btcec.S256())
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

func TestK256FeldmanCombineSingle(t *testing.T) {
	scheme, err := NewFeldman(2, 3, btcec.S256())
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	verifiers, shares, err := scheme.Split([]byte("test"))
	assert.Nil(t, err)
	assert.NotNil(t, shares)
	for _, s := range shares {
		ok, err := scheme.Verify(s, verifiers)
		assert.Nil(t, err)
		assert.True(t, ok)
	}
	secret, err := scheme.Combine(shares...)
	assert.Nil(t, err)
	assert.Equal(t, secret, []byte("test"))
}

func TestK256FeldmanAllCombinations(t *testing.T) {
	scheme, err := NewFeldman(3, 5, btcec.S256())
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	secret := []byte("test")
	verifiers, shares, err := scheme.Split(secret)
	for _, s := range shares {
		ok, err := scheme.Verify(s, verifiers)
		assert.Nil(t, err)
		assert.True(t, ok)
	}
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
