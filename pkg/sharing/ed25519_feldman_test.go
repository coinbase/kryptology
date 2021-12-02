//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sharing

import (
	crand "crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testCurve = curves.ED25519()

func TestEd25519FeldmanSplitInvalidArgs(t *testing.T) {
	_, err := NewFeldman(0, 0, testCurve)
	assert.NotNil(t, err)
	_, err = NewFeldman(3, 2, testCurve)
	assert.NotNil(t, err)
	_, err = NewFeldman(1, 10, testCurve)
	assert.NotNil(t, err)
	scheme, err := NewFeldman(2, 3, testCurve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, _, err = scheme.Split(testCurve.NewScalar(), crand.Reader)
	assert.NotNil(t, err)
}

func TestEd25519FeldmanCombineNoShares(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
	_, err = scheme.Combine()
	assert.NotNil(t, err)
}

func TestEd25519FeldmanCombineDuplicateShare(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
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
	assert.NotNil(t, err)
}

func TestEd25519FeldmanCombineBadIdentifier(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)
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
	assert.NotNil(t, err)
	shares[0] = &ShamirShare{
		Id:    4,
		Value: testCurve.Scalar.New(3).Bytes(),
	}
	_, err = scheme.Combine(shares...)
	assert.NotNil(t, err)
}

func TestEd25519FeldmanCombineSingle(t *testing.T) {
	scheme, err := NewFeldman(2, 3, testCurve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	secret := testCurve.Scalar.Hash([]byte("test"))
	verifiers, shares, err := scheme.Split(secret, crand.Reader)
	assert.Nil(t, err)
	assert.NotNil(t, shares)
	for _, s := range shares {
		err = verifiers.Verify(s)
		assert.Nil(t, err)
	}
	secret2, err := scheme.Combine(shares...)
	assert.Nil(t, err)
	assert.Equal(t, secret2, secret)
}

func TestEd25519FeldmanAllCombinations(t *testing.T) {
	scheme, err := NewFeldman(3, 5, testCurve)
	assert.Nil(t, err)
	assert.NotNil(t, scheme)

	secret := testCurve.Scalar.Hash([]byte("test"))
	verifiers, shares, err := scheme.Split(secret, crand.Reader)
	for _, s := range shares {
		err = verifiers.Verify(s)
		assert.Nil(t, err)
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
