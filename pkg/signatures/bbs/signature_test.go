//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSignatureWorks(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	msgs := []curves.Scalar{
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
		curve.Scalar.New(6),
	}
	pk, sk, err := NewKeys(curve)
	assert.NoError(t, err)
	generators := new(MessageGenerators).Init(pk, 4)

	sig, err := sk.Sign(generators, msgs)
	assert.NoError(t, err)
	err = pk.Verify(sig, generators, msgs)
	assert.NoError(t, err)
}

func TestSignatureIncorrectMessages(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	msgs := []curves.Scalar{
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
		curve.Scalar.New(6),
	}
	pk, sk, err := NewKeys(curve)
	assert.NoError(t, err)
	generators := new(MessageGenerators).Init(pk, 4)

	sig, err := sk.Sign(generators, msgs)
	assert.NoError(t, err)
	msgs[0] = curve.Scalar.New(7)
	err = pk.Verify(sig, generators, msgs)
	assert.Error(t, err)
}

func TestSignatureMarshalBinary(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	msgs := []curves.Scalar{
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
		curve.Scalar.New(6),
	}
	pk, sk, err := NewKeys(curve)
	assert.NoError(t, err)
	generators := new(MessageGenerators).Init(pk, 4)

	sig, err := sk.Sign(generators, msgs)
	assert.NoError(t, err)

	data, err := sig.MarshalBinary()
	assert.NoError(t, err)
	assert.Equal(t, 112, len(data))
	sig2 := new(Signature).Init(curve)
	err = sig2.UnmarshalBinary(data)
	assert.NoError(t, err)
	assert.True(t, sig.a.Equal(sig2.a))
	assert.Equal(t, sig.e.Cmp(sig2.e), 0)
	assert.Equal(t, sig.s.Cmp(sig2.s), 0)
}
