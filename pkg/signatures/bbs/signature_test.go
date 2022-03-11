//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
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
	require.NoError(t, err)
	generators, err := new(MessageGenerators).Init(pk, 4)
	require.NoError(t, err)

	sig, err := sk.Sign(generators, msgs)
	require.NoError(t, err)
	err = pk.Verify(sig, generators, msgs)
	require.NoError(t, err)
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
	require.NoError(t, err)
	generators, err := new(MessageGenerators).Init(pk, 4)
	require.NoError(t, err)

	sig, err := sk.Sign(generators, msgs)
	require.NoError(t, err)
	msgs[0] = curve.Scalar.New(7)
	err = pk.Verify(sig, generators, msgs)
	require.Error(t, err)
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
	require.NoError(t, err)
	generators, err := new(MessageGenerators).Init(pk, 4)
	require.NoError(t, err)

	sig, err := sk.Sign(generators, msgs)
	require.NoError(t, err)

	data, err := sig.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, 112, len(data))
	sig2 := new(Signature).Init(curve)
	err = sig2.UnmarshalBinary(data)
	require.NoError(t, err)
	require.True(t, sig.a.Equal(sig2.a))
	require.Equal(t, sig.e.Cmp(sig2.e), 0)
	require.Equal(t, sig.s.Cmp(sig2.s), 0)
}
