//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSecretKeyMarshal(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	data, err := SecretKey{curve.Scalar.One()}.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, data)
	e := &SecretKey{curve.Scalar.New(2)}
	err = e.UnmarshalBinary(data)
	require.NoError(t, err)
	require.Equal(t, e.value.Bytes(), curve.Scalar.One().Bytes())

	// element cannot be empty
	_, err = SecretKey{}.MarshalBinary()
	require.Error(t, err)
}

func TestPublicKeyMarshal(t *testing.T) {
	// Actually test both toBytes() and from()
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk := &SecretKey{curve.Scalar.New(3)}
	pk, _ := sk.GetPublicKey(curve)
	pkBytes, err := pk.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, pkBytes)

	pk2 := &PublicKey{}
	err = pk2.UnmarshalBinary(pkBytes)
	require.NoError(t, err)
	require.Equal(t, pk.value, pk2.value)
}

func TestBatch(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	sk, _ := new(SecretKey).New(curve, seed[:])
	element1 := curve.Scalar.Hash([]byte("value1"))
	element2 := curve.Scalar.Hash([]byte("value2"))
	elements := []Element{element1, element2}

	add, err := sk.BatchAdditions(elements)
	require.NoError(t, err)
	require.NotNil(t, add)

	del, err := sk.BatchDeletions(elements)
	require.NoError(t, err)
	require.NotNil(t, del)

	result := add.Mul(del)
	require.Equal(t, result, curve.Scalar.One())

	g1 := curve.PointG1.Generator()
	acc := g1.Mul(add)
	require.NotEqual(t, acc, g1)
	acc = acc.Mul(del)
	require.Equal(t, acc.ToAffineCompressed(), g1.ToAffineCompressed())

	acc2 := g1.Mul(result)
	require.Equal(t, acc2, g1)
}

func TestCoefficient(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(SecretKey).New(curve, []byte("1234567890"))
	element1 := curve.Scalar.Hash([]byte("value1"))
	element2 := curve.Scalar.Hash([]byte("value2"))
	element3 := curve.Scalar.Hash([]byte("value3"))
	element4 := curve.Scalar.Hash([]byte("value4"))
	element5 := curve.Scalar.Hash([]byte("value5"))
	elements := []Element{element1, element2, element3, element4, element5}
	coefficients, err := sk.CreateCoefficients(elements[0:2], elements[2:5])
	require.NoError(t, err)
	require.Equal(t, len(coefficients), 3)
}
