//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestNewAccumulator100(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	require.NoError(t, err)
	require.NotNil(t, key)
	acc, err := new(Accumulator).New(curve)
	require.NoError(t, err)
	require.NotNil(t, acc)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}

func TestNewAccumulator10K(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	require.NoError(t, err)
	require.NotNil(t, key)
	acc, err := new(Accumulator).New(curve)
	require.NoError(t, err)
	require.NotNil(t, acc)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}

func TestNewAccumulator10M(t *testing.T) {
	// Initiating 10M values takes time
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	require.NoError(t, err)
	require.NotNil(t, key)
	acc, err := new(Accumulator).New(curve)
	require.NoError(t, err)
	require.NotNil(t, acc)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}

func TestWithElements(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, _ := new(SecretKey).New(curve, seed[:])
	element1 := curve.Scalar.Hash([]byte("value1"))
	element2 := curve.Scalar.Hash([]byte("value2"))
	elements := []Element{element1, element2}
	newAcc, err := new(Accumulator).WithElements(curve, key, elements)
	require.NoError(t, err)
	require.NotNil(t, newAcc)
	require.NotEqual(t, newAcc.value.ToAffineCompressed(), curve.PointG1.Identity().ToAffineCompressed())
	require.NotEqual(t, newAcc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())

	_, _ = newAcc.Remove(key, element1)
	_, _ = newAcc.Remove(key, element2)
	require.Equal(t, newAcc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}

func TestAdd(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	require.NoError(t, err)
	require.NotNil(t, key)
	acc := &Accumulator{curve.PointG1.Generator()}
	_, _ = acc.New(curve)
	require.NoError(t, err)
	require.NotNil(t, acc)

	element := curve.Scalar.Hash([]byte("value1"))
	require.NoError(t, err)
	require.NotNil(t, element)
	_, _ = acc.Add(key, element)
	require.NotEqual(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}

func TestRemove(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	require.NoError(t, err)
	require.NotNil(t, key)
	acc, err := new(Accumulator).New(curve)
	require.NoError(t, err)
	require.NotNil(t, acc)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())

	element := curve.Scalar.Hash([]byte("value1"))
	require.NoError(t, err)
	require.NotNil(t, element)

	// add element
	_, _ = acc.Add(key, element)
	require.NotEqual(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())

	// remove element
	acc, err = acc.Remove(key, element)
	require.NoError(t, err)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}

func TestAddElements(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	require.NoError(t, err)
	require.NotNil(t, key)
	acc := &Accumulator{curve.PointG1.Generator()}
	_, _ = acc.New(curve)
	require.NoError(t, err)
	require.NotNil(t, acc)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())

	element1 := curve.Scalar.Hash([]byte("value1"))
	element2 := curve.Scalar.Hash([]byte("value2"))
	element3 := curve.Scalar.Hash([]byte("value3"))
	elements := []Element{element1, element2, element3}

	acc, err = acc.AddElements(key, elements)
	require.NoError(t, err)
	require.NotEqual(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}

func TestAccumulatorMarshal(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	point := curve.PointG1.Generator().Mul(curve.Scalar.New(2))
	data, err := Accumulator{point}.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, data)
	// element cannot be empty
	_, err = Accumulator{}.MarshalBinary()
	require.Error(t, err)

	e := &Accumulator{curve.PointG1.Generator()}
	_ = e.UnmarshalBinary(data)
	require.True(t, e.value.Equal(point))
}

func TestUpdate(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, err := new(SecretKey).New(curve, seed[:])
	require.NoError(t, err)
	require.NotNil(t, key)
	acc, err := new(Accumulator).New(curve)
	require.NoError(t, err)
	require.NotNil(t, acc)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())

	element1 := curve.Scalar.Hash([]byte("value1"))
	element2 := curve.Scalar.Hash([]byte("value2"))
	element3 := curve.Scalar.Hash([]byte("value3"))
	elements := []Element{element1, element2, element3}

	acc, _, err = acc.Update(key, elements, nil)
	require.NoError(t, err)
	require.NotEqual(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())

	acc, _, err = acc.Update(key, nil, elements)
	require.NoError(t, err)
	require.Equal(t, acc.value.ToAffineCompressed(), curve.PointG1.Generator().ToAffineCompressed())
}
