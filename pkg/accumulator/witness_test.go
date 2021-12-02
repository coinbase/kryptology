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

func Test_Membership_Witness_New(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	var seed [32]byte
	key, _ := new(SecretKey).New(curve, seed[:])
	acc, _ := new(Accumulator).New(curve)
	e := curve.Scalar.New(2)
	mw, err := new(MembershipWitness).New(e, acc, key)
	require.NoError(t, err)
	require.NotNil(t, mw.c)
	require.NotNil(t, mw.y)
}

func Test_Membership_Witness_Marshal(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	mw := &MembershipWitness{
		curve.PointG1.Generator().Mul(curve.Scalar.New(10)),
		curve.Scalar.New(15),
	}
	data, err := mw.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, data)
	newMW := &MembershipWitness{}
	err = newMW.UnmarshalBinary(data)
	require.NoError(t, err)
	require.Equal(t, mw.c, newMW.c)
	require.Equal(t, mw.y, newMW.y)
}

func Test_Membership(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)

	element1 := curve.Scalar.Hash([]byte("3"))
	element2 := curve.Scalar.Hash([]byte("4"))
	element3 := curve.Scalar.Hash([]byte("5"))
	element4 := curve.Scalar.Hash([]byte("6"))
	element5 := curve.Scalar.Hash([]byte("7"))
	element6 := curve.Scalar.Hash([]byte("8"))
	element7 := curve.Scalar.Hash([]byte("9"))
	elements := []Element{element1, element2, element3, element4, element5, element6, element7}

	// nm_witness_max works as well if set to value larger than 0 for this test.x
	acc, err := new(Accumulator).WithElements(curve, sk, elements)
	require.NoError(t, err)
	require.NotNil(t, acc.value)
	require.False(t, acc.value.IsIdentity())
	require.True(t, acc.value.IsOnCurve())
	require.NotEqual(t, acc.value, curve.NewG1GeneratorPoint())

	wit, err := new(MembershipWitness).New(elements[3], acc, sk)
	require.NoError(t, err)
	require.Equal(t, wit.y, elements[3])

	err = wit.Verify(pk, acc)
	require.NoError(t, err)

	// Test wrong cases, forge a wrong witness
	wrongWit := MembershipWitness{
		curve.PointG1.Identity(),
		curve.Scalar.One(),
	}
	err = wrongWit.Verify(pk, acc)
	require.Error(t, err)

	// Test wrong cases, forge a wrong accumulator
	wrongAcc := &Accumulator{
		curve.PointG1.Generator(),
	}
	err = wit.Verify(pk, wrongAcc)
	require.Error(t, err)
}

func Test_Membership_Batch_Update(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)

	element1 := curve.Scalar.Hash([]byte("3"))
	element2 := curve.Scalar.Hash([]byte("4"))
	element3 := curve.Scalar.Hash([]byte("5"))
	element4 := curve.Scalar.Hash([]byte("6"))
	element5 := curve.Scalar.Hash([]byte("7"))
	element6 := curve.Scalar.Hash([]byte("8"))
	element7 := curve.Scalar.Hash([]byte("9"))
	elements := []Element{element1, element2, element3, element4, element5, element6, element7}

	// nm_witness_max works as well if set to value larger than 0 for this test.
	acc, err := new(Accumulator).WithElements(curve, sk, elements)
	require.NoError(t, err)
	require.NotNil(t, acc.value)

	wit, err := new(MembershipWitness).New(elements[3], acc, sk)
	require.NoError(t, err)
	require.Equal(t, wit.y, elements[3])

	err = wit.Verify(pk, acc)
	require.Nil(t, err)

	data1 := curve.Scalar.Hash([]byte("1"))
	data2 := curve.Scalar.Hash([]byte("2"))
	data3 := curve.Scalar.Hash([]byte("3"))
	data4 := curve.Scalar.Hash([]byte("4"))
	data5 := curve.Scalar.Hash([]byte("5"))
	data := []Element{data1, data2, data3, data4, data5}
	additions := data[0:2]
	deletions := data[2:5]
	_, coefficients, err := acc.Update(sk, additions, deletions)
	require.NoError(t, err)
	require.NotNil(t, coefficients)

	_, err = wit.BatchUpdate(additions, deletions, coefficients)
	require.NoError(t, err)
	err = wit.Verify(pk, acc)
	require.Nil(t, err)
}

func Test_Membership_Multi_Batch_Update(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)

	element1 := curve.Scalar.Hash([]byte("3"))
	element2 := curve.Scalar.Hash([]byte("4"))
	element3 := curve.Scalar.Hash([]byte("5"))
	element4 := curve.Scalar.Hash([]byte("6"))
	element5 := curve.Scalar.Hash([]byte("7"))
	element6 := curve.Scalar.Hash([]byte("8"))
	element7 := curve.Scalar.Hash([]byte("9"))
	element8 := curve.Scalar.Hash([]byte("10"))
	element9 := curve.Scalar.Hash([]byte("11"))
	element10 := curve.Scalar.Hash([]byte("12"))
	element11 := curve.Scalar.Hash([]byte("13"))
	element12 := curve.Scalar.Hash([]byte("14"))
	element13 := curve.Scalar.Hash([]byte("15"))
	element14 := curve.Scalar.Hash([]byte("16"))
	element15 := curve.Scalar.Hash([]byte("17"))
	element16 := curve.Scalar.Hash([]byte("18"))
	element17 := curve.Scalar.Hash([]byte("19"))
	element18 := curve.Scalar.Hash([]byte("20"))
	elements := []Element{
		element1,
		element2,
		element3,
		element4,
		element5,
		element6,
		element7,
		element8,
		element9,
		element10,
		element11,
		element12,
		element13,
		element14,
		element15,
		element16,
		element17,
		element18,
	}
	acc, err := new(Accumulator).WithElements(curve, sk, elements)
	require.NoError(t, err)
	require.NotNil(t, acc.value)

	wit, err := new(MembershipWitness).New(elements[3], acc, sk)
	require.NoError(t, err)

	err = wit.Verify(pk, acc)
	require.Nil(t, err)

	data1 := curve.Scalar.Hash([]byte("1"))
	data2 := curve.Scalar.Hash([]byte("2"))
	data3 := curve.Scalar.Hash([]byte("3"))
	data4 := curve.Scalar.Hash([]byte("4"))
	data5 := curve.Scalar.Hash([]byte("5"))
	data := []Element{data1, data2, data3, data4, data5}
	adds1 := data[0:2]
	dels1 := data[2:5]
	_, coeffs1, err := acc.Update(sk, adds1, dels1)
	require.NoError(t, err)
	require.NotNil(t, coeffs1)

	dels2 := elements[8:10]
	_, coeffs2, err := acc.Update(sk, []Element{}, dels2)
	require.NoError(t, err)
	require.NotNil(t, coeffs2)

	dels3 := elements[11:14]
	_, coeffs3, err := acc.Update(sk, []Element{}, dels3)
	require.NoError(t, err)
	require.NotNil(t, coeffs3)

	a := make([][]Element, 3)
	a[0] = adds1
	a[1] = []Element{}
	a[2] = []Element{}

	d := make([][]Element, 3)
	d[0] = dels1
	d[1] = dels2
	d[2] = dels3

	c := make([][]Coefficient, 3)
	c[0] = coeffs1
	c[1] = coeffs2
	c[2] = coeffs3

	_, err = wit.MultiBatchUpdate(a, d, c)
	require.NoError(t, err)

	err = wit.Verify(pk, acc)
	require.Nil(t, err)
}
