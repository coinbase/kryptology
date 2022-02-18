//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package fp

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFpSetOne(t *testing.T) {
	fp := new(Fp).SetOne()
	require.NotNil(t, fp)
	require.True(t, fp.Equal(r))
}

func TestFpSetUint64(t *testing.T) {
	act := new(Fp).SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, int(act[0]), 0x592d30ed00000001)
}

func TestFpAdd(t *testing.T) {
	lhs := new(Fp).SetOne()
	rhs := new(Fp).SetOne()
	exp := new(Fp).SetUint64(2)
	res := new(Fp).Add(lhs, rhs)
	require.NotNil(t, res)
	require.True(t, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint64() >> 2
		r := rand.Uint64() >> 2
		e := l + r
		lhs.SetUint64(l)
		rhs.SetUint64(r)
		exp.SetUint64(e)

		a := new(Fp).Add(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpSub(t *testing.T) {
	lhs := new(Fp).SetOne()
	rhs := new(Fp).SetOne()
	exp := new(Fp).SetZero()
	res := new(Fp).Sub(lhs, rhs)
	require.NotNil(t, res)
	require.True(t, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint64() >> 2
		r := rand.Uint64() >> 2
		if l < r {
			l, r = r, l
		}
		e := l - r
		lhs.SetUint64(l)
		rhs.SetUint64(r)
		exp.SetUint64(e)

		a := new(Fp).Sub(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpMul(t *testing.T) {
	lhs := new(Fp).SetOne()
	rhs := new(Fp).SetOne()
	exp := new(Fp).SetOne()
	res := new(Fp).Mul(lhs, rhs)
	require.NotNil(t, res)
	require.True(t, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint32()
		r := rand.Uint32()
		e := uint64(l) * uint64(r)
		lhs.SetUint64(uint64(l))
		rhs.SetUint64(uint64(r))
		exp.SetUint64(e)

		a := new(Fp).Mul(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpDouble(t *testing.T) {
	a := new(Fp).SetUint64(2)
	e := new(Fp).SetUint64(4)
	require.Equal(t, e, new(Fp).Double(a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a = new(Fp).SetUint64(uint64(tv))
		e = new(Fp).SetUint64(ttv)
		require.Equal(t, e, new(Fp).Double(a))
	}
}

func TestFpSquare(t *testing.T) {
	a := new(Fp).SetUint64(4)
	e := new(Fp).SetUint64(16)
	require.Equal(t, e, a.Square(a))

	for i := 0; i < 25; i++ {
		j := rand.Uint32()
		exp := uint64(j) * uint64(j)
		e.SetUint64(exp)
		a.SetUint64(uint64(j))
		require.Equal(t, e, a.Square(a))
	}
}

func TestFpNeg(t *testing.T) {
	a := new(Fp).SetOne()
	a.Neg(a)
	e := &Fp{7256640077462241284, 9879318615658062958, 0, 0}
	require.Equal(t, e, a)
	a.Neg(generator)
	e = &Fp{0xf787d28400000014, 0xad83f3b0ba037627, 0x2, 0x0}
	require.Equal(t, e, a)
}

func TestFpExp(t *testing.T) {
	e := new(Fp).SetUint64(8)
	a := new(Fp).SetUint64(2)
	by := new(Fp).SetUint64(3)
	require.Equal(t, e, a.Exp(a, by))
}

func TestFpSqrt(t *testing.T) {
	t1 := new(Fp).SetUint64(2)
	t2 := new(Fp).Neg(t1)
	t3 := new(Fp).Square(t1)
	_, wasSquare := t3.Sqrt(t3)
	require.True(t, wasSquare)
	require.True(t, t1.Equal(t3) || t2.Equal(t3))
	t1.SetUint64(5)
	_, wasSquare = new(Fp).Sqrt(t1)
	require.False(t, wasSquare)
}

func TestFpInvert(t *testing.T) {
	twoInv := &Fp{0xcc96987680000001, 0x11234c7e04a67c8d, 0x0000000000000000, 0x2000000000000000}
	fiat_pasta_fp_to_montgomery((*fiat_pasta_fp_montgomery_domain_field_element)(twoInv), (*fiat_pasta_fp_non_montgomery_domain_field_element)(twoInv))
	two := new(Fp).SetUint64(2)
	a, inverted := new(Fp).Invert(two)
	require.True(t, inverted)
	require.Equal(t, a, twoInv)

	rootOfUnity := &Fp{0xbdad6fabd87ea32f, 0xea322bf2b7bb7584, 0x362120830561f81a, 0x2bce74deac30ebda}
	fiat_pasta_fp_to_montgomery((*fiat_pasta_fp_montgomery_domain_field_element)(rootOfUnity), (*fiat_pasta_fp_non_montgomery_domain_field_element)(rootOfUnity))
	rootOfUnityInv := &Fp{0xf0b87c7db2ce91f6, 0x84a0a1d8859f066f, 0xb4ed8e647196dad1, 0x2cd5282c53116b5c}
	fiat_pasta_fp_to_montgomery((*fiat_pasta_fp_montgomery_domain_field_element)(rootOfUnityInv), (*fiat_pasta_fp_non_montgomery_domain_field_element)(rootOfUnityInv))
	a, inverted = new(Fp).Invert(rootOfUnity)
	require.True(t, inverted)
	require.Equal(t, a, rootOfUnityInv)

	lhs := new(Fp).SetUint64(9)
	rhs := new(Fp).SetUint64(3)
	rhsInv, inverted := new(Fp).Invert(rhs)
	require.True(t, inverted)
	require.Equal(t, rhs, new(Fp).Mul(lhs, rhsInv))

	rhs.SetZero()
	_, inverted = new(Fp).Invert(rhs)
	require.False(t, inverted)
}

func TestFpCMove(t *testing.T) {
	t1 := new(Fp).SetUint64(5)
	t2 := new(Fp).SetUint64(10)
	require.Equal(t, t1, new(Fp).CMove(t1, t2, 0))
	require.Equal(t, t2, new(Fp).CMove(t1, t2, 1))
}

func TestFpBytes(t *testing.T) {
	t1 := new(Fp).SetUint64(99)
	seq := t1.Bytes()
	t2, err := new(Fp).SetBytes(&seq)
	require.NoError(t, err)
	require.Equal(t, t1, t2)

	for i := 0; i < 25; i++ {
		t1.SetUint64(rand.Uint64())
		seq = t1.Bytes()
		_, err = t2.SetBytes(&seq)
		require.NoError(t, err)
		require.Equal(t, t1, t2)
	}
}

func TestFpBigInt(t *testing.T) {
	t1 := new(Fp).SetBigInt(big.NewInt(9999))
	t2 := new(Fp).SetBigInt(t1.BigInt())
	require.Equal(t, t1, t2)

	e := &Fp{0x8c6bc70550c87761, 0xce2c6c48e7063731, 0xf1275fd1e4607cd6, 0x3e6762e63501edbd}
	b := new(big.Int).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
	e[0] = 0xcc169e7af3788a0
	e[1] = 0x541a2cb32246c1ea
	e[2] = 0xed8a02e1b9f8329
	e[3] = 0x1989d19cafe1242
	b.Neg(b)
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
}

func TestFpSetBool(t *testing.T) {
	require.Equal(t, new(Fp).SetOne(), new(Fp).SetBool(true))
	require.Equal(t, new(Fp).SetZero(), new(Fp).SetBool(false))
}

func TestFpSetBytesWide(t *testing.T) {
	e := &Fp{0x3daec14d565241d9, 0x0b7af45b6073944b, 0xea5b8bd611a5bd4c, 0x150160330625db3d}
	fiat_pasta_fp_to_montgomery((*fiat_pasta_fp_montgomery_domain_field_element)(e), (*fiat_pasta_fp_non_montgomery_domain_field_element)(e))
	a := new(Fp).SetBytesWide(&[64]byte{
		0xa1, 0x78, 0x76, 0x29, 0x41, 0x56, 0x15, 0xee,
		0x65, 0xbe, 0xfd, 0xdb, 0x6b, 0x15, 0x3e, 0xd8,
		0xb5, 0xa0, 0x8b, 0xc6, 0x34, 0xd8, 0xcc, 0xd9,
		0x58, 0x27, 0x27, 0x12, 0xe3, 0xed, 0x08, 0xf5,
		0x89, 0x8e, 0x22, 0xf8, 0xcb, 0xf7, 0x8d, 0x03,
		0x41, 0x4b, 0xc7, 0xa3, 0xe4, 0xa1, 0x05, 0x35,
		0xb3, 0x2d, 0xb8, 0x5e, 0x77, 0x6f, 0xa4, 0xbf,
		0x1d, 0x47, 0x2f, 0x26, 0x7e, 0xe2, 0xeb, 0x26,
	})
	require.Equal(t, e, a)
}
