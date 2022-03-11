//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls12381

import (
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/internal"
)

func TestFpSetOne(t *testing.T) {
	var fp fp
	fp.SetOne()
	require.NotNil(t, fp)
	require.Equal(t, fp, r)
}

func TestFpSetUint64(t *testing.T) {
	var act fp
	act.SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, act[0], uint64(0xf6ea9fde37db5e8c))
}

func TestFpAdd(t *testing.T) {
	var lhs, rhs, exp, res fp
	lhs.SetOne()
	rhs.SetOne()
	exp.SetUint64(2)
	res.Add(&lhs, &rhs)
	require.NotNil(t, res)
	require.Equal(t, 1, res.Equal(&exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint64() >> 2
		r := rand.Uint64() >> 2
		e := l + r
		lhs.SetUint64(l)
		rhs.SetUint64(r)
		exp.SetUint64(e)

		res.Add(&lhs, &rhs)
		require.NotNil(t, res)
		require.Equal(t, exp, res)
	}
}

func TestFpSub(t *testing.T) {
	var lhs, rhs, exp, res fp
	lhs.SetOne()
	rhs.SetOne()
	exp.SetZero()
	res.Sub(&lhs, &rhs)
	require.NotNil(t, res)
	require.Equal(t, 1, res.Equal(&exp))

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

		res.Sub(&lhs, &rhs)
		require.NotNil(t, res)
		require.Equal(t, exp, res)
	}
}

func TestFpMul(t *testing.T) {
	var lhs, rhs, exp, res fp
	lhs.SetOne()
	rhs.SetOne()
	exp.SetOne()
	res.Mul(&lhs, &rhs)
	require.NotNil(t, res)
	require.Equal(t, 1, res.Equal(&exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint32()
		r := rand.Uint32()
		e := uint64(l) * uint64(r)
		lhs.SetUint64(uint64(l))
		rhs.SetUint64(uint64(r))
		exp.SetUint64(e)

		res.Mul(&lhs, &rhs)
		require.NotNil(t, res)
		require.Equal(t, exp, res)
	}
}

func TestFpDouble(t *testing.T) {
	var a, e, res fp
	a.SetUint64(2)
	e.SetUint64(4)
	require.Equal(t, &e, res.Double(&a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a.SetUint64(uint64(tv))
		e.SetUint64(ttv)
		require.Equal(t, &e, res.Double(&a))
	}
}

func TestFpSquare(t *testing.T) {
	var a, e, res fp
	a.SetUint64(4)
	e.SetUint64(16)
	require.Equal(t, 1, e.Equal(res.Square(&a)))

	a.SetUint64(2854263694)
	e.SetUint64(8146821234886525636)
	require.Equal(t, 1, e.Equal(res.Square(&a)))

	for i := 0; i < 25; i++ {
		j := rand.Uint32()
		exp := uint64(j) * uint64(j)
		e.SetUint64(exp)
		a.SetUint64(uint64(j))
		require.Equal(t, 1, e.Equal(res.Square(&a)), "exp = %d, j = %d", exp, j)
	}
}

func TestFpNeg(t *testing.T) {
	var g, a, e fp
	g.SetLimbs(&[Limbs]uint64{7, 0, 0, 0, 0, 0})
	a.SetOne()
	a.Neg(&a)
	e.SetRaw(&[Limbs]uint64{0x43f5fffffffcaaae, 0x32b7fff2ed47fffd, 0x07e83a49a2e99d69, 0xeca8f3318332bb7a, 0xef148d1ea0f4c069, 0x040ab3263eff0206})
	require.Equal(t, 1, e.Equal(&a))
	a.Neg(&g)
	e.SetRaw(&[Limbs]uint64{0x21baffffffe90017, 0x445bffa5cba3ffed, 0xd028c5627db257bc, 0x14275ad5a2de0d96, 0x3e7434202365960e, 0x0249d4217f792796})
	require.Equal(t, e, a)
}

func TestFpExp(t *testing.T) {
	var a, e, by fp
	e.SetUint64(8)
	a.SetUint64(2)
	by.SetUint64(3)
	require.Equal(t, &e, a.Exp(&a, &by))
}

func TestFpSqrt(t *testing.T) {
	var t1, t2, t3 fp
	t1.SetUint64(2)
	t2.Neg(&t1)
	t3.Square(&t1)
	_, wasSquare := t3.Sqrt(&t3)

	require.Equal(t, 1, wasSquare)
	require.Equal(t, 1, t1.Equal(&t3)|t2.Equal(&t3))
	t1.SetUint64(5)
	_, wasSquare = t1.Sqrt(&t1)
	require.Equal(t, 0, wasSquare)
}

func TestFpInvert(t *testing.T) {
	var two, twoInv, a, lhs, rhs, rhsInv fp
	twoInv.SetRaw(&[Limbs]uint64{0x1804000000015554, 0x855000053ab00001, 0x633cb57c253c276f, 0x6e22d1ec31ebb502, 0xd3916126f2d14ca2, 0x17fbb8571a006596})
	two.SetUint64(2)
	_, inverted := a.Invert(&two)
	require.Equal(t, 1, inverted)
	require.Equal(t, &a, &twoInv)

	lhs.SetUint64(9)
	rhs.SetUint64(3)
	_, inverted = rhsInv.Invert(&rhs)
	require.Equal(t, 1, inverted)
	require.Equal(t, &rhs, lhs.Mul(&lhs, &rhsInv))

	rhs.SetZero()
	_, inverted = lhs.Invert(&rhs)
	require.Equal(t, 0, inverted)
}

func TestFpCMove(t *testing.T) {
	var t1, t2, tt fp
	t1.SetUint64(5)
	t2.SetUint64(10)
	require.Equal(t, &t1, tt.CMove(&t1, &t2, 0))
	require.Equal(t, &t2, tt.CMove(&t1, &t2, 1))
}

func TestFpBytes(t *testing.T) {
	var t1, t2 fp
	t1.SetUint64(99)
	seq := t1.Bytes()
	_, suc := t2.SetBytes(&seq)
	require.Equal(t, 1, suc)
	require.Equal(t, t1, t2)

	for i := 0; i < 25; i++ {
		t1.SetUint64(rand.Uint64())
		seq = t1.Bytes()
		_, suc = t2.SetBytes(&seq)
		require.Equal(t, 1, suc)
		require.Equal(t, t1, t2)
	}
}

func TestFpBigInt(t *testing.T) {
	var t1, t2, e fp
	t1.SetBigInt(big.NewInt(9999))
	t2.SetBigInt(t1.BigInt())
	require.Equal(t, t1, t2)

	e.SetRaw(&[Limbs]uint64{0x922af810e5e35f31, 0x6bc75973ed382d59, 0xd4716c9d4d491d42, 0x69d98d1ebeeb3f6e, 0x7e425d7b46d4a82b, 0x12d04b0965870e92})
	b := new(big.Int).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
	e.Neg(&e)
	b.Neg(b)
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
}

func TestFpSetBytesWideBigInt(t *testing.T) {
	var a fp
	var tv2 [96]byte
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(tv2[:])
		e := new(big.Int).SetBytes(tv2[:])
		e.Mod(e, biModulus)

		tv := internal.ReverseScalarBytes(tv2[:])
		copy(tv2[:], tv)
		a.SetBytesWide(&tv2)
		require.Equal(t, 0, e.Cmp(a.BigInt()))
	}
}

func TestFpToMontgomery(t *testing.T) {
	var v fp
	v.SetUint64(2)
	require.Equal(t, fp{0x321300000006554f, 0xb93c0018d6c40005, 0x57605e0db0ddbb51, 0x8b256521ed1f9bcb, 0x6cf28d7901622c03, 0x11ebab9dbb81e28c}, v)
}

func TestFpFromMontgomery(t *testing.T) {
	var v fp
	e := fp{2, 0, 0, 0, 0, 0}
	v.SetUint64(2)
	v.fromMontgomery(&v)
	require.Equal(t, e, v)
}

func TestFpLexicographicallyLargest(t *testing.T) {
	require.Equal(t, 0, new(fp).SetZero().LexicographicallyLargest())
	require.Equal(t, 0, new(fp).SetOne().LexicographicallyLargest())
	require.Equal(t, 0, (&fp{
		0xa1fafffffffe5557,
		0x995bfff976a3fffe,
		0x03f41d24d174ceb4,
		0xf6547998c1995dbd,
		0x778a468f507a6034,
		0x020559931f7f8103,
	}).LexicographicallyLargest())
	require.Equal(t, 1, (&fp{
		0x1804000000015554,
		0x855000053ab00001,
		0x633cb57c253c276f,
		0x6e22d1ec31ebb502,
		0xd3916126f2d14ca2,
		0x17fbb8571a006596,
	}).LexicographicallyLargest())
	require.Equal(t, 1, (&fp{
		0x43f5fffffffcaaae,
		0x32b7fff2ed47fffd,
		0x07e83a49a2e99d69,
		0xeca8f3318332bb7a,
		0xef148d1ea0f4c069,
		0x040ab3263eff0206,
	}).LexicographicallyLargest())
}
