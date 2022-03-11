//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package fq

import (
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
)

func TestFqSetOne(t *testing.T) {
	fq := P256FqNew().SetOne()
	require.NotNil(t, fq)
	require.Equal(t, fq.Value, getP256FqParams().R)
}

func TestFqSetUint64(t *testing.T) {
	act := P256FqNew().SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, act.Value[0], uint64(0xb3f3986dec632551))
}

func TestFqAdd(t *testing.T) {
	lhs := P256FqNew().SetOne()
	rhs := P256FqNew().SetOne()
	exp := P256FqNew().SetUint64(2)
	res := P256FqNew().Add(lhs, rhs)
	require.NotNil(t, res)
	require.Equal(t, 1, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint64() >> 2
		r := rand.Uint64() >> 2
		e := l + r
		lhs.SetUint64(l)
		rhs.SetUint64(r)
		exp.SetUint64(e)

		a := P256FqNew().Add(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqSub(t *testing.T) {
	lhs := P256FqNew().SetOne()
	rhs := P256FqNew().SetOne()
	exp := P256FqNew().SetZero()
	res := P256FqNew().Sub(lhs, rhs)
	require.NotNil(t, res)
	require.Equal(t, 1, res.Equal(exp))

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

		a := P256FqNew().Sub(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqMul(t *testing.T) {
	lhs := P256FqNew().SetOne()
	rhs := P256FqNew().SetOne()
	exp := P256FqNew().SetOne()
	res := P256FqNew().Mul(lhs, rhs)
	require.NotNil(t, res)
	require.Equal(t, 1, res.Equal(exp))

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint32()
		r := rand.Uint32()
		e := uint64(l) * uint64(r)
		lhs.SetUint64(uint64(l))
		rhs.SetUint64(uint64(r))
		exp.SetUint64(e)

		a := P256FqNew().Mul(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqDouble(t *testing.T) {
	a := P256FqNew().SetUint64(2)
	e := P256FqNew().SetUint64(4)
	require.Equal(t, e, P256FqNew().Double(a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a = P256FqNew().SetUint64(uint64(tv))
		e = P256FqNew().SetUint64(ttv)
		require.Equal(t, e, P256FqNew().Double(a))
	}
}

func TestFqSquare(t *testing.T) {
	a := P256FqNew().SetUint64(4)
	e := P256FqNew().SetUint64(16)
	require.Equal(t, e, a.Square(a))

	for i := 0; i < 25; i++ {
		j := rand.Uint32()
		exp := uint64(j) * uint64(j)
		e.SetUint64(exp)
		a.SetUint64(uint64(j))
		require.Equal(t, e, a.Square(a))
	}
}

func TestFqNeg(t *testing.T) {
	g := P256FqNew().SetRaw(generator)
	a := P256FqNew().SetOne()
	a.Neg(a)
	e := P256FqNew().SetRaw(&[native.FieldLimbs]uint64{0xe7739585f8c64aa2, 0x79cdf55b4e2f3d09, 0xffffffffffffffff, 0xfffffffe00000001})
	require.Equal(t, e, a)
	a.Neg(g)
	e = P256FqNew().SetRaw(&[native.FieldLimbs]uint64{0x9dce5617e3192a88, 0xe737d56d38bcf427, 0xfffffffffffffffd, 0xfffffff800000007})
	require.Equal(t, e, a)
}

func TestFqExp(t *testing.T) {
	e := P256FqNew().SetUint64(8)
	a := P256FqNew().SetUint64(2)
	by := P256FqNew().SetUint64(3)
	require.Equal(t, e, a.Exp(a, by))
}

func TestFqSqrt(t *testing.T) {
	t1 := P256FqNew().SetUint64(2)
	t2 := P256FqNew().Neg(t1)
	t3 := P256FqNew().Square(t1)
	_, wasSquare := t3.Sqrt(t3)

	require.True(t, wasSquare)
	require.Equal(t, 1, t1.Equal(t3)|t2.Equal(t3))
	t1.SetUint64(7)
	_, wasSquare = t3.Sqrt(t1)
	require.False(t, wasSquare)
}

func TestFqInvert(t *testing.T) {
	twoInv := P256FqNew().SetRaw(&[native.FieldLimbs]uint64{0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x8000000000000000})
	two := P256FqNew().SetUint64(2)
	a, inverted := P256FqNew().Invert(two)
	require.True(t, inverted)
	require.Equal(t, a, twoInv)

	rootOfUnityInv := P256FqNew().SetRaw(&[native.FieldLimbs]uint64{0xcfbf53b9618acf96, 0xf17e5c39df7bd05b, 0xc7acb1f83e3ad9ad, 0x4659a42b394ff7df})
	rootOU := P256FqNew().SetRaw(rootOfUnity)
	a, inverted = P256FqNew().Invert(rootOU)
	require.True(t, inverted)
	require.Equal(t, a, rootOfUnityInv)

	lhs := P256FqNew().SetUint64(9)
	rhs := P256FqNew().SetUint64(3)
	rhsInv, inverted := P256FqNew().Invert(rhs)
	require.True(t, inverted)
	require.Equal(t, rhs, P256FqNew().Mul(lhs, rhsInv))

	rhs.SetZero()
	_, inverted = P256FqNew().Invert(rhs)
	require.False(t, inverted)
}

func TestFqCMove(t *testing.T) {
	t1 := P256FqNew().SetUint64(5)
	t2 := P256FqNew().SetUint64(10)
	require.Equal(t, t1, P256FqNew().CMove(t1, t2, 0))
	require.Equal(t, t2, P256FqNew().CMove(t1, t2, 1))
}

func TestFqBytes(t *testing.T) {
	t1 := P256FqNew().SetUint64(99)
	seq := t1.Bytes()
	t2, err := P256FqNew().SetBytes(&seq)
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

func TestFqCmp(t *testing.T) {
	tests := []struct {
		a *native.Field
		b *native.Field
		e int
	}{
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{2731658267414164836, 14655288906067898431, 6537465423330262322, 8306191141697566219}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{6472764012681988529, 10848812988401906064, 2961825807536828898, 4282183981941645679}),
			e: 1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{8023004109510539223, 4652004072850285717, 1877219145646046927, 383214385093921911}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{10099384440823804262, 16139476942229308465, 8636966320777393798, 5435928725024696785}),
			e: -1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{3741840066202388211, 12165774400417314871, 16619312580230515379, 16195032234110087705}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{3905865991286066744, 543690822309071825, 17963103015950210055, 3745476720756119742}),
			e: 1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{16660853697936147788, 7799793619412111108, 13515141085171033220, 2641079731236069032}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{17790588295388238399, 571847801379669440, 14537208974498222469, 12792570372087452754}),
			e: -1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{3912839285384959186, 2701177075110484070, 6453856448115499033, 6475797457962597458}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{1282566391665688512, 13503640416992806563, 2962240104675990153, 3374904770947067689}),
			e: 1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{5716631803409360103, 7859567470082614154, 12747956220853330146, 18434584096087315020}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{16317076441459028418, 12854146980376319601, 2258436689269031143, 9531877130792223752}),
			e: 1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{17955191469941083403, 10350326247207200880, 17263512235150705075, 12700328451238078022}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{6767595547459644695, 7146403825494928147, 12269344038346710612, 9122477829383225603}),
			e: 1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{17099388671847024438, 6426264987820696548, 10641143464957227405, 7709745403700754098}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{10799154372990268556, 17178492485719929374, 5705777922258988797, 8051037767683567782}),
			e: -1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{4567139260680454325, 1629385880182139061, 16607020832317899145, 1261011562621553200}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{13487234491304534488, 17872642955936089265, 17651026784972590233, 9468934643333871559}),
			e: -1,
		},
		{
			a: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{18071070103467571798, 11787850505799426140, 10631355976141928593, 4867785203635092610}),
			b: P256FqNew().SetRaw(&[native.FieldLimbs]uint64{12596443599426461624, 10176122686151524591, 17075755296887483439, 6726169532695070719}),
			e: -1,
		},
	}

	for _, test := range tests {
		require.Equal(t, test.e, test.a.Cmp(test.b))
		require.Equal(t, -test.e, test.b.Cmp(test.a))
		require.Equal(t, 0, test.a.Cmp(test.a))
		require.Equal(t, 0, test.b.Cmp(test.b))
	}
}

func TestFqBigInt(t *testing.T) {
	t1 := P256FqNew().SetBigInt(big.NewInt(9999))
	t2 := P256FqNew().SetBigInt(t1.BigInt())
	require.Equal(t, t1, t2)

	e := P256FqNew().SetRaw(&[native.FieldLimbs]uint64{0x21dcaaadf1cb6aa0, 0x568de5f5990a98d7, 0x354f43b0d837fac5, 0x3e02532cb23f481a})
	b := new(big.Int).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
	e.Value[0] = 0xd1dd20150a97bab1
	e.Value[1] = 0x665914b80e0d05ad
	e.Value[2] = 0xcab0bc4f27c8053a
	e.Value[3] = 0xc1fdacd24dc0b7e6
	b.Neg(b)
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
}

func TestFqSetBytesWide(t *testing.T) {
	e := P256FqNew().SetRaw(&[native.FieldLimbs]uint64{0xe2b8d4b0e576c8fa, 0x9d2b215f85d3bdf7, 0xf6070a872442640c, 0xcf15d1e49c990b88})

	a := P256FqNew().SetBytesWide(&[64]byte{
		0x69, 0x23, 0x5a, 0x0b, 0xce, 0x0c, 0xa8, 0x64,
		0x3c, 0x78, 0xbc, 0x01, 0x05, 0xef, 0xf2, 0x84,
		0xde, 0xbb, 0x6b, 0xc8, 0x63, 0x5e, 0x6e, 0x69,
		0x62, 0xcc, 0xc6, 0x2d, 0xf5, 0x72, 0x40, 0x92,
		0x28, 0x11, 0xd6, 0xc8, 0x07, 0xa5, 0x88, 0x82,
		0xfe, 0xe3, 0x97, 0xf6, 0x1e, 0xfb, 0x2e, 0x3b,
		0x27, 0x5f, 0x85, 0x06, 0x8d, 0x99, 0xa4, 0x75,
		0xc0, 0x2c, 0x71, 0x69, 0x9e, 0x58, 0xea, 0x52,
	})
	require.Equal(t, e, a)
}

func TestFpSetBytesWideBigInt(t *testing.T) {
	params := getP256FqParams()
	var tv2 [64]byte
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(tv2[:])
		e := new(big.Int).SetBytes(tv2[:])
		e.Mod(e, params.BiModulus)

		tv := internal.ReverseScalarBytes(tv2[:])
		copy(tv2[:], tv)
		a := P256FqNew().SetBytesWide(&tv2)
		require.Equal(t, 0, e.Cmp(a.BigInt()))
	}
}
