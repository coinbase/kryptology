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
	fq := K256FqNew().SetOne()
	require.NotNil(t, fq)
	require.Equal(t, fq.Value, getK256FqParams().R)
}

func TestFqSetUint64(t *testing.T) {
	act := K256FqNew().SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, act.Value[0], uint64(0xF000000000000000))
}

func TestFqAdd(t *testing.T) {
	lhs := K256FqNew().SetOne()
	rhs := K256FqNew().SetOne()
	exp := K256FqNew().SetUint64(2)
	res := K256FqNew().Add(lhs, rhs)
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

		a := K256FqNew().Add(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqSub(t *testing.T) {
	lhs := K256FqNew().SetOne()
	rhs := K256FqNew().SetOne()
	exp := K256FqNew().SetZero()
	res := K256FqNew().Sub(lhs, rhs)
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

		a := K256FqNew().Sub(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqMul(t *testing.T) {
	lhs := K256FqNew().SetOne()
	rhs := K256FqNew().SetOne()
	exp := K256FqNew().SetOne()
	res := K256FqNew().Mul(lhs, rhs)
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

		a := K256FqNew().Mul(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqDouble(t *testing.T) {
	a := K256FqNew().SetUint64(2)
	e := K256FqNew().SetUint64(4)
	require.Equal(t, e, K256FqNew().Double(a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a = K256FqNew().SetUint64(uint64(tv))
		e = K256FqNew().SetUint64(ttv)
		require.Equal(t, e, K256FqNew().Double(a))
	}
}

func TestFqSquare(t *testing.T) {
	a := K256FqNew().SetUint64(4)
	e := K256FqNew().SetUint64(16)
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
	g := K256FqNew().SetRaw(generator)
	a := K256FqNew().SetOne()
	a.Neg(a)
	e := K256FqNew().SetRaw(&[native.FieldLimbs]uint64{0x7fa4bd19a06c8282, 0x755db9cd5e914077, 0xfffffffffffffffd, 0xffffffffffffffff})
	require.Equal(t, e, a)
	a.Neg(g)
	e = K256FqNew().SetRaw(&[native.FieldLimbs]uint64{0xfe92f46681b20a08, 0xd576e7357a4501dd, 0xfffffffffffffff5, 0xffffffffffffffff})
	require.Equal(t, e, a)
}

func TestFqExp(t *testing.T) {
	e := K256FqNew().SetUint64(8)
	a := K256FqNew().SetUint64(2)
	by := K256FqNew().SetUint64(3)
	require.Equal(t, e, a.Exp(a, by))
}

func TestFqSqrt(t *testing.T) {
	t1 := K256FqNew().SetUint64(2)
	t2 := K256FqNew().Neg(t1)
	t3 := K256FqNew().Square(t1)
	_, wasSquare := t3.Sqrt(t3)

	require.True(t, wasSquare)
	require.Equal(t, 1, t1.Equal(t3)|t2.Equal(t3))
	t1.SetUint64(5)
	_, wasSquare = K256FqNew().Sqrt(t1)
	require.False(t, wasSquare)
}

func TestFqInvert(t *testing.T) {
	twoInv := K256FqNew().SetLimbs(&[native.FieldLimbs]uint64{0xdfe92f46681b20a1, 0x5d576e7357a4501d, 0xffffffffffffffff, 0x7fffffffffffffff})
	two := K256FqNew().SetUint64(2)
	a, inverted := K256FqNew().Invert(two)
	require.True(t, inverted)
	require.Equal(t, a, twoInv)

	rootOfUnity := K256FqNew().SetLimbs(&[native.FieldLimbs]uint64{0x8619a9e760c01d0c, 0xa883c4fba37998df, 0x45607580b6eabd98, 0xf252b002544b2f99})
	rootOfUnityInv := K256FqNew().SetRaw(&[native.FieldLimbs]uint64{0x7d99f8e21447e314, 0x5b60c477e7728d4c, 0xd78befc191f58654, 0x6897e5ff7824360f})
	a, inverted = K256FqNew().Invert(rootOfUnity)
	require.True(t, inverted)
	require.Equal(t, a, rootOfUnityInv)

	lhs := K256FqNew().SetUint64(9)
	rhs := K256FqNew().SetUint64(3)
	rhsInv, inverted := K256FqNew().Invert(rhs)
	require.True(t, inverted)
	require.Equal(t, rhs, K256FqNew().Mul(lhs, rhsInv))

	rhs.SetZero()
	_, inverted = K256FqNew().Invert(rhs)
	require.False(t, inverted)
}

func TestFqCMove(t *testing.T) {
	t1 := K256FqNew().SetUint64(5)
	t2 := K256FqNew().SetUint64(10)
	require.Equal(t, t1, K256FqNew().CMove(t1, t2, 0))
	require.Equal(t, t2, K256FqNew().CMove(t1, t2, 1))
}

func TestFqBytes(t *testing.T) {
	t1 := K256FqNew().SetUint64(99)
	seq := t1.Bytes()
	t2, err := K256FqNew().SetBytes(&seq)
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
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{2731658267414164836, 14655288906067898431, 6537465423330262322, 8306191141697566219}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{6472764012681988529, 10848812988401906064, 2961825807536828898, 4282183981941645679}),
			e: 1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{8023004109510539223, 4652004072850285717, 1877219145646046927, 383214385093921911}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{10099384440823804262, 16139476942229308465, 8636966320777393798, 5435928725024696785}),
			e: -1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{3741840066202388211, 12165774400417314871, 16619312580230515379, 16195032234110087705}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{3905865991286066744, 543690822309071825, 17963103015950210055, 3745476720756119742}),
			e: 1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{16660853697936147788, 7799793619412111108, 13515141085171033220, 2641079731236069032}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{17790588295388238399, 571847801379669440, 14537208974498222469, 12792570372087452754}),
			e: -1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{3912839285384959186, 2701177075110484070, 6453856448115499033, 6475797457962597458}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{1282566391665688512, 13503640416992806563, 2962240104675990153, 3374904770947067689}),
			e: 1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{5716631803409360103, 7859567470082614154, 12747956220853330146, 18434584096087315020}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{16317076441459028418, 12854146980376319601, 2258436689269031143, 9531877130792223752}),
			e: 1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{17955191469941083403, 10350326247207200880, 17263512235150705075, 12700328451238078022}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{6767595547459644695, 7146403825494928147, 12269344038346710612, 9122477829383225603}),
			e: 1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{17099388671847024438, 6426264987820696548, 10641143464957227405, 7709745403700754098}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{10799154372990268556, 17178492485719929374, 5705777922258988797, 8051037767683567782}),
			e: -1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{4567139260680454325, 1629385880182139061, 16607020832317899145, 1261011562621553200}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{13487234491304534488, 17872642955936089265, 17651026784972590233, 9468934643333871559}),
			e: -1,
		},
		{
			a: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{18071070103467571798, 11787850505799426140, 10631355976141928593, 4867785203635092610}),
			b: K256FqNew().SetRaw(&[native.FieldLimbs]uint64{12596443599426461624, 10176122686151524591, 17075755296887483439, 6726169532695070719}),
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
	t1 := K256FqNew().SetBigInt(big.NewInt(9999))
	t2 := K256FqNew().SetBigInt(t1.BigInt())
	require.Equal(t, t1, t2)

	e := K256FqNew().SetRaw(&[native.FieldLimbs]uint64{0xa764d3f6f152f222, 0x3b5dc8aacb9297b7, 0xb015fa9d2b3efdc6, 0x567360cef000f24a})
	b := new(big.Int).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
	e.Value[0] = 0x186d8a95dee34f1f
	e.Value[1] = 0x7f51143be3b60884
	e.Value[2] = 0x4fea0562d4c10238
	e.Value[3] = 0xa98c9f310fff0db5
	b.Neg(b)
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
}

func TestFqSetBytesWide(t *testing.T) {
	e := K256FqNew().SetRaw(&[native.FieldLimbs]uint64{0x70620a92b4f2eb7a, 0xd04588eb9c228a3a, 0xccb71ae40a10491c, 0x61cf39d70a8b33b7})

	a := K256FqNew().SetBytesWide(&[64]byte{
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
	params := getK256FqParams()
	var tv2 [64]byte
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(tv2[:])
		e := new(big.Int).SetBytes(tv2[:])
		e.Mod(e, params.BiModulus)

		tv := internal.ReverseScalarBytes(tv2[:])
		copy(tv2[:], tv)
		a := K256FqNew().SetBytesWide(&tv2)
		require.Equal(t, 0, e.Cmp(a.BigInt()))
	}
}
