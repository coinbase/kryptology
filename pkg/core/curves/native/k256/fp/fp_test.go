//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package fp

import (
	crand "crypto/rand"
	"math/big"
	"math/rand"
	"testing"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves/native"
	"github.com/stretchr/testify/require"
)

func TestFpSetOne(t *testing.T) {
	fp := K256FpNew().SetOne()
	require.NotNil(t, fp)
	require.Equal(t, fp.Value, getK256FpParams().R)
}

func TestFpSetUint64(t *testing.T) {
	act := K256FpNew().SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, act.Value[0], uint64(0x1000000000000000))
}

func TestFpAdd(t *testing.T) {
	lhs := K256FpNew().SetOne()
	rhs := K256FpNew().SetOne()
	exp := K256FpNew().SetUint64(2)
	res := K256FpNew().Add(lhs, rhs)
	require.NotNil(t, res)
	require.Equal(t, res.Equal(exp), 1)

	// Fuzz test
	for i := 0; i < 25; i++ {
		// Divide by 4 to prevent overflow false errors
		l := rand.Uint64() >> 2
		r := rand.Uint64() >> 2
		e := l + r
		lhs.SetUint64(l)
		rhs.SetUint64(r)
		exp.SetUint64(e)

		a := K256FpNew().Add(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpSub(t *testing.T) {
	lhs := K256FpNew().SetOne()
	rhs := K256FpNew().SetOne()
	exp := K256FpNew().SetZero()
	res := K256FpNew().Sub(lhs, rhs)
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

		a := K256FpNew().Sub(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpMul(t *testing.T) {
	lhs := K256FpNew().SetOne()
	rhs := K256FpNew().SetOne()
	exp := K256FpNew().SetOne()
	res := K256FpNew().Mul(lhs, rhs)
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

		a := K256FpNew().Mul(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFpDouble(t *testing.T) {
	a := K256FpNew().SetUint64(2)
	e := K256FpNew().SetUint64(4)
	require.Equal(t, e, K256FpNew().Double(a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a = K256FpNew().SetUint64(uint64(tv))
		e = K256FpNew().SetUint64(ttv)
		require.Equal(t, e, K256FpNew().Double(a))
	}
}

func TestFpSquare(t *testing.T) {
	a := K256FpNew().SetUint64(4)
	e := K256FpNew().SetUint64(16)
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
	a := K256FpNew().SetOne()
	a.Neg(a)
	e := K256FpNew().SetRaw(&[native.FieldLimbs]uint64{0xfffffffdfffff85e, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff})
	require.Equal(t, e, a)
}

func TestFpExp(t *testing.T) {
	e := K256FpNew().SetUint64(8)
	a := K256FpNew().SetUint64(2)
	by := K256FpNew().SetUint64(3)
	require.Equal(t, e, a.Exp(a, by))
}

func TestFpSqrt(t *testing.T) {
	t1 := K256FpNew().SetUint64(2)
	t2 := K256FpNew().Neg(t1)
	t3 := K256FpNew().Square(t1)
	_, wasSquare := t3.Sqrt(t3)
	require.True(t, wasSquare)
	require.Equal(t, 1, t1.Equal(t3)|t2.Equal(t3))
	t1.SetUint64(5)
	_, wasSquare = K256FpNew().Sqrt(t1)
	require.False(t, wasSquare)
}

func TestFpInvert(t *testing.T) {
	twoInv := K256FpNew().SetLimbs(&[native.FieldLimbs]uint64{
		0xffffffff7ffffe18,
		0xffffffffffffffff,
		0xffffffffffffffff,
		0x7fffffffffffffff,
	})
	two := K256FpNew().SetUint64(2)
	a, inverted := K256FpNew().Invert(two)
	require.True(t, inverted)
	require.Equal(t, a, twoInv)

	seven := K256FpNew().SetUint64(7)
	sevenInv := K256FpNew().SetRaw(&[native.FieldLimbs]uint64{0xdb6db6dab6db6afd, 0x6db6db6db6db6db6, 0xb6db6db6db6db6db, 0xdb6db6db6db6db6d})
	a, inverted = K256FpNew().Invert(seven)
	require.True(t, inverted)
	require.Equal(t, a, sevenInv)

	lhs := K256FpNew().SetUint64(9)
	rhs := K256FpNew().SetUint64(3)
	rhsInv, inverted := K256FpNew().Invert(rhs)
	require.True(t, inverted)
	require.Equal(t, rhs, K256FpNew().Mul(lhs, rhsInv))

	rhs.SetZero()
	_, inverted = K256FpNew().Invert(rhs)
	require.False(t, inverted)
}

func TestFpCMove(t *testing.T) {
	t1 := K256FpNew().SetUint64(5)
	t2 := K256FpNew().SetUint64(10)
	require.Equal(t, t1, K256FpNew().CMove(t1, t2, 0))
	require.Equal(t, t2, K256FpNew().CMove(t1, t2, 1))
}

func TestFpBytes(t *testing.T) {
	t1 := K256FpNew().SetUint64(99)
	seq := t1.Bytes()
	t2, err := K256FpNew().SetBytes(&seq)
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

func TestFpCmp(t *testing.T) {
	tests := []struct {
		a *native.Field
		b *native.Field
		e int
	}{
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{2731658267414164836, 14655288906067898431, 6537465423330262322, 8306191141697566219}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{6472764012681988529, 10848812988401906064, 2961825807536828898, 4282183981941645679}),
			e: 1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{8023004109510539223, 4652004072850285717, 1877219145646046927, 383214385093921911}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{10099384440823804262, 16139476942229308465, 8636966320777393798, 5435928725024696785}),
			e: -1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{3741840066202388211, 12165774400417314871, 16619312580230515379, 16195032234110087705}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{3905865991286066744, 543690822309071825, 17963103015950210055, 3745476720756119742}),
			e: 1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{16660853697936147788, 7799793619412111108, 13515141085171033220, 2641079731236069032}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{17790588295388238399, 571847801379669440, 14537208974498222469, 12792570372087452754}),
			e: -1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{3912839285384959186, 2701177075110484070, 6453856448115499033, 6475797457962597458}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{1282566391665688512, 13503640416992806563, 2962240104675990153, 3374904770947067689}),
			e: 1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{5716631803409360103, 7859567470082614154, 12747956220853330146, 18434584096087315020}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{16317076441459028418, 12854146980376319601, 2258436689269031143, 9531877130792223752}),
			e: 1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{17955191469941083403, 10350326247207200880, 17263512235150705075, 12700328451238078022}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{6767595547459644695, 7146403825494928147, 12269344038346710612, 9122477829383225603}),
			e: 1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{17099388671847024438, 6426264987820696548, 10641143464957227405, 7709745403700754098}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{10799154372990268556, 17178492485719929374, 5705777922258988797, 8051037767683567782}),
			e: -1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{4567139260680454325, 1629385880182139061, 16607020832317899145, 1261011562621553200}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{13487234491304534488, 17872642955936089265, 17651026784972590233, 9468934643333871559}),
			e: -1,
		},
		{
			a: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{18071070103467571798, 11787850505799426140, 10631355976141928593, 4867785203635092610}),
			b: K256FpNew().SetRaw(&[native.FieldLimbs]uint64{12596443599426461624, 10176122686151524591, 17075755296887483439, 6726169532695070719}),
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

func TestFpBigInt(t *testing.T) {
	t1 := K256FpNew().SetBigInt(big.NewInt(9999))
	t2 := K256FpNew().SetBigInt(t1.BigInt())
	require.Equal(t, t1, t2)

	e := K256FpNew().SetRaw(&[native.FieldLimbs]uint64{0xc6c6c6c63939371d, 0xc6c6c6c6c6c6c6c6, 0x8d8d8dd28485081d, 0x8484848484848484})
	b := new(big.Int).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
	e.Value[0] = 0x39393938c6c6c512
	e.Value[1] = 0x3939393939393939
	e.Value[2] = 0x7272722d7b7af7e2
	e.Value[3] = 0x7b7b7b7b7b7b7b7b
	b.Neg(b)
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
}

func TestFpSetBytesWide(t *testing.T) {
	e := K256FpNew().SetRaw(&[native.FieldLimbs]uint64{0x6aa784623e2d641e, 0x7c40617d755bae27, 0x206b7be66ed7b71b, 0x6d1e4fc581e19dc2})

	a := K256FpNew().SetBytesWide(&[64]byte{
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
	params := getK256FpParams()
	var tv2 [64]byte
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(tv2[:])
		e := new(big.Int).SetBytes(tv2[:])
		e.Mod(e, params.BiModulus)

		tv := internal.ReverseScalarBytes(tv2[:])
		copy(tv2[:], tv)
		a := K256FpNew().SetBytesWide(&tv2)
		require.Equal(t, 0, e.Cmp(a.BigInt()))
	}
}
