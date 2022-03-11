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
	"github.com/coinbase/kryptology/pkg/core/curves/native"
)

func TestFqSetOne(t *testing.T) {
	fq := Bls12381FqNew().SetOne()
	require.NotNil(t, fq)
	require.Equal(t, fq.Value, getBls12381FqParams().R)
}

func TestFqSetUint64(t *testing.T) {
	act := Bls12381FqNew().SetUint64(1 << 60)
	require.NotNil(t, act)
	// Remember it will be in montgomery form
	require.Equal(t, act.Value[0], uint64(0xbc98da2820121c89))
}

func TestFqAdd(t *testing.T) {
	lhs := Bls12381FqNew().SetOne()
	rhs := Bls12381FqNew().SetOne()
	exp := Bls12381FqNew().SetUint64(2)
	res := Bls12381FqNew().Add(lhs, rhs)
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

		a := Bls12381FqNew().Add(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqSub(t *testing.T) {
	lhs := Bls12381FqNew().SetOne()
	rhs := Bls12381FqNew().SetOne()
	exp := Bls12381FqNew().SetZero()
	res := Bls12381FqNew().Sub(lhs, rhs)
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

		a := Bls12381FqNew().Sub(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqMul(t *testing.T) {
	lhs := Bls12381FqNew().SetOne()
	rhs := Bls12381FqNew().SetOne()
	exp := Bls12381FqNew().SetOne()
	res := Bls12381FqNew().Mul(lhs, rhs)
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

		a := Bls12381FqNew().Mul(lhs, rhs)
		require.NotNil(t, a)
		require.Equal(t, exp, a)
	}
}

func TestFqDouble(t *testing.T) {
	a := Bls12381FqNew().SetUint64(2)
	e := Bls12381FqNew().SetUint64(4)
	require.Equal(t, e, Bls12381FqNew().Double(a))

	for i := 0; i < 25; i++ {
		tv := rand.Uint32()
		ttv := uint64(tv) * 2
		a = Bls12381FqNew().SetUint64(uint64(tv))
		e = Bls12381FqNew().SetUint64(ttv)
		require.Equal(t, e, Bls12381FqNew().Double(a))
	}
}

func TestFqSquare(t *testing.T) {
	a := Bls12381FqNew().SetUint64(4)
	e := Bls12381FqNew().SetUint64(16)
	require.Equal(t, 1, e.Equal(a.Square(a)))

	a.SetUint64(2854263694)
	e.SetUint64(8146821234886525636)
	require.Equal(t, 1, e.Equal(a.Square(a)))

	for i := 0; i < 25; i++ {
		j := rand.Uint32()
		exp := uint64(j) * uint64(j)
		e.SetUint64(exp)
		a.SetUint64(uint64(j))
		require.Equal(t, 1, e.Equal(a.Square(a)), "exp = %d, j = %d", exp, j)
	}
}

func TestFqNeg(t *testing.T) {
	g := Bls12381FqNew().SetRaw(&fqGenerator)
	a := Bls12381FqNew().SetOne()
	a.Neg(a)
	e := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{0xfffffffd00000003, 0xfb38ec08fffb13fc, 0x99ad88181ce5880f, 0x5bc8f5f97cd877d8})
	require.Equal(t, 1, e.Equal(a))
	a.Neg(g)
	e = Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{0xfffffff000000010, 0x3bda402fffe5bfef, 0x339d80809a1d8055, 0x3eda753299d7d483})
	require.Equal(t, e, a)
}

func TestFqExp(t *testing.T) {
	e := Bls12381FqNew().SetUint64(8)
	a := Bls12381FqNew().SetUint64(2)
	by := Bls12381FqNew().SetUint64(3)
	require.Equal(t, e, a.Exp(a, by))
}

func TestFqSqrt(t *testing.T) {
	t1 := Bls12381FqNew().SetUint64(2)
	t2 := Bls12381FqNew().Neg(t1)
	t3 := Bls12381FqNew().Square(t1)
	_, wasSquare := t3.Sqrt(t3)

	require.True(t, wasSquare)
	require.Equal(t, 1, t1.Equal(t3)|t2.Equal(t3))
	t1.SetUint64(5)
	_, wasSquare = Bls12381FqNew().Sqrt(t1)
	require.False(t, wasSquare)
}

func TestFqInvert(t *testing.T) {
	twoInv := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{0xffffffff, 0xac425bfd0001a401, 0xccc627f7f65e27fa, 0xc1258acd66282b7})
	two := Bls12381FqNew().SetUint64(2)
	a, inverted := Bls12381FqNew().Invert(two)
	require.True(t, inverted)
	require.Equal(t, a, twoInv)

	rootOfUnity := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{0xb9b58d8c5f0e466a, 0x5b1b4c801819d7ec, 0x0af53ae352a31e64, 0x5bf3adda19e9b27b})
	rootOfUnityInv := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{0x4256481adcf3219a, 0x45f37b7f96b6cad3, 0xf9c3f1d75f7a3b27, 0x2d2fc049658afd43})
	a, inverted = Bls12381FqNew().Invert(rootOfUnity)
	require.True(t, inverted)
	require.Equal(t, a, rootOfUnityInv)

	lhs := Bls12381FqNew().SetUint64(9)
	rhs := Bls12381FqNew().SetUint64(3)
	rhsInv, inverted := Bls12381FqNew().Invert(rhs)
	require.True(t, inverted)
	require.Equal(t, rhs, Bls12381FqNew().Mul(lhs, rhsInv))

	rhs.SetZero()
	_, inverted = Bls12381FqNew().Invert(rhs)
	require.False(t, inverted)
}

func TestFqCMove(t *testing.T) {
	t1 := Bls12381FqNew().SetUint64(5)
	t2 := Bls12381FqNew().SetUint64(10)
	require.Equal(t, t1, Bls12381FqNew().CMove(t1, t2, 0))
	require.Equal(t, t2, Bls12381FqNew().CMove(t1, t2, 1))
}

func TestFqBytes(t *testing.T) {
	t1 := Bls12381FqNew().SetUint64(99)
	seq := t1.Bytes()
	t2, err := Bls12381FqNew().SetBytes(&seq)
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
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{2731658267414164836, 14655288906067898431, 6537465423330262322, 8306191141697566219}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{6472764012681988529, 10848812988401906064, 2961825807536828898, 4282183981941645679}),
			e: 1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{8023004109510539223, 4652004072850285717, 1877219145646046927, 383214385093921911}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{10099384440823804262, 16139476942229308465, 8636966320777393798, 5435928725024696785}),
			e: -1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{3741840066202388211, 12165774400417314871, 16619312580230515379, 16195032234110087705}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{3905865991286066744, 543690822309071825, 17963103015950210055, 3745476720756119742}),
			e: 1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{16660853697936147788, 7799793619412111108, 13515141085171033220, 2641079731236069032}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{17790588295388238399, 571847801379669440, 14537208974498222469, 12792570372087452754}),
			e: -1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{3912839285384959186, 2701177075110484070, 6453856448115499033, 6475797457962597458}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{1282566391665688512, 13503640416992806563, 2962240104675990153, 3374904770947067689}),
			e: 1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{5716631803409360103, 7859567470082614154, 12747956220853330146, 18434584096087315020}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{16317076441459028418, 12854146980376319601, 2258436689269031143, 9531877130792223752}),
			e: 1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{17955191469941083403, 10350326247207200880, 17263512235150705075, 12700328451238078022}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{6767595547459644695, 7146403825494928147, 12269344038346710612, 9122477829383225603}),
			e: 1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{17099388671847024438, 6426264987820696548, 10641143464957227405, 7709745403700754098}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{10799154372990268556, 17178492485719929374, 5705777922258988797, 8051037767683567782}),
			e: -1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{4567139260680454325, 1629385880182139061, 16607020832317899145, 1261011562621553200}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{13487234491304534488, 17872642955936089265, 17651026784972590233, 9468934643333871559}),
			e: -1,
		},
		{
			a: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{18071070103467571798, 11787850505799426140, 10631355976141928593, 4867785203635092610}),
			b: Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{12596443599426461624, 10176122686151524591, 17075755296887483439, 6726169532695070719}),
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
	t1 := Bls12381FqNew().SetBigInt(big.NewInt(9999))
	t2 := Bls12381FqNew().SetBigInt(t1.BigInt())
	require.Equal(t, t1, t2)

	e := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{0x673053fc60e06500, 0x86e6d480b4f76ada, 0x7fc68f9fefa23291, 0x3fb17f49bdda126d})
	b := new(big.Int).SetBytes([]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
	e.Neg(e)
	b.Neg(b)
	t1.SetBigInt(b)
	require.Equal(t, e, t1)
}

func TestFqSetBytesWide(t *testing.T) {
	e := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{0xc759fba87ff8c5a6, 0x9ef5194839e7df44, 0x21375d22b678bf0e, 0x38b105387033fd57})

	a := Bls12381FqNew().SetBytesWide(&[64]byte{
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

func TestFqSetBytesWideBigInt(t *testing.T) {
	params := getBls12381FqParams()
	var tv2 [64]byte
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(tv2[:])
		e := new(big.Int).SetBytes(tv2[:])
		e.Mod(e, params.BiModulus)

		tv := internal.ReverseScalarBytes(tv2[:])
		copy(tv2[:], tv)
		a := Bls12381FqNew().SetBytesWide(&tv2)
		require.Equal(t, 0, e.Cmp(a.BigInt()))
	}
}

func TestFqToMontgomery(t *testing.T) {
	v := Bls12381FqNew().SetUint64(2)
	require.Equal(t, [native.FieldLimbs]uint64{0x3fffffffc, 0xb1096ff400069004, 0x33189fdfd9789fea, 0x304962b3598a0adf}, v.Value)
}

func TestFqFromMontgomery(t *testing.T) {
	e := [native.FieldLimbs]uint64{2, 0, 0, 0}
	a := [native.FieldLimbs]uint64{0, 0, 0, 0}
	v := Bls12381FqNew().SetUint64(2)
	v.Arithmetic.FromMontgomery(&a, &v.Value)
	require.Equal(t, e, a)
}
