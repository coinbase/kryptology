//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestScalarBls12381G1Random(t *testing.T) {
	bls12381g1 := BLS12381G1()
	sc := bls12381g1.Scalar.Random(testRng())
	s, ok := sc.(*ScalarBls12381)
	assert.True(t, ok)
	expected, _ := new(big.Int).SetString("1208bca85f538782d3941c7e805b239d181247a3c0ab58db6b1c8848804df8c8", 16)
	assert.Equal(t, s.Value, expected)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12381g1.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarBls12381)
		assert.True(t, ok)
		assert.True(t, !sc.IsZero())
	}
}

func TestScalarBls12381G1Hash(t *testing.T) {
	var b [32]byte
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarBls12381)
	assert.True(t, ok)
	expected, _ := new(big.Int).SetString("07ec86a2ab79613fc0294e058151ddc74db38b0cde95a4678eb91f1258f31b40", 16)
	assert.Equal(t, s.Value, expected)
}

func TestScalarBls12381G1Zero(t *testing.T) {
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Scalar.Zero()
	assert.True(t, sc.IsZero())
	assert.True(t, sc.IsEven())
}

func TestScalarBls12381G1One(t *testing.T) {
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Scalar.One()
	assert.True(t, sc.IsOne())
	assert.True(t, sc.IsOdd())
}

func TestScalarBls12381G1New(t *testing.T) {
	bls12381G1 := BLS12381G1()
	three := bls12381G1.Scalar.New(3)
	assert.True(t, three.IsOdd())
	four := bls12381G1.Scalar.New(4)
	assert.True(t, four.IsEven())
	neg1 := bls12381G1.Scalar.New(-1)
	assert.True(t, neg1.IsEven())
	neg2 := bls12381G1.Scalar.New(-2)
	assert.True(t, neg2.IsOdd())
}

func TestScalarBls12381G1Square(t *testing.T) {
	bls12381G1 := BLS12381G1()
	three := bls12381G1.Scalar.New(3)
	nine := bls12381G1.Scalar.New(9)
	assert.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarBls12381G1Cube(t *testing.T) {
	bls12381G1 := BLS12381G1()
	three := bls12381G1.Scalar.New(3)
	twentySeven := bls12381G1.Scalar.New(27)
	assert.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarBls12381G1Double(t *testing.T) {
	bls12381G1 := BLS12381G1()
	three := bls12381G1.Scalar.New(3)
	six := bls12381G1.Scalar.New(6)
	assert.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarBls12381G1Neg(t *testing.T) {
	bls12381G1 := BLS12381G1()
	one := bls12381G1.Scalar.One()
	neg1 := bls12381G1.Scalar.New(-1)
	assert.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := bls12381G1.Scalar.New(333333)
	expected := bls12381G1.Scalar.New(-333333)
	assert.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarBls12381G1Invert(t *testing.T) {
	bls12381G1 := BLS12381G1()
	nine := bls12381G1.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarBls12381)
	expected, err := bls12381G1.Scalar.SetBigInt(bhex("19c308bd25b13848eef068e557794c72f62a247271c6bf1c38e38e38aaaaaaab"))
	assert.NoError(t, err)
	assert.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarBls12381G1Sqrt(t *testing.T) {
	bls12381G1 := BLS12381G1()
	nine := bls12381G1.Scalar.New(9)
	actual, err := nine.Sqrt()
	assert.NoError(t, err)
	sa, _ := actual.(*ScalarBls12381)
	expected, err := bls12381G1.Scalar.SetBigInt(bhex("73eda753299d7d483339d80809a1d80553bda402fffe5bfefffffffefffffffe"))
	assert.NoError(t, err)
	assert.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarBls12381G1Add(t *testing.T) {
	bls12381G1 := BLS12381G1()
	nine := bls12381G1.Scalar.New(9)
	six := bls12381G1.Scalar.New(6)
	fifteen := nine.Add(six)
	assert.NotNil(t, fifteen)
	expected := bls12381G1.Scalar.New(15)
	assert.Equal(t, expected.Cmp(fifteen), 0)
	n := new(big.Int).Set(g1.Q())
	n.Sub(n, big.NewInt(3))

	upper, err := bls12381G1.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	actual := upper.Add(nine)
	assert.NotNil(t, actual)
	assert.Equal(t, actual.Cmp(six), 0)
}

func TestScalarBls12381G1Sub(t *testing.T) {
	bls12381G1 := BLS12381G1()
	nine := bls12381G1.Scalar.New(9)
	six := bls12381G1.Scalar.New(6)
	n := new(big.Int).Set(g1.Q())
	n.Sub(n, big.NewInt(3))

	expected, err := bls12381G1.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	actual := six.Sub(nine)
	assert.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	assert.Equal(t, actual.Cmp(bls12381G1.Scalar.New(3)), 0)
}

func TestScalarBls12381G1Mul(t *testing.T) {
	bls12381G1 := BLS12381G1()
	nine := bls12381G1.Scalar.New(9)
	six := bls12381G1.Scalar.New(6)
	actual := nine.Mul(six)
	assert.Equal(t, actual.Cmp(bls12381G1.Scalar.New(54)), 0)
	n := new(big.Int).Set(g1.Q())
	n.Sub(n, big.NewInt(1))
	upper, err := bls12381G1.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	assert.Equal(t, upper.Mul(upper).Cmp(bls12381G1.Scalar.New(1)), 0)
}

func TestScalarBls12381G1Div(t *testing.T) {
	bls12381G1 := BLS12381G1()
	nine := bls12381G1.Scalar.New(9)
	actual := nine.Div(nine)
	assert.Equal(t, actual.Cmp(bls12381G1.Scalar.New(1)), 0)
	assert.Equal(t, bls12381G1.Scalar.New(54).Div(nine).Cmp(bls12381G1.Scalar.New(6)), 0)
}

func TestScalarBls12381G1Serialize(t *testing.T) {
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Scalar.New(255)
	sequence := sc.Bytes()
	assert.Equal(t, len(sequence), 32)
	assert.Equal(t, sequence, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	ret, err := bls12381G1.Scalar.SetBytes(sequence)
	assert.NoError(t, err)
	assert.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = bls12381G1.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		assert.Equal(t, len(sequence), 32)
		ret, err = bls12381G1.Scalar.SetBytes(sequence)
		assert.NoError(t, err)
		assert.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarBls12381G1Nil(t *testing.T) {
	bls12381G1 := BLS12381G1()
	one := bls12381G1.Scalar.New(1)
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, one.Div(nil))
	assert.Nil(t, bls12381G1.Scalar.Random(nil))
	assert.Equal(t, one.Cmp(nil), -2)
	_, err := bls12381G1.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestScalarBls12381Point(t *testing.T) {
	bls12381G1 := BLS12381G1()
	_, ok := bls12381G1.Scalar.Point().(*PointBls12381G1)
	assert.True(t, ok)
	bls12381G2 := BLS12381G2()
	_, ok = bls12381G2.Scalar.Point().(*PointBls12381G2)
	assert.True(t, ok)
}

func TestPointBls12381G2Random(t *testing.T) {
	bls12381G2 := BLS12381G2()
	sc := bls12381G2.Point.Random(testRng())
	s, ok := sc.(*PointBls12381G2)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("13520facd10fc1cd71384d86b445b0e65ac1bf9205e86cd02837c064d1886b8aa3dc5348845bb06216601de5628315600967df84901b1c4f1fac87f9fc13d02f9c3a0f8cf462c86d2b4bbddf7b8520a3df2a5c541724a2c7ddc9eec45f0b2f74", 16)
	expectedY, _ := new(big.Int).SetString("0a46cb3d91222e4eb068e1eb41e7ef3efd1c705c1272476d74064541661736bf0910adcfe37fafbabf0989e0c9ae122b0ce11d941d60570a9b39ff332e09f9ba661a4aac019911032b1ddb0dee7ce5a34aebb8cb6f1fa21e5cf565d06dfc7b61", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12381G2.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls12381G2)
		assert.True(t, ok)
		assert.True(t, !sc.IsIdentity())
	}
}

func TestPointBls12381G2Hash(t *testing.T) {
	var b [32]byte
	bls12381G2 := BLS12381G2()
	sc := bls12381G2.Point.Hash(b[:])
	s, ok := sc.(*PointBls12381G2)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("15060db402f549b74be2656006f369e0892a857cd7d16738761ad9ba01bf8da2d1e45f86c4f13fe0850ba1195a2e8aa91914cb4d8eac1e4582a45d92cd2c8fec3d34c11629503dafe60f7910e39eff6f6b6d41d881e9fb2b9857c06de7966077", 16)
	expectedY, _ := new(big.Int).SetString("0e509ea244e9f57d3a6f5140b39792424fb0889b5a3cad7f65d84cf9f3fccf64bec9ff45fc1f0c8fb7f045930336363217b27f340cd6f8bbf15fb1872a4e137c9655aad86672fa4d7e9973c39eec102069a36c632f7f90e6ec75b23dd6accafc", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
}

func TestPointBls12381G2Identity(t *testing.T) {
	bls12381G2 := BLS12381G2()
	sc := bls12381G2.Point.Identity()
	assert.True(t, sc.IsIdentity())
	assert.Equal(t, sc.ToAffineCompressed(), []byte{0xc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
}

func TestPointBls12381G2Generator(t *testing.T) {
	bls12381G2 := BLS12381G2()
	sc := bls12381G2.Point.Generator()
	s, ok := sc.(*PointBls12381G2)
	assert.True(t, ok)
	assert.True(t, g2.Equal(s.Value, g2.One()))
}

func TestPointBls12381G2Set(t *testing.T) {
	bls12381G2 := BLS12381G2()
	iden, err := bls12381G2.Point.Set(big.NewInt(0), big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, iden.IsIdentity())
	generator := g2.ToBytes(g2.One())
	_, err = bls12381G2.Point.Set(new(big.Int).SetBytes(generator[:96]), new(big.Int).SetBytes(generator[96:]))
	assert.NoError(t, err)
}

func TestPointBls12381G2Double(t *testing.T) {
	bls12381G2 := BLS12381G2()
	g := bls12381G2.Point.Generator()
	gg2 := g.Double()
	assert.True(t, gg2.Equal(g.Mul(bls12381G2.Scalar.New(2))))
	i := bls12381G2.Point.Identity()
	assert.True(t, i.Double().Equal(i))
}

func TestPointBls12381G2Neg(t *testing.T) {
	bls12381G2 := BLS12381G1()
	g := bls12381G2.Point.Generator().Neg()
	assert.True(t, g.Neg().Equal(bls12381G2.Point.Generator()))
	assert.True(t, bls12381G2.Point.Identity().Neg().Equal(bls12381G2.Point.Identity()))
}

func TestPointBls12381G2Add(t *testing.T) {
	bls12381G2 := BLS12381G2()
	pt := bls12381G2.Point.Generator()
	assert.True(t, pt.Add(pt).Equal(pt.Double()))
	assert.True(t, pt.Mul(bls12381G2.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12381G2Sub(t *testing.T) {
	bls12381G2 := BLS12381G2()
	g := bls12381G2.Point.Generator()
	pt := bls12381G2.Point.Generator().Mul(bls12381G2.Scalar.New(4))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls12381G2Mul(t *testing.T) {
	bls12381G2 := BLS12381G2()
	g := bls12381G2.Point.Generator()
	pt := bls12381G2.Point.Generator().Mul(bls12381G2.Scalar.New(4))
	assert.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12381G2Serialize(t *testing.T) {
	bls12381G2 := BLS12381G2()
	ss := bls12381G2.Scalar.Random(testRng())
	g := bls12381G2.Point.Generator()

	ppt := g.Mul(ss)
	assert.Equal(t, ppt.ToAffineCompressed(), []byte{0xad, 0x49, 0x42, 0x28, 0xc6, 0x2c, 0x54, 0xb3, 0xfd, 0xb0, 0xed, 0xd1, 0x8f, 0x10, 0x1f, 0x9a, 0x9a, 0xc5, 0x68, 0x57, 0xff, 0x99, 0x93, 0x6e, 0x8d, 0x79, 0x95, 0xc3, 0xc9, 0xa8, 0xdf, 0x99, 0x63, 0xa2, 0x67, 0xe4, 0xaa, 0x62, 0x9c, 0x33, 0xb0, 0x54, 0x5e, 0xb6, 0xd6, 0x36, 0xa4, 0x0, 0x12, 0x9b, 0x9b, 0x7f, 0x27, 0xce, 0x26, 0x29, 0xf3, 0xa4, 0xf0, 0x8d, 0xfb, 0x48, 0x6d, 0xc7, 0x73, 0xa0, 0x18, 0x84, 0xc7, 0x98, 0xb7, 0xa7, 0xb1, 0x8, 0x88, 0xe9, 0x21, 0xe1, 0xed, 0x61, 0x3c, 0x37, 0xf7, 0xf3, 0xc1, 0x4f, 0x95, 0xfa, 0x64, 0xda, 0x39, 0x32, 0x4, 0x95, 0x87, 0x44})
	assert.Equal(t, ppt.ToAffineUncompressed(), []byte{0xd, 0x49, 0x42, 0x28, 0xc6, 0x2c, 0x54, 0xb3, 0xfd, 0xb0, 0xed, 0xd1, 0x8f, 0x10, 0x1f, 0x9a, 0x9a, 0xc5, 0x68, 0x57, 0xff, 0x99, 0x93, 0x6e, 0x8d, 0x79, 0x95, 0xc3, 0xc9, 0xa8, 0xdf, 0x99, 0x63, 0xa2, 0x67, 0xe4, 0xaa, 0x62, 0x9c, 0x33, 0xb0, 0x54, 0x5e, 0xb6, 0xd6, 0x36, 0xa4, 0x0, 0x12, 0x9b, 0x9b, 0x7f, 0x27, 0xce, 0x26, 0x29, 0xf3, 0xa4, 0xf0, 0x8d, 0xfb, 0x48, 0x6d, 0xc7, 0x73, 0xa0, 0x18, 0x84, 0xc7, 0x98, 0xb7, 0xa7, 0xb1, 0x8, 0x88, 0xe9, 0x21, 0xe1, 0xed, 0x61, 0x3c, 0x37, 0xf7, 0xf3, 0xc1, 0x4f, 0x95, 0xfa, 0x64, 0xda, 0x39, 0x32, 0x4, 0x95, 0x87, 0x44, 0x12, 0x37, 0xbe, 0xd8, 0xbf, 0xdb, 0x2a, 0xcc, 0xd, 0x17, 0xcc, 0x6c, 0xfe, 0x7f, 0x49, 0xe4, 0x5d, 0xaf, 0xa3, 0x54, 0xb0, 0xe3, 0xc5, 0x86, 0xff, 0x20, 0x64, 0x30, 0x65, 0xc, 0x7c, 0x7c, 0x2f, 0x80, 0xee, 0x7c, 0x74, 0xd2, 0x8d, 0x2e, 0x92, 0xba, 0x16, 0xe4, 0x13, 0xa6, 0x6, 0xfd, 0x9, 0x3e, 0xd8, 0x59, 0xcc, 0x59, 0x3b, 0xa8, 0x64, 0x44, 0x6b, 0xc, 0xba, 0xd9, 0x9a, 0x2c, 0xed, 0x2d, 0xe4, 0x1e, 0xf1, 0xe6, 0xda, 0x8a, 0xfc, 0x62, 0x1d, 0xf, 0x3b, 0xdf, 0xf6, 0xe5, 0xa3, 0xd1, 0xcd, 0xec, 0x21, 0x73, 0x1f, 0x7d, 0xb2, 0x26, 0x7d, 0x5f, 0xf2, 0xd2, 0xc9, 0x4})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls12381G2.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		assert.Equal(t, len(cmprs), 96)
		retC, err := pt.FromAffineCompressed(cmprs)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		assert.Equal(t, len(un), 192)
		retU, err := pt.FromAffineUncompressed(un)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retU))
	}
}

func TestPointBls12381G2Nil(t *testing.T) {
	bls12381G2 := BLS12381G2()
	one := bls12381G2.Point.Generator()
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, bls12381G2.Scalar.Random(nil))
	assert.False(t, one.Equal(nil))
	_, err := bls12381G2.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestPointBls12381G1Random(t *testing.T) {
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Point.Random(testRng())
	s, ok := sc.(*PointBls12381G1)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("191b78617711a9aca6092c50d8c715db4856b84e48b9aa07dc42719335751b2ef3dfa2f6f15afc6dba2d0fb3be63dd83", 16)
	expectedY, _ := new(big.Int).SetString("0d7053b5d9b5f23839a0dc4ad18bb55bd6ac20e1e53750c1140e434c61f87033e6338f10955b690eee0efc383d6e6d25", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12381G1.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls12381G1)
		assert.True(t, ok)
		assert.True(t, !sc.IsIdentity())
	}
}

func TestPointBls12381G1Hash(t *testing.T) {
	var b [32]byte
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Point.Hash(b[:])
	s, ok := sc.(*PointBls12381G1)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("1239150a658a8b04d56f3d14593bb3fa6f791ee221224480b5170da43a4c3602f97be83649c31b2738a606b89c2e9fea", 16)
	expectedY, _ := new(big.Int).SetString("124af4bc2008ed9be7db7137f8b41e4b65f37cfd34938c4466531dc7ed657e66ff6c6c6912488d9285e0645c6ba62b92", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
}

func TestPointBls12381G1Identity(t *testing.T) {
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Point.Identity()
	assert.True(t, sc.IsIdentity())
	assert.Equal(t, sc.ToAffineCompressed(), []byte{0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointBls12381G1Generator(t *testing.T) {
	bls12381G1 := BLS12381G1()
	sc := bls12381G1.Point.Generator()
	s, ok := sc.(*PointBls12381G1)
	assert.True(t, ok)
	assert.True(t, g1.Equal(s.Value, g1.One()))
}

func TestPointBls12381G1Set(t *testing.T) {
	bls12381G1 := BLS12381G1()
	iden, err := bls12381G1.Point.Set(big.NewInt(0), big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, iden.IsIdentity())
	generator := g1.ToBytes(g1.One())
	_, err = bls12381G1.Point.Set(new(big.Int).SetBytes(generator[:48]), new(big.Int).SetBytes(generator[48:]))
	assert.NoError(t, err)
}

func TestPointBls12381G1Double(t *testing.T) {
	bls12381G1 := BLS12381G1()
	g := bls12381G1.Point.Generator()
	g2 := g.Double()
	assert.True(t, g2.Equal(g.Mul(bls12381G1.Scalar.New(2))))
	i := bls12381G1.Point.Identity()
	assert.True(t, i.Double().Equal(i))
}

func TestPointBls12381G1Neg(t *testing.T) {
	bls12381G1 := BLS12381G1()
	g := bls12381G1.Point.Generator().Neg()
	assert.True(t, g.Neg().Equal(bls12381G1.Point.Generator()))
	assert.True(t, bls12381G1.Point.Identity().Neg().Equal(bls12381G1.Point.Identity()))
}

func TestPointBls12381G1Add(t *testing.T) {
	bls12381G1 := BLS12381G1()
	pt := bls12381G1.Point.Generator()
	assert.True(t, pt.Add(pt).Equal(pt.Double()))
	assert.True(t, pt.Mul(bls12381G1.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12381G1Sub(t *testing.T) {
	bls12381G1 := BLS12381G1()
	g := bls12381G1.Point.Generator()
	pt := bls12381G1.Point.Generator().Mul(bls12381G1.Scalar.New(4))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls12381G1Mul(t *testing.T) {
	bls12381G1 := BLS12381G1()
	g := bls12381G1.Point.Generator()
	pt := bls12381G1.Point.Generator().Mul(bls12381G1.Scalar.New(4))
	assert.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12381G1Serialize(t *testing.T) {
	bls12381G1 := BLS12381G1()
	ss := bls12381G1.Scalar.Random(testRng())
	g := bls12381G1.Point.Generator()

	ppt := g.Mul(ss)
	assert.Equal(t, ppt.ToAffineCompressed(), []byte{0xa8, 0x6d, 0xac, 0x3a, 0xd8, 0x6f, 0x6b, 0x1f, 0x6b, 0x47, 0x7f, 0x22, 0x73, 0xa9, 0x5a, 0x5f, 0x4c, 0xff, 0x1a, 0xf7, 0x27, 0xab, 0x73, 0x51, 0xfe, 0xa5, 0xfd, 0x9d, 0x21, 0xcd, 0xaa, 0x40, 0x7f, 0xf9, 0x5, 0xca, 0x2f, 0x9a, 0xdb, 0x5d, 0x5b, 0x6a, 0x86, 0xb3, 0x84, 0xc6, 0xc, 0x37})
	assert.Equal(t, ppt.ToAffineUncompressed(), []byte{0x8, 0x6d, 0xac, 0x3a, 0xd8, 0x6f, 0x6b, 0x1f, 0x6b, 0x47, 0x7f, 0x22, 0x73, 0xa9, 0x5a, 0x5f, 0x4c, 0xff, 0x1a, 0xf7, 0x27, 0xab, 0x73, 0x51, 0xfe, 0xa5, 0xfd, 0x9d, 0x21, 0xcd, 0xaa, 0x40, 0x7f, 0xf9, 0x5, 0xca, 0x2f, 0x9a, 0xdb, 0x5d, 0x5b, 0x6a, 0x86, 0xb3, 0x84, 0xc6, 0xc, 0x37, 0x10, 0x5f, 0x99, 0x9a, 0x58, 0x93, 0x4, 0x35, 0x76, 0x91, 0x7c, 0x8e, 0x6a, 0xcb, 0x3c, 0xad, 0xdb, 0x84, 0x3, 0xd9, 0x24, 0xec, 0xa2, 0xa8, 0x4e, 0x99, 0x4f, 0xbb, 0x77, 0x3a, 0x3f, 0x9a, 0xd, 0x64, 0x9d, 0x76, 0xe, 0x61, 0xfb, 0x60, 0x36, 0x55, 0x91, 0x5c, 0x49, 0x20, 0x43, 0x29})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls12381G1.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		assert.Equal(t, len(cmprs), 48)
		retC, err := pt.FromAffineCompressed(cmprs)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		assert.Equal(t, len(un), 96)
		retU, err := pt.FromAffineUncompressed(un)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retU))
	}
}

func TestPointBls12381G1Nil(t *testing.T) {
	bls12381G1 := BLS12381G1()
	one := bls12381G1.Point.Generator()
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, bls12381G1.Scalar.Random(nil))
	assert.False(t, one.Equal(nil))
	_, err := bls12381G1.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestPointBls12381G1SumOfProducts(t *testing.T) {
	lhs := new(PointBls12381G1).Generator().Mul(new(ScalarBls12381).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointBls12381G1).Generator()
	}
	scalars := []Scalar{
		new(ScalarBls12381).New(8),
		new(ScalarBls12381).New(9),
		new(ScalarBls12381).New(10),
		new(ScalarBls12381).New(11),
		new(ScalarBls12381).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	assert.NotNil(t, rhs)
	assert.True(t, lhs.Equal(rhs))
}
