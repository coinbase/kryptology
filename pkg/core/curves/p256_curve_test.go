//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScalarP256Random(t *testing.T) {
	p256 := P256()
	sc := p256.Scalar.Random(testRng())
	s, ok := sc.(*ScalarP256)
	require.True(t, ok)
	expected := bhex("02ca487e56f8cb1ad9666027b2282d1159792d39a5e05f0bc696f85de5acc6d4")
	require.Equal(t, s.value.BigInt(), expected)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := p256.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarP256)
		require.True(t, ok)
		require.True(t, !sc.IsZero())
	}
}

func TestScalarP256Hash(t *testing.T) {
	var b [32]byte
	p256 := P256()
	sc := p256.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarP256)
	require.True(t, ok)
	expected := bhex("43ca74a23022b221e60c8499781afff2a2776ec23362712df90a3080b5557f90")
	require.Equal(t, s.value.BigInt(), expected)
}

func TestScalarP256Zero(t *testing.T) {
	p256 := P256()
	sc := p256.Scalar.Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarP256One(t *testing.T) {
	p256 := P256()
	sc := p256.Scalar.One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarP256New(t *testing.T) {
	p256 := P256()
	three := p256.Scalar.New(3)
	require.True(t, three.IsOdd())
	four := p256.Scalar.New(4)
	require.True(t, four.IsEven())
	neg1 := p256.Scalar.New(-1)
	require.True(t, neg1.IsEven())
	neg2 := p256.Scalar.New(-2)
	require.True(t, neg2.IsOdd())
}

func TestScalarP256Square(t *testing.T) {
	p256 := P256()
	three := p256.Scalar.New(3)
	nine := p256.Scalar.New(9)
	require.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarP256Cube(t *testing.T) {
	p256 := P256()
	three := p256.Scalar.New(3)
	twentySeven := p256.Scalar.New(27)
	require.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarP256Double(t *testing.T) {
	p256 := P256()
	three := p256.Scalar.New(3)
	six := p256.Scalar.New(6)
	require.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarP256Neg(t *testing.T) {
	p256 := P256()
	one := p256.Scalar.One()
	neg1 := p256.Scalar.New(-1)
	require.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := p256.Scalar.New(333333)
	expected := p256.Scalar.New(-333333)
	require.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarP256Invert(t *testing.T) {
	p256 := P256()
	nine := p256.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarP256)
	bn := bhex("8e38e38daaaaaaab38e38e38e38e38e368f2197ceb0d1f2d6af570a536e1bf66")
	expected, err := p256.Scalar.SetBigInt(bn)
	require.NoError(t, err)
	require.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarP256Sqrt(t *testing.T) {
	p256 := P256()
	nine := p256.Scalar.New(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*ScalarP256)
	expected := p256.Scalar.New(3)
	require.NoError(t, err)
	require.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarP256Add(t *testing.T) {
	p256 := P256()
	nine := p256.Scalar.New(9)
	six := p256.Scalar.New(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := p256.Scalar.New(15)
	require.Equal(t, expected.Cmp(fifteen), 0)
	n := new(big.Int).Set(elliptic.P256().Params().N)
	n.Sub(n, big.NewInt(3))

	upper, err := p256.Scalar.SetBigInt(n)
	require.NoError(t, err)
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, actual.Cmp(six), 0)
}

func TestScalarP256Sub(t *testing.T) {
	p256 := P256()
	nine := p256.Scalar.New(9)
	six := p256.Scalar.New(6)
	n := new(big.Int).Set(elliptic.P256().Params().N)
	n.Sub(n, big.NewInt(3))

	expected, err := p256.Scalar.SetBigInt(n)
	require.NoError(t, err)
	actual := six.Sub(nine)
	require.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	require.Equal(t, actual.Cmp(p256.Scalar.New(3)), 0)
}

func TestScalarP256Mul(t *testing.T) {
	p256 := P256()
	nine := p256.Scalar.New(9)
	six := p256.Scalar.New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(p256.Scalar.New(54)), 0)
	n := new(big.Int).Set(elliptic.P256().Params().N)
	n.Sub(n, big.NewInt(1))
	upper, err := p256.Scalar.SetBigInt(n)
	require.NoError(t, err)
	require.Equal(t, upper.Mul(upper).Cmp(p256.Scalar.New(1)), 0)
}

func TestScalarP256Div(t *testing.T) {
	p256 := P256()
	nine := p256.Scalar.New(9)
	actual := nine.Div(nine)
	require.Equal(t, actual.Cmp(p256.Scalar.New(1)), 0)
	require.Equal(t, p256.Scalar.New(54).Div(nine).Cmp(p256.Scalar.New(6)), 0)
}

func TestScalarP256Serialize(t *testing.T) {
	p256 := P256()
	sc := p256.Scalar.New(255)
	sequence := sc.Bytes()
	require.Equal(t, len(sequence), 32)
	require.Equal(t, sequence, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	ret, err := p256.Scalar.SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = p256.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		require.Equal(t, len(sequence), 32)
		ret, err = p256.Scalar.SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarP256Nil(t *testing.T) {
	p256 := P256()
	one := p256.Scalar.New(1)
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, one.Div(nil))
	require.Nil(t, p256.Scalar.Random(nil))
	require.Equal(t, one.Cmp(nil), -2)
	_, err := p256.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointP256Random(t *testing.T) {
	p256 := P256()
	sc := p256.Point.Random(testRng())
	s, ok := sc.(*PointP256)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("7d31a079d75687cd0dd1118996f726c3e4d52806a5124d23c1faeee9fadb2201", 16)
	expectedY, _ := new(big.Int).SetString("da62629181a0e2ec6943c263bbe81f53d87cb94d0039a707309f415f04d47bab", 16)
	require.Equal(t, s.X().BigInt(), expectedX)
	require.Equal(t, s.Y().BigInt(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := p256.Point.Random(crand.Reader)
		_, ok := sc.(*PointP256)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
	}
}

func TestPointP256Hash(t *testing.T) {
	var b [32]byte
	p256 := P256()
	sc := p256.Point.Hash(b[:])
	s, ok := sc.(*PointP256)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("10f1699c24cf20f5322b92bfab4fdf14814ee1472ffc6b1ef2ec36be3051925d", 16)
	expectedY, _ := new(big.Int).SetString("99efe055f13c3e5e3fc65be12043a89d0482b806c7a9945c276b7aee887c1de0", 16)
	require.Equal(t, s.X().BigInt(), expectedX)
	require.Equal(t, s.Y().BigInt(), expectedY)
}

func TestPointP256Identity(t *testing.T) {
	p256 := P256()
	sc := p256.Point.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointP256Generator(t *testing.T) {
	p256 := P256()
	sc := p256.Point.Generator()
	s, ok := sc.(*PointP256)
	require.True(t, ok)
	require.Equal(t, s.X().BigInt(), elliptic.P256().Params().Gx)
	require.Equal(t, s.Y().BigInt(), elliptic.P256().Params().Gy)
}

func TestPointP256Set(t *testing.T) {
	p256 := P256()
	iden, err := p256.Point.Set(big.NewInt(0), big.NewInt(0))
	require.NoError(t, err)
	require.True(t, iden.IsIdentity())
	_, err = p256.Point.Set(elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	require.NoError(t, err)
}

func TestPointP256Double(t *testing.T) {
	p256 := P256()
	g := p256.Point.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(p256.Scalar.New(2))))
	i := p256.Point.Identity()
	require.True(t, i.Double().Equal(i))
}

func TestPointP256Neg(t *testing.T) {
	p256 := P256()
	g := p256.Point.Generator().Neg()
	require.True(t, g.Neg().Equal(p256.Point.Generator()))
	require.True(t, p256.Point.Identity().Neg().Equal(p256.Point.Identity()))
}

func TestPointP256Add(t *testing.T) {
	p256 := P256()
	pt := p256.Point.Generator()
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(p256.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointP256Sub(t *testing.T) {
	p256 := P256()
	g := p256.Point.Generator()
	pt := p256.Point.Generator().Mul(p256.Scalar.New(4))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointP256Mul(t *testing.T) {
	p256 := P256()
	g := p256.Point.Generator()
	pt := p256.Point.Generator().Mul(p256.Scalar.New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointP256Serialize(t *testing.T) {
	p256 := P256()
	ss := p256.Scalar.Random(testRng())
	g := p256.Point.Generator()

	ppt := g.Mul(ss)
	require.Equal(t, ppt.ToAffineCompressed(), []byte{0x3, 0x1b, 0xfa, 0x44, 0xfb, 0x6, 0xa4, 0x6d, 0xe1, 0x38, 0x72, 0x39, 0x9a, 0x69, 0xd4, 0x71, 0x38, 0x3f, 0x8b, 0x13, 0x39, 0x60, 0xdc, 0x61, 0x91, 0x22, 0x70, 0x58, 0x7c, 0xdf, 0x82, 0x33, 0xba})
	require.Equal(t, ppt.ToAffineUncompressed(), []byte{0x4, 0x1b, 0xfa, 0x44, 0xfb, 0x6, 0xa4, 0x6d, 0xe1, 0x38, 0x72, 0x39, 0x9a, 0x69, 0xd4, 0x71, 0x38, 0x3f, 0x8b, 0x13, 0x39, 0x60, 0xdc, 0x61, 0x91, 0x22, 0x70, 0x58, 0x7c, 0xdf, 0x82, 0x33, 0xba, 0x48, 0xdf, 0x58, 0xac, 0x70, 0xf3, 0x9b, 0x9d, 0x5d, 0x84, 0x6e, 0x2d, 0x75, 0xc9, 0x6, 0x1e, 0xd9, 0x62, 0x8b, 0x15, 0x0, 0x65, 0x69, 0x79, 0xfb, 0x42, 0xc, 0x35, 0xce, 0x2e, 0x8b, 0xfd})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := p256.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		require.Equal(t, len(cmprs), 33)
		retC, err := pt.FromAffineCompressed(cmprs)
		require.NoError(t, err)
		require.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		require.Equal(t, len(un), 65)
		retU, err := pt.FromAffineUncompressed(un)
		require.NoError(t, err)
		require.True(t, pt.Equal(retU))
	}
}

func TestPointP256Nil(t *testing.T) {
	p256 := P256()
	one := p256.Point.Generator()
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, p256.Scalar.Random(nil))
	require.False(t, one.Equal(nil))
	_, err := p256.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointP256SumOfProducts(t *testing.T) {
	lhs := new(PointP256).Generator().Mul(new(ScalarP256).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointP256).Generator()
	}
	scalars := []Scalar{
		new(ScalarP256).New(8),
		new(ScalarP256).New(9),
		new(ScalarP256).New(10),
		new(ScalarP256).New(11),
		new(ScalarP256).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))
}
