//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	"math/big"
	"sync"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"
)

type mockReader struct {
	index int
	seed  []byte
}

var mockRngInitonce sync.Once
var mockRng mockReader

func newMockReader() {
	mockRng.index = 0
	mockRng.seed = make([]byte, 32)
	for i := range mockRng.seed {
		mockRng.seed[i] = 1
	}
}

func testRng() *mockReader {
	mockRngInitonce.Do(newMockReader)
	return &mockRng
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	limit := len(m.seed)
	for i := range p {
		p[i] = m.seed[m.index]
		m.index += 1
		m.index %= limit
	}
	n = len(p)
	err = nil
	return
}

func TestScalarK256Random(t *testing.T) {
	curve := K256()
	sc := curve.Scalar.Random(testRng())
	s, ok := sc.(*ScalarK256)
	require.True(t, ok)
	expected, _ := new(big.Int).SetString("2f71aaec5e14d747c72e46cdcaffffe6f542f38b3f0925469ceb24ac1c65885d", 16)
	require.Equal(t, s.value.BigInt(), expected)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := curve.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarK256)
		require.True(t, ok)
		require.True(t, !sc.IsZero())
	}
}

func TestScalarK256Hash(t *testing.T) {
	var b [32]byte
	k256 := K256()
	sc := k256.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarK256)
	require.True(t, ok)
	expected, _ := new(big.Int).SetString("e5cb3500b809a8202de0834a805068bc21bde09bd6367815e7523a37adf8f52e", 16)
	require.Equal(t, s.value.BigInt(), expected)
}

func TestScalarK256Zero(t *testing.T) {
	k256 := K256()
	sc := k256.Scalar.Zero()
	require.True(t, sc.IsZero())
	require.True(t, sc.IsEven())
}

func TestScalarK256One(t *testing.T) {
	k256 := K256()
	sc := k256.Scalar.One()
	require.True(t, sc.IsOne())
	require.True(t, sc.IsOdd())
}

func TestScalarK256New(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	require.True(t, three.IsOdd())
	four := k256.Scalar.New(4)
	require.True(t, four.IsEven())
	neg1 := k256.Scalar.New(-1)
	require.True(t, neg1.IsEven())
	neg2 := k256.Scalar.New(-2)
	require.True(t, neg2.IsOdd())
}

func TestScalarK256Square(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	nine := k256.Scalar.New(9)
	require.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarK256Cube(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	twentySeven := k256.Scalar.New(27)
	require.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarK256Double(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	six := k256.Scalar.New(6)
	require.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarK256Neg(t *testing.T) {
	k256 := K256()
	one := k256.Scalar.One()
	neg1 := k256.Scalar.New(-1)
	require.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := k256.Scalar.New(333333)
	expected := k256.Scalar.New(-333333)
	require.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarK256Invert(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarK256)
	bn, _ := new(big.Int).SetString("8e38e38e38e38e38e38e38e38e38e38d842841d57dd303af6a9150f8e5737996", 16)
	expected, err := k256.Scalar.SetBigInt(bn)
	require.NoError(t, err)
	require.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarK256Sqrt(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*ScalarK256)
	expected := k256.Scalar.New(3)
	require.NoError(t, err)
	require.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarK256Add(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	six := k256.Scalar.New(6)
	fifteen := nine.Add(six)
	require.NotNil(t, fifteen)
	expected := k256.Scalar.New(15)
	require.Equal(t, expected.Cmp(fifteen), 0)
	n := new(big.Int).Set(btcec.S256().N)
	n.Sub(n, big.NewInt(3))

	upper, err := k256.Scalar.SetBigInt(n)
	require.NoError(t, err)
	actual := upper.Add(nine)
	require.NotNil(t, actual)
	require.Equal(t, actual.Cmp(six), 0)
}

func TestScalarK256Sub(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	six := k256.Scalar.New(6)
	n := new(big.Int).Set(btcec.S256().N)
	n.Sub(n, big.NewInt(3))

	expected, err := k256.Scalar.SetBigInt(n)
	require.NoError(t, err)
	actual := six.Sub(nine)
	require.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	require.Equal(t, actual.Cmp(k256.Scalar.New(3)), 0)
}

func TestScalarK256Mul(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	six := k256.Scalar.New(6)
	actual := nine.Mul(six)
	require.Equal(t, actual.Cmp(k256.Scalar.New(54)), 0)
	n := new(big.Int).Set(btcec.S256().N)
	n.Sub(n, big.NewInt(1))
	upper, err := k256.Scalar.SetBigInt(n)
	require.NoError(t, err)
	require.Equal(t, upper.Mul(upper).Cmp(k256.Scalar.New(1)), 0)
}

func TestScalarK256Div(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	actual := nine.Div(nine)
	require.Equal(t, actual.Cmp(k256.Scalar.New(1)), 0)
	require.Equal(t, k256.Scalar.New(54).Div(nine).Cmp(k256.Scalar.New(6)), 0)
}

func TestScalarK256Serialize(t *testing.T) {
	k256 := K256()
	sc := k256.Scalar.New(255)
	sequence := sc.Bytes()
	require.Equal(t, len(sequence), 32)
	require.Equal(t, sequence, []byte{0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	ret, err := k256.Scalar.SetBytes(sequence)
	require.NoError(t, err)
	require.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = k256.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		require.Equal(t, len(sequence), 32)
		ret, err = k256.Scalar.SetBytes(sequence)
		require.NoError(t, err)
		require.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarK256Nil(t *testing.T) {
	k256 := K256()
	one := k256.Scalar.New(1)
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, one.Div(nil))
	require.Nil(t, k256.Scalar.Random(nil))
	require.Equal(t, one.Cmp(nil), -2)
	_, err := k256.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointK256Random(t *testing.T) {
	curve := K256()
	sc := curve.Point.Random(testRng())
	s, ok := sc.(*PointK256)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("c6e18a1d7cf834462675b31581639a18e14fd0f73f8dfd5fe2993f88f6fbe008", 16)
	expectedY, _ := new(big.Int).SetString("b65fab3243c5d07cef005d7fb335ebe8019efd954e95e68c86ef9b3bd7bccd36", 16)
	require.Equal(t, s.X().BigInt(), expectedX)
	require.Equal(t, s.Y().BigInt(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := curve.Point.Random(crand.Reader)
		_, ok := sc.(*PointK256)
		require.True(t, ok)
		require.True(t, !sc.IsIdentity())
	}
}

func TestPointK256Hash(t *testing.T) {
	var b [32]byte
	curve := K256()
	sc := curve.Point.Hash(b[:])
	s, ok := sc.(*PointK256)
	require.True(t, ok)
	expectedX, _ := new(big.Int).SetString("95d0ad42f68ddb5a808469dd75fa866890dcc7d039844e0e2d58a6d25bd9a66b", 16)
	expectedY, _ := new(big.Int).SetString("f37c564d05168dab4413caacdb8e3426143fc5fb24a470ccd8a51856c11d163c", 16)
	require.Equal(t, s.X().BigInt(), expectedX)
	require.Equal(t, s.Y().BigInt(), expectedY)
}

func TestPointK256Identity(t *testing.T) {
	k256 := K256()
	sc := k256.Point.Identity()
	require.True(t, sc.IsIdentity())
	require.Equal(t, sc.ToAffineCompressed(), []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointK256Generator(t *testing.T) {
	curve := K256()
	sc := curve.Point.Generator()
	s, ok := sc.(*PointK256)
	require.True(t, ok)
	require.Equal(t, s.X().BigInt().Cmp(btcec.S256().Gx), 0)
	require.Equal(t, s.Y().BigInt().Cmp(btcec.S256().Gy), 0)
}

func TestPointK256Set(t *testing.T) {
	k256 := K256()
	iden, err := k256.Point.Set(big.NewInt(0), big.NewInt(0))
	require.NoError(t, err)
	require.True(t, iden.IsIdentity())
	_, err = k256.Point.Set(btcec.S256().Gx, btcec.S256().Gy)
	require.NoError(t, err)
}

func TestPointK256Double(t *testing.T) {
	curve := K256()
	g := curve.Point.Generator()
	g2 := g.Double()
	require.True(t, g2.Equal(g.Mul(curve.Scalar.New(2))))
	i := curve.Point.Identity()
	require.True(t, i.Double().Equal(i))
	gg := curve.Point.Generator().Add(curve.Point.Generator())
	require.True(t, g2.Equal(gg))
}

func TestPointK256Neg(t *testing.T) {
	k256 := K256()
	g := k256.Point.Generator().Neg()
	require.True(t, g.Neg().Equal(k256.Point.Generator()))
	require.True(t, k256.Point.Identity().Neg().Equal(k256.Point.Identity()))
}

func TestPointK256Add(t *testing.T) {
	curve := K256()
	pt := curve.Point.Generator().(*PointK256)
	pt1 := pt.Add(pt).(*PointK256)
	pt2 := pt.Double().(*PointK256)
	pt3 := pt.Mul(curve.Scalar.New(2)).(*PointK256)

	require.True(t, pt1.Equal(pt2))
	require.True(t, pt1.Equal(pt3))
	require.True(t, pt.Add(pt).Equal(pt.Double()))
	require.True(t, pt.Mul(curve.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointK256Sub(t *testing.T) {
	curve := K256()
	g := curve.Point.Generator()
	pt := curve.Point.Generator().Mul(curve.Scalar.New(4))

	require.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	require.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointK256Mul(t *testing.T) {
	curve := K256()
	g := curve.Point.Generator()
	pt := curve.Point.Generator().Mul(curve.Scalar.New(4))
	require.True(t, g.Double().Double().Equal(pt))
}

func TestPointK256Serialize(t *testing.T) {
	curve := K256()
	ss := curve.Scalar.Random(testRng())

	g := curve.Point.Generator()
	ppt := g.Mul(ss).(*PointK256)

	require.Equal(t, ppt.ToAffineCompressed(), []byte{0x2, 0x1b, 0xa7, 0x7e, 0x98, 0xd6, 0xd8, 0x49, 0x45, 0xa4, 0x75, 0xd8, 0x6, 0xc0, 0x94, 0x5b, 0x8c, 0xf0, 0x5b, 0x8a, 0xb2, 0x76, 0xbb, 0x9f, 0x6e, 0x52, 0x9a, 0x11, 0x9c, 0x79, 0xdd, 0xf6, 0x5a})
	require.Equal(t, ppt.ToAffineUncompressed(), []byte{0x4, 0x1b, 0xa7, 0x7e, 0x98, 0xd6, 0xd8, 0x49, 0x45, 0xa4, 0x75, 0xd8, 0x6, 0xc0, 0x94, 0x5b, 0x8c, 0xf0, 0x5b, 0x8a, 0xb2, 0x76, 0xbb, 0x9f, 0x6e, 0x52, 0x9a, 0x11, 0x9c, 0x79, 0xdd, 0xf6, 0x5a, 0xb2, 0x96, 0x7c, 0x59, 0x4, 0xeb, 0x9a, 0xaa, 0xa9, 0x1d, 0x4d, 0xd0, 0x2d, 0xc6, 0x37, 0xee, 0x4a, 0x95, 0x51, 0x60, 0xab, 0xab, 0xf7, 0xdb, 0x30, 0x7d, 0x7d, 0x0, 0x68, 0x6c, 0xcf, 0xf6})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	require.NoError(t, err)
	require.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := curve.Scalar.Random(crand.Reader)
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

func TestPointK256Nil(t *testing.T) {
	k256 := K256()
	one := k256.Point.Generator()
	require.Nil(t, one.Add(nil))
	require.Nil(t, one.Sub(nil))
	require.Nil(t, one.Mul(nil))
	require.Nil(t, k256.Scalar.Random(nil))
	require.False(t, one.Equal(nil))
	_, err := k256.Scalar.SetBigInt(nil)
	require.Error(t, err)
}

func TestPointK256SumOfProducts(t *testing.T) {
	lhs := new(PointK256).Generator().Mul(new(ScalarK256).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointK256).Generator()
	}
	scalars := []Scalar{
		new(ScalarK256).New(8),
		new(ScalarK256).New(9),
		new(ScalarK256).New(10),
		new(ScalarK256).New(11),
		new(ScalarK256).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	require.NotNil(t, rhs)
	require.True(t, lhs.Equal(rhs))

	for j := 0; j < 25; j++ {
		lhs = lhs.Identity()
		for i := range points {
			points[i] = new(PointK256).Random(crand.Reader)
			scalars[i] = new(ScalarK256).Random(crand.Reader)
			lhs = lhs.Add(points[i].Mul(scalars[i]))
		}
		rhs = lhs.SumOfProducts(points, scalars)
		require.NotNil(t, rhs)
		require.True(t, lhs.Equal(rhs))
	}
}
