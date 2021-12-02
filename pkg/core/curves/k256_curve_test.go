//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
	"math/big"
	"sync"
	"testing"
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
	k256 := K256()
	sc := k256.Scalar.Random(testRng())
	s, ok := sc.(*ScalarK256)
	assert.True(t, ok)
	expected, _ := new(big.Int).SetString("2f71aaec5e14d747c72e46cdcaffffe6f542f38b3f0925469ceb24ac1c65885d", 16)
	assert.Equal(t, s.value, expected)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := k256.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarK256)
		assert.True(t, ok)
		assert.True(t, !sc.IsZero())
	}
}

func TestScalarK256Hash(t *testing.T) {
	var b [32]byte
	k256 := K256()
	sc := k256.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarK256)
	assert.True(t, ok)
	expected, _ := new(big.Int).SetString("e5cb3500b809a8202de0834a805068bc21bde09bd6367815e7523a37adf8f52e", 16)
	assert.Equal(t, s.value, expected)
}

func TestScalarK256Zero(t *testing.T) {
	k256 := K256()
	sc := k256.Scalar.Zero()
	assert.True(t, sc.IsZero())
	assert.True(t, sc.IsEven())
}

func TestScalarK256One(t *testing.T) {
	k256 := K256()
	sc := k256.Scalar.One()
	assert.True(t, sc.IsOne())
	assert.True(t, sc.IsOdd())
}

func TestScalarK256New(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	assert.True(t, three.IsOdd())
	four := k256.Scalar.New(4)
	assert.True(t, four.IsEven())
	neg1 := k256.Scalar.New(-1)
	assert.True(t, neg1.IsEven())
	neg2 := k256.Scalar.New(-2)
	assert.True(t, neg2.IsOdd())
}

func TestScalarK256Square(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	nine := k256.Scalar.New(9)
	assert.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarK256Cube(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	twentySeven := k256.Scalar.New(27)
	assert.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarK256Double(t *testing.T) {
	k256 := K256()
	three := k256.Scalar.New(3)
	six := k256.Scalar.New(6)
	assert.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarK256Neg(t *testing.T) {
	k256 := K256()
	one := k256.Scalar.One()
	neg1 := k256.Scalar.New(-1)
	assert.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := k256.Scalar.New(333333)
	expected := k256.Scalar.New(-333333)
	assert.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarK256Invert(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarK256)
	bn, _ := new(big.Int).SetString("8e38e38e38e38e38e38e38e38e38e38d842841d57dd303af6a9150f8e5737996", 16)
	expected, err := k256.Scalar.SetBigInt(bn)
	assert.NoError(t, err)
	assert.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarK256Sqrt(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*ScalarK256)
	expected := k256.Scalar.New(3)
	assert.NoError(t, err)
	assert.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarK256Add(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	six := k256.Scalar.New(6)
	fifteen := nine.Add(six)
	assert.NotNil(t, fifteen)
	expected := k256.Scalar.New(15)
	assert.Equal(t, expected.Cmp(fifteen), 0)
	n := new(big.Int).Set(btcec.S256().N)
	n.Sub(n, big.NewInt(3))

	upper, err := k256.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	actual := upper.Add(nine)
	assert.NotNil(t, actual)
	assert.Equal(t, actual.Cmp(six), 0)
}

func TestScalarK256Sub(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	six := k256.Scalar.New(6)
	n := new(big.Int).Set(btcec.S256().N)
	n.Sub(n, big.NewInt(3))

	expected, err := k256.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	actual := six.Sub(nine)
	assert.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	assert.Equal(t, actual.Cmp(k256.Scalar.New(3)), 0)
}

func TestScalarK256Mul(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	six := k256.Scalar.New(6)
	actual := nine.Mul(six)
	assert.Equal(t, actual.Cmp(k256.Scalar.New(54)), 0)
	n := new(big.Int).Set(btcec.S256().N)
	n.Sub(n, big.NewInt(1))
	upper, err := k256.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	assert.Equal(t, upper.Mul(upper).Cmp(k256.Scalar.New(1)), 0)
}

func TestScalarK256Div(t *testing.T) {
	k256 := K256()
	nine := k256.Scalar.New(9)
	actual := nine.Div(nine)
	assert.Equal(t, actual.Cmp(k256.Scalar.New(1)), 0)
	assert.Equal(t, k256.Scalar.New(54).Div(nine).Cmp(k256.Scalar.New(6)), 0)
}

func TestScalarK256Serialize(t *testing.T) {
	k256 := K256()
	sc := k256.Scalar.New(255)
	sequence := sc.Bytes()
	assert.Equal(t, len(sequence), 32)
	assert.Equal(t, sequence, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	ret, err := k256.Scalar.SetBytes(sequence)
	assert.NoError(t, err)
	assert.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = k256.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		assert.Equal(t, len(sequence), 32)
		ret, err = k256.Scalar.SetBytes(sequence)
		assert.NoError(t, err)
		assert.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarK256Nil(t *testing.T) {
	k256 := K256()
	one := k256.Scalar.New(1)
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, one.Div(nil))
	assert.Nil(t, k256.Scalar.Random(nil))
	assert.Equal(t, one.Cmp(nil), -2)
	_, err := k256.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestPointK256Random(t *testing.T) {
	k256 := K256()
	sc := k256.Point.Random(testRng())
	s, ok := sc.(*PointK256)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("c6e18a1d7cf834462675b31581639a18e14fd0f73f8dfd5fe2993f88f6fbe008", 16)
	expectedY, _ := new(big.Int).SetString("b65fab3243c5d07cef005d7fb335ebe8019efd954e95e68c86ef9b3bd7bccd36", 16)
	assert.Equal(t, s.x, expectedX)
	assert.Equal(t, s.y, expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := k256.Point.Random(crand.Reader)
		_, ok := sc.(*PointK256)
		assert.True(t, ok)
		assert.True(t, !sc.IsIdentity())
	}
}

func TestPointK256Hash(t *testing.T) {
	var b [32]byte
	k256 := K256()
	sc := k256.Point.Hash(b[:])
	s, ok := sc.(*PointK256)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("95d0ad42f68ddb5a808469dd75fa866890dcc7d039844e0e2d58a6d25bd9a66b", 16)
	expectedY, _ := new(big.Int).SetString("f37c564d05168dab4413caacdb8e3426143fc5fb24a470ccd8a51856c11d163c", 16)
	assert.Equal(t, s.x, expectedX)
	assert.Equal(t, s.y, expectedY)
}

func TestPointK256Identity(t *testing.T) {
	k256 := K256()
	sc := k256.Point.Identity()
	assert.True(t, sc.IsIdentity())
	assert.Equal(t, sc.ToAffineCompressed(), []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointK256Generator(t *testing.T) {
	k256 := K256()
	sc := k256.Point.Generator()
	s, ok := sc.(*PointK256)
	assert.True(t, ok)
	assert.Equal(t, s.x.Cmp(btcec.S256().Gx), 0)
	assert.Equal(t, s.y.Cmp(btcec.S256().Gy), 0)
}

func TestPointK256Set(t *testing.T) {
	k256 := K256()
	iden, err := k256.Point.Set(big.NewInt(0), big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, iden.IsIdentity())
	_, err = k256.Point.Set(btcec.S256().Gx, btcec.S256().Gy)
	assert.NoError(t, err)
}

func TestPointK256Double(t *testing.T) {
	k256 := K256()
	g := k256.Point.Generator()
	g2 := g.Double()
	assert.True(t, g2.Equal(g.Mul(k256.Scalar.New(2))))
	i := k256.Point.Identity()
	assert.True(t, i.Double().Equal(i))
}

func TestPointK256Neg(t *testing.T) {
	k256 := K256()
	g := k256.Point.Generator().Neg()
	assert.True(t, g.Neg().Equal(k256.Point.Generator()))
	assert.True(t, k256.Point.Identity().Neg().Equal(k256.Point.Identity()))
}

func TestPointK256Add(t *testing.T) {
	k256 := K256()
	pt := k256.Point.Generator()
	assert.True(t, pt.Add(pt).Equal(pt.Double()))
	assert.True(t, pt.Mul(k256.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointK256Sub(t *testing.T) {
	k256 := K256()
	g := k256.Point.Generator()
	pt := k256.Point.Generator().Mul(k256.Scalar.New(4))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointK256Mul(t *testing.T) {
	k256 := K256()
	g := k256.Point.Generator()
	pt := k256.Point.Generator().Mul(k256.Scalar.New(4))
	assert.True(t, g.Double().Double().Equal(pt))
}

func TestPointK256Serialize(t *testing.T) {
	k256 := K256()
	ss := k256.Scalar.Random(testRng())
	g := k256.Point.Generator()

	ppt := g.Mul(ss)
	assert.Equal(t, ppt.ToAffineCompressed(), []byte{0x2, 0x1b, 0xa7, 0x7e, 0x98, 0xd6, 0xd8, 0x49, 0x45, 0xa4, 0x75, 0xd8, 0x6, 0xc0, 0x94, 0x5b, 0x8c, 0xf0, 0x5b, 0x8a, 0xb2, 0x76, 0xbb, 0x9f, 0x6e, 0x52, 0x9a, 0x11, 0x9c, 0x79, 0xdd, 0xf6, 0x5a})
	assert.Equal(t, ppt.ToAffineUncompressed(), []byte{0x4, 0x1b, 0xa7, 0x7e, 0x98, 0xd6, 0xd8, 0x49, 0x45, 0xa4, 0x75, 0xd8, 0x6, 0xc0, 0x94, 0x5b, 0x8c, 0xf0, 0x5b, 0x8a, 0xb2, 0x76, 0xbb, 0x9f, 0x6e, 0x52, 0x9a, 0x11, 0x9c, 0x79, 0xdd, 0xf6, 0x5a, 0xb2, 0x96, 0x7c, 0x59, 0x4, 0xeb, 0x9a, 0xaa, 0xa9, 0x1d, 0x4d, 0xd0, 0x2d, 0xc6, 0x37, 0xee, 0x4a, 0x95, 0x51, 0x60, 0xab, 0xab, 0xf7, 0xdb, 0x30, 0x7d, 0x7d, 0x0, 0x68, 0x6c, 0xcf, 0xf6})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := k256.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		assert.Equal(t, len(cmprs), 33)
		retC, err := pt.FromAffineCompressed(cmprs)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		assert.Equal(t, len(un), 65)
		retU, err := pt.FromAffineUncompressed(un)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retU))
	}
}

func TestPointK256Nil(t *testing.T) {
	k256 := K256()
	one := k256.Point.Generator()
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, k256.Scalar.Random(nil))
	assert.False(t, one.Equal(nil))
	_, err := k256.Scalar.SetBigInt(nil)
	assert.Error(t, err)
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
	assert.NotNil(t, rhs)
	assert.True(t, lhs.Equal(rhs))
}
