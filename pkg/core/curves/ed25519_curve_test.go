//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	"encoding/hex"
	ed "filippo.io/edwards25519"
	"github.com/coinbase/kryptology/internal"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestScalarEd25519Random(t *testing.T) {
	ed25519 := ED25519()
	sc := ed25519.Scalar.Random(testRng())
	s, ok := sc.(*ScalarEd25519)
	assert.True(t, ok)
	expected := toRSc("feaa6a9d6dda758da6145f7d411a3af9f8a120698e0093faa97085b384c3f00e")
	assert.Equal(t, s.value.Equal(expected), 1)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := ed25519.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarEd25519)
		assert.True(t, ok)
		assert.True(t, !sc.IsZero())
	}
}

func TestScalarEd25519Hash(t *testing.T) {
	var b [32]byte
	ed25519 := ED25519()
	sc := ed25519.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarEd25519)
	assert.True(t, ok)
	expected := toRSc("9d574494a02d72f5ff311cf0fb844d0fdd6103b17255274e029bdeed7207d409")
	assert.Equal(t, s.value.Equal(expected), 1)
}

func TestScalarEd25519Zero(t *testing.T) {
	ed25519 := ED25519()
	sc := ed25519.Scalar.Zero()
	assert.True(t, sc.IsZero())
	assert.True(t, sc.IsEven())
}

func TestScalarEd25519One(t *testing.T) {
	ed25519 := ED25519()
	sc := ed25519.Scalar.One()
	assert.True(t, sc.IsOne())
	assert.True(t, sc.IsOdd())
}

func TestScalarEd25519New(t *testing.T) {
	ed25519 := ED25519()
	three := ed25519.Scalar.New(3)
	assert.True(t, three.IsOdd())
	four := ed25519.Scalar.New(4)
	assert.True(t, four.IsEven())
	neg1 := ed25519.Scalar.New(-1)
	assert.True(t, neg1.IsEven())
	neg2 := ed25519.Scalar.New(-2)
	assert.True(t, neg2.IsOdd())
}

func TestScalarEd25519Square(t *testing.T) {
	ed25519 := ED25519()
	three := ed25519.Scalar.New(3)
	nine := ed25519.Scalar.New(9)
	assert.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarEd25519Cube(t *testing.T) {
	ed25519 := ED25519()
	three := ed25519.Scalar.New(3)
	twentySeven := ed25519.Scalar.New(27)
	assert.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarEd25519Double(t *testing.T) {
	ed25519 := ED25519()
	three := ed25519.Scalar.New(3)
	six := ed25519.Scalar.New(6)
	assert.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarEd25519Neg(t *testing.T) {
	ed25519 := ED25519()
	one := ed25519.Scalar.One()
	neg1 := ed25519.Scalar.New(-1)
	assert.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := ed25519.Scalar.New(333333)
	expected := ed25519.Scalar.New(-333333)
	assert.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarEd25519Invert(t *testing.T) {
	ed25519 := ED25519()
	nine := ed25519.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarEd25519)
	expected := toRSc("c3d9c4db0516043013b1e1ce8637dc92e3388ee3388ee3388ee3388ee3388e03")
	assert.Equal(t, sa.value.Equal(expected), 1)
}

func TestScalarEd25519Sqrt(t *testing.T) {
	ed25519 := ED25519()
	nine := ed25519.Scalar.New(9)
	actual, err := nine.Sqrt()
	sa, _ := actual.(*ScalarEd25519)
	expected := toRSc("03")
	assert.NoError(t, err)
	assert.Equal(t, sa.value.Equal(expected), 1)
}

func TestScalarEd25519Add(t *testing.T) {
	ed25519 := ED25519()
	nine := ed25519.Scalar.New(9)
	six := ed25519.Scalar.New(6)
	fifteen := nine.Add(six)
	assert.NotNil(t, fifteen)
	expected := ed25519.Scalar.New(15)
	assert.Equal(t, expected.Cmp(fifteen), 0)

	upper := ed25519.Scalar.New(-3)
	actual := upper.Add(nine)
	assert.NotNil(t, actual)
	assert.Equal(t, actual.Cmp(six), 0)
}

func TestScalarEd25519Sub(t *testing.T) {
	ed25519 := ED25519()
	nine := ed25519.Scalar.New(9)
	six := ed25519.Scalar.New(6)
	expected := ed25519.Scalar.New(-3)

	actual := six.Sub(nine)
	assert.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	assert.Equal(t, actual.Cmp(ed25519.Scalar.New(3)), 0)
}

func TestScalarEd25519Mul(t *testing.T) {
	ed25519 := ED25519()
	nine := ed25519.Scalar.New(9)
	six := ed25519.Scalar.New(6)
	actual := nine.Mul(six)
	assert.Equal(t, actual.Cmp(ed25519.Scalar.New(54)), 0)

	upper := ed25519.Scalar.New(-1)
	assert.Equal(t, upper.Mul(upper).Cmp(ed25519.Scalar.New(1)), 0)
}

func TestScalarEd25519Div(t *testing.T) {
	ed25519 := ED25519()
	nine := ed25519.Scalar.New(9)
	actual := nine.Div(nine)
	assert.Equal(t, actual.Cmp(ed25519.Scalar.New(1)), 0)
	assert.Equal(t, ed25519.Scalar.New(54).Div(nine).Cmp(ed25519.Scalar.New(6)), 0)
}

func TestScalarEd25519Serialize(t *testing.T) {
	ed25519 := ED25519()
	sc := ed25519.Scalar.New(255)
	sequence := sc.Bytes()
	assert.Equal(t, len(sequence), 32)
	assert.Equal(t, sequence, []byte{0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
	ret, err := ed25519.Scalar.SetBytes(sequence)
	assert.NoError(t, err)
	assert.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = ed25519.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		assert.Equal(t, len(sequence), 32)
		ret, err = ed25519.Scalar.SetBytes(sequence)
		assert.NoError(t, err)
		assert.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarEd25519Nil(t *testing.T) {
	ed25519 := ED25519()
	one := ed25519.Scalar.New(1)
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, one.Div(nil))
	assert.Nil(t, ed25519.Scalar.Random(nil))
	assert.Equal(t, one.Cmp(nil), -2)
	_, err := ed25519.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestPointEd25519Random(t *testing.T) {
	ed25519 := ED25519()
	sc := ed25519.Point.Random(testRng())
	s, ok := sc.(*PointEd25519)
	assert.True(t, ok)
	expected := toRPt("6011540c6231421a70ced5f577432531f198d318facfaad6e52cc42fba6e6fc5")
	assert.True(t, s.Equal(&PointEd25519{expected}))
	// Try 25 random values
	for i := 0; i < 25; i++ {
		sc := ed25519.Point.Random(crand.Reader)
		_, ok := sc.(*PointEd25519)
		assert.True(t, ok)
		assert.True(t, !sc.IsIdentity())
		pBytes := sc.ToAffineCompressed()
		_, err := ed.NewIdentityPoint().SetBytes(pBytes)
		assert.NoError(t, err)
	}
}

func TestPointEd25519Hash(t *testing.T) {
	var b [32]byte
	ed25519 := ED25519()
	sc := ed25519.Point.Hash(b[:])
	s, ok := sc.(*PointEd25519)
	assert.True(t, ok)
	expected := toRPt("b4d75c3bb03ca644ab6c6d2a955c911003d8cfa719415de93a6b85eeb0c8dd97")
	assert.True(t, s.Equal(&PointEd25519{expected}))

	// Fuzz test
	for i := 0; i < 25; i++ {
		_, _ = crand.Read(b[:])
		sc = ed25519.Point.Hash(b[:])
		assert.NotNil(t, sc)
	}
}

func TestPointEd25519Identity(t *testing.T) {
	ed25519 := ED25519()
	sc := ed25519.Point.Identity()
	assert.True(t, sc.IsIdentity())
	assert.Equal(t, sc.ToAffineCompressed(), []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointEd25519Generator(t *testing.T) {
	ed25519 := ED25519()
	sc := ed25519.Point.Generator()
	s, ok := sc.(*PointEd25519)
	assert.True(t, ok)
	assert.Equal(t, s.ToAffineCompressed(), []byte{0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66})
}

func TestPointEd25519Set(t *testing.T) {
	ed25519 := ED25519()
	iden, err := ed25519.Point.Set(big.NewInt(0), big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, iden.IsIdentity())
	xBytes, _ := hex.DecodeString("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921")
	yBytes, _ := hex.DecodeString("5866666666666666666666666666666666666666666666666666666666666666")
	x := new(big.Int).SetBytes(internal.ReverseScalarBytes(xBytes))
	y := new(big.Int).SetBytes(internal.ReverseScalarBytes(yBytes))
	newPoint, err := ed25519.Point.Set(x, y)
	assert.NoError(t, err)
	assert.NotEqualf(t, iden, newPoint, "after setting valid x and y, the point should NOT be identity point")

	emptyX := new(big.Int).SetBytes(internal.ReverseScalarBytes([]byte{}))
	identityPoint, err := ed25519.Point.Set(emptyX, y)
	assert.NoError(t, err)
	assert.Equalf(t, iden, identityPoint, "When x is empty, the point will be identity")
}

func TestPointEd25519Double(t *testing.T) {
	ed25519 := ED25519()
	g := ed25519.Point.Generator()
	g2 := g.Double()
	assert.True(t, g2.Equal(g.Mul(ed25519.Scalar.New(2))))
	i := ed25519.Point.Identity()
	assert.True(t, i.Double().Equal(i))
}

func TestPointEd25519Neg(t *testing.T) {
	ed25519 := ED25519()
	g := ed25519.Point.Generator().Neg()
	assert.True(t, g.Neg().Equal(ed25519.Point.Generator()))
	assert.True(t, ed25519.Point.Identity().Neg().Equal(ed25519.Point.Identity()))
}

func TestPointEd25519Add(t *testing.T) {
	ed25519 := ED25519()
	pt := ed25519.Point.Generator()
	assert.True(t, pt.Add(pt).Equal(pt.Double()))
	assert.True(t, pt.Mul(ed25519.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointEd25519Sub(t *testing.T) {
	ed25519 := ED25519()
	g := ed25519.Point.Generator()
	pt := ed25519.Point.Generator().Mul(ed25519.Scalar.New(4))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointEd25519Mul(t *testing.T) {
	ed25519 := ED25519()
	g := ed25519.Point.Generator()
	pt := ed25519.Point.Generator().Mul(ed25519.Scalar.New(4))
	assert.True(t, g.Double().Double().Equal(pt))
}

func TestPointEd25519Serialize(t *testing.T) {
	ed25519 := ED25519()
	ss := ed25519.Scalar.Random(testRng())
	g := ed25519.Point.Generator()

	ppt := g.Mul(ss)
	expectedC := []byte{0x7f, 0x5b, 0xa, 0xd9, 0xb8, 0xce, 0xb7, 0x7, 0x4c, 0x10, 0xc8, 0xb4, 0x27, 0xe8, 0xd2, 0x28, 0x50, 0x42, 0x6c, 0x0, 0x8a, 0x3, 0x72, 0x2b, 0x7c, 0x3c, 0x37, 0x6f, 0xf8, 0x8f, 0x42, 0x5d}
	expectedU := []byte{0x70, 0xad, 0x4, 0xa1, 0x6, 0x8, 0x9f, 0x47, 0xe1, 0xe8, 0x9b, 0x9c, 0x81, 0x5a, 0xfb, 0xb9, 0x85, 0x6a, 0x2c, 0xa, 0xbc, 0xff, 0xe, 0xc6, 0xa0, 0xb0, 0xac, 0x75, 0xc, 0xd8, 0x59, 0x53, 0x7f, 0x5b, 0xa, 0xd9, 0xb8, 0xce, 0xb7, 0x7, 0x4c, 0x10, 0xc8, 0xb4, 0x27, 0xe8, 0xd2, 0x28, 0x50, 0x42, 0x6c, 0x0, 0x8a, 0x3, 0x72, 0x2b, 0x7c, 0x3c, 0x37, 0x6f, 0xf8, 0x8f, 0x42, 0x5d}
	assert.Equal(t, ppt.ToAffineCompressed(), expectedC)
	assert.Equal(t, ppt.ToAffineUncompressed(), expectedU)
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := ed25519.Scalar.Random(crand.Reader)
		pt := g.Mul(s)
		cmprs := pt.ToAffineCompressed()
		assert.Equal(t, len(cmprs), 32)
		retC, err := pt.FromAffineCompressed(cmprs)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retC))

		un := pt.ToAffineUncompressed()
		assert.Equal(t, len(un), 64)
		retU, err := pt.FromAffineUncompressed(un)
		assert.NoError(t, err)
		assert.True(t, pt.Equal(retU))
	}
}

func TestPointEd25519Nil(t *testing.T) {
	ed25519 := ED25519()
	one := ed25519.Point.Generator()
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, ed25519.Scalar.Random(nil))
	assert.False(t, one.Equal(nil))
	_, err := ed25519.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestPointEd25519SumOfProducts(t *testing.T) {
	lhs := new(PointEd25519).Generator().Mul(new(ScalarEd25519).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointEd25519).Generator()
	}
	scalars := []Scalar{
		new(ScalarEd25519).New(8),
		new(ScalarEd25519).New(9),
		new(ScalarEd25519).New(10),
		new(ScalarEd25519).New(11),
		new(ScalarEd25519).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	assert.NotNil(t, rhs)
	assert.True(t, lhs.Equal(rhs))
}

func TestPointEd25519VarTimeDoubleScalarBaseMult(t *testing.T) {
	curve := ED25519()
	h := curve.Point.Hash([]byte("TestPointEd25519VarTimeDoubleScalarBaseMult"))
	a := curve.Scalar.New(23)
	b := curve.Scalar.New(77)
	H, ok := h.(*PointEd25519)
	assert.True(t, ok)
	rhs := H.VarTimeDoubleScalarBaseMult(a, H, b)
	lhs := h.Mul(a).Add(curve.Point.Generator().Mul(b))
	assert.True(t, lhs.Equal(rhs))
}

func toRSc(hx string) *ed.Scalar {
	e, _ := hex.DecodeString(hx)
	var data [32]byte
	copy(data[:], e)
	value, _ := new(ed.Scalar).SetCanonicalBytes(data[:])
	return value
}

func toRPt(hx string) *ed.Point {
	e, _ := hex.DecodeString(hx)
	var data [32]byte
	copy(data[:], e)
	pt, _ := new(PointEd25519).FromAffineCompressed(data[:])
	return pt.(*PointEd25519).value
}
