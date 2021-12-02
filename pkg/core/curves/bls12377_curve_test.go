//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	crand "crypto/rand"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestScalarBls12377G1Random(t *testing.T) {
	bls12377g1 := BLS12377G1()
	sc := bls12377g1.Scalar.Random(testRng())
	s, ok := sc.(*ScalarBls12377)
	assert.True(t, ok)
	expected, _ := new(big.Int).SetString("022a7db6fad5d5ff49108230818187de316bd0b3e5e96f190397bbb9f28e7a8b", 16)
	assert.Equal(t, s.value, expected)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12377g1.Scalar.Random(crand.Reader)
		_, ok := sc.(*ScalarBls12377)
		assert.True(t, ok)
		assert.True(t, !sc.IsZero())
	}
}

func TestScalarBls12377G1Hash(t *testing.T) {
	var b [32]byte
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.Hash(b[:])
	s, ok := sc.(*ScalarBls12377)
	assert.True(t, ok)
	expected, _ := new(big.Int).SetString("0c043edae82bf279180b9353139711c1fda5fa64a1f085b80760edaee8f0baca", 16)
	assert.Equal(t, s.value, expected)
}

func TestScalarBls12377G1Zero(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.Zero()
	assert.True(t, sc.IsZero())
	assert.True(t, sc.IsEven())
}

func TestScalarBls12377G1One(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.One()
	assert.True(t, sc.IsOne())
	assert.True(t, sc.IsOdd())
}

func TestScalarBls12377G1New(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	assert.True(t, three.IsOdd())
	four := bls12377G1.Scalar.New(4)
	assert.True(t, four.IsEven())
	neg1 := bls12377G1.Scalar.New(-1)
	assert.True(t, neg1.IsEven())
	neg2 := bls12377G1.Scalar.New(-2)
	assert.True(t, neg2.IsOdd())
}

func TestScalarBls12377G1Square(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	nine := bls12377G1.Scalar.New(9)
	assert.Equal(t, three.Square().Cmp(nine), 0)
}

func TestScalarBls12377G1Cube(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	twentySeven := bls12377G1.Scalar.New(27)
	assert.Equal(t, three.Cube().Cmp(twentySeven), 0)
}

func TestScalarBls12377G1Double(t *testing.T) {
	bls12377G1 := BLS12377G1()
	three := bls12377G1.Scalar.New(3)
	six := bls12377G1.Scalar.New(6)
	assert.Equal(t, three.Double().Cmp(six), 0)
}

func TestScalarBls12377G1Neg(t *testing.T) {
	bls12377G1 := BLS12377G1()
	one := bls12377G1.Scalar.One()
	neg1 := bls12377G1.Scalar.New(-1)
	assert.Equal(t, one.Neg().Cmp(neg1), 0)
	lotsOfThrees := bls12377G1.Scalar.New(333333)
	expected := bls12377G1.Scalar.New(-333333)
	assert.Equal(t, lotsOfThrees.Neg().Cmp(expected), 0)
}

func TestScalarBls12377G1Invert(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	actual, _ := nine.Invert()
	sa, _ := actual.(*ScalarBls12377)
	expected, err := bls12377G1.Scalar.SetBigInt(bhex("0a5f38510051b12ffcd5f1f46c1ef000c0095e8d9000000093d0d55555555556"))
	assert.NoError(t, err)
	assert.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarBls12377G1Sqrt(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	actual, err := nine.Sqrt()
	assert.NoError(t, err)
	sa, _ := actual.(*ScalarBls12377)
	expected, err := bls12377G1.Scalar.SetBigInt(bhex("12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a117ffffffffffe"))
	assert.NoError(t, err)
	assert.Equal(t, sa.Cmp(expected), 0)
}

func TestScalarBls12377G1Add(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	six := bls12377G1.Scalar.New(6)
	fifteen := nine.Add(six)
	assert.NotNil(t, fifteen)
	expected := bls12377G1.Scalar.New(15)
	assert.Equal(t, expected.Cmp(fifteen), 0)
	n := new(big.Int).Set(bls12377modulus)
	n.Sub(n, big.NewInt(3))

	upper, err := bls12377G1.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	actual := upper.Add(nine)
	assert.NotNil(t, actual)
	assert.Equal(t, actual.Cmp(six), 0)
}

func TestScalarBls12377G1Sub(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	six := bls12377G1.Scalar.New(6)
	n := new(big.Int).Set(bls12377modulus)
	n.Sub(n, big.NewInt(3))

	expected, err := bls12377G1.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	actual := six.Sub(nine)
	assert.Equal(t, expected.Cmp(actual), 0)

	actual = nine.Sub(six)
	assert.Equal(t, actual.Cmp(bls12377G1.Scalar.New(3)), 0)
}

func TestScalarBls12377G1Mul(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	six := bls12377G1.Scalar.New(6)
	actual := nine.Mul(six)
	assert.Equal(t, actual.Cmp(bls12377G1.Scalar.New(54)), 0)
	n := new(big.Int).Set(bls12377modulus)
	n.Sub(n, big.NewInt(1))
	upper, err := bls12377G1.Scalar.SetBigInt(n)
	assert.NoError(t, err)
	assert.Equal(t, upper.Mul(upper).Cmp(bls12377G1.Scalar.New(1)), 0)
}

func TestScalarBls12377G1Div(t *testing.T) {
	bls12377G1 := BLS12377G1()
	nine := bls12377G1.Scalar.New(9)
	actual := nine.Div(nine)
	assert.Equal(t, actual.Cmp(bls12377G1.Scalar.New(1)), 0)
	assert.Equal(t, bls12377G1.Scalar.New(54).Div(nine).Cmp(bls12377G1.Scalar.New(6)), 0)
}

func TestScalarBls12377G1Serialize(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Scalar.New(255)
	sequence := sc.Bytes()
	assert.Equal(t, len(sequence), 32)
	assert.Equal(t, sequence, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff})
	ret, err := bls12377G1.Scalar.SetBytes(sequence)
	assert.NoError(t, err)
	assert.Equal(t, ret.Cmp(sc), 0)

	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc = bls12377G1.Scalar.Random(crand.Reader)
		sequence = sc.Bytes()
		assert.Equal(t, len(sequence), 32)
		ret, err = bls12377G1.Scalar.SetBytes(sequence)
		assert.NoError(t, err)
		assert.Equal(t, ret.Cmp(sc), 0)
	}
}

func TestScalarBls12377G1Nil(t *testing.T) {
	bls12377G1 := BLS12377G1()
	one := bls12377G1.Scalar.New(1)
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, one.Div(nil))
	assert.Nil(t, bls12377G1.Scalar.Random(nil))
	assert.Equal(t, one.Cmp(nil), -2)
	_, err := bls12377G1.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestScalarBls12377Point(t *testing.T) {
	bls12377G1 := BLS12377G1()
	_, ok := bls12377G1.Scalar.Point().(*PointBls12377G1)
	assert.True(t, ok)
	bls12377G2 := BLS12377G2()
	_, ok = bls12377G2.Scalar.Point().(*PointBls12377G2)
	assert.True(t, ok)
}

func TestPointBls12377G2Random(t *testing.T) {
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Random(testRng())
	s, ok := sc.(*PointBls12377G2)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("2deeb99988cc46605a5e8eeb50b2c52fc4a12b4537aa8a149431ca85bac2017a32d2a3bf8411d5145bdf587f162a1b01a106e89ebf3210c0926ba07681cd84fc8ae2409b396b24730a8b851d05ba3293b82ae341c472d626c1f55da16ba46d", 16)
	expectedY, _ := new(big.Int).SetString("b17be752bc4a8ff05824fcf974d232cebe07ee333ce879bf8c7b88ce18813cb190e8a45eddbd7cc5a4b68993ed17770094ab97b85b70b0b80e89c854336b85e46c7259070fb6606b03bcab12d96438f9a79353fafe11733aed51bfa4e798b8", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12377G2.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls12377G2)
		assert.True(t, ok)
		assert.True(t, !sc.IsIdentity())
	}
}

func TestPointBls12377G2Hash(t *testing.T) {
	var b [32]byte
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Hash(b[:])
	s, ok := sc.(*PointBls12377G2)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("014eec1848d84be62f3a5778353ea6c2b0db859508bc40ff2c1387f0a4b2a167fedbe6b10f946f33c600623d7b96dc8200ef8b67c1e07c4dc522f25deb617ad8251199d235da8bc7700332c8416aa204f81e6bebd914e46acea095d3083b7723", 16)
	expectedY, _ := new(big.Int).SetString("015c17fb5e37ce1284fa5f10cca9a55be5a5e4d821649294ab820a6f044f55337665df04a940ee7f5d937aff69196b010168d9090eb791d4b21752622f1fd5fb0f4c44bfd83e2cf6d332b02343999fac3de660ca84aff40b428f25b5378fe648", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
}

func TestPointBls12377G2Identity(t *testing.T) {
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Identity()
	assert.True(t, sc.IsIdentity())
	assert.Equal(t, sc.ToAffineCompressed(), []byte{0xc0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})
}

func TestPointBls12377G2Generator(t *testing.T) {
	bls12377G2 := BLS12377G2()
	sc := bls12377G2.Point.Generator()
	s, ok := sc.(*PointBls12377G2)
	assert.True(t, ok)
	_, _, _, g2Aff := bls12377.Generators()
	assert.True(t, s.value.Equal(&g2Aff))
}

func TestPointBls12377G2Set(t *testing.T) {
	bls12377G2 := BLS12377G2()
	iden, err := bls12377G2.Point.Set(big.NewInt(0), big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, iden.IsIdentity())
	_, _, _, g2Aff := bls12377.Generators()
	generator := g2Aff.Bytes()
	_, err = bls12377G2.Point.Set(new(big.Int).SetBytes(generator[:96]), new(big.Int).SetBytes(generator[96:]))
	assert.NoError(t, err)
}

func TestPointBls12377G2Double(t *testing.T) {
	bls12377G2 := BLS12377G2()
	g := bls12377G2.Point.Generator()
	gg2 := g.Double()
	assert.True(t, gg2.Equal(g.Mul(bls12377G2.Scalar.New(2))))
	i := bls12377G2.Point.Identity()
	assert.True(t, i.Double().Equal(i))
}

func TestPointBls12377G2Neg(t *testing.T) {
	bls12377G2 := BLS12377G1()
	g := bls12377G2.Point.Generator().Neg()
	assert.True(t, g.Neg().Equal(bls12377G2.Point.Generator()))
	assert.True(t, bls12377G2.Point.Identity().Neg().Equal(bls12377G2.Point.Identity()))
}

func TestPointBls12377G2Add(t *testing.T) {
	bls12377G2 := BLS12377G2()
	pt := bls12377G2.Point.Generator()
	assert.True(t, pt.Add(pt).Equal(pt.Double()))
	assert.True(t, pt.Mul(bls12377G2.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12377G2Sub(t *testing.T) {
	bls12377G2 := BLS12377G2()
	g := bls12377G2.Point.Generator()
	pt := bls12377G2.Point.Generator().Mul(bls12377G2.Scalar.New(4))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls12377G2Mul(t *testing.T) {
	bls12377G2 := BLS12377G2()
	g := bls12377G2.Point.Generator()
	pt := bls12377G2.Point.Generator().Mul(bls12377G2.Scalar.New(4))
	assert.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12377G2Serialize(t *testing.T) {
	bls12377G2 := BLS12377G2()
	ss := bls12377G2.Scalar.Random(testRng())
	g := bls12377G2.Point.Generator()

	ppt := g.Mul(ss)
	assert.Equal(t, ppt.ToAffineCompressed(), []byte{0x81, 0x88, 0xf4, 0x32, 0xec, 0x60, 0x72, 0xd3, 0x76, 0x77, 0x86, 0xcd, 0x44, 0xce, 0x91, 0x5a, 0x3a, 0xb5, 0x13, 0xe2, 0x81, 0x10, 0x41, 0xa1, 0x39, 0x1e, 0xe2, 0x8a, 0x5f, 0x5f, 0xf1, 0x2e, 0x72, 0xab, 0xc5, 0x62, 0x5c, 0x99, 0x56, 0x5d, 0xd4, 0x33, 0x9a, 0x61, 0x63, 0xd4, 0x8e, 0x7c, 0x0, 0xec, 0x46, 0xb, 0xc4, 0x22, 0xd9, 0xe0, 0x74, 0xe6, 0x79, 0x7b, 0x55, 0x8d, 0x8f, 0x9b, 0xf7, 0x59, 0x65, 0x10, 0x97, 0xe3, 0x12, 0x18, 0xd3, 0x76, 0x3, 0x58, 0x87, 0xc7, 0x82, 0x4c, 0x42, 0x80, 0xa2, 0xa, 0x3d, 0x66, 0xfe, 0xb6, 0xed, 0xd9, 0x38, 0x45, 0x5, 0xbe, 0x40, 0x32})
	assert.Equal(t, ppt.ToAffineUncompressed(), []byte{0x1, 0x88, 0xf4, 0x32, 0xec, 0x60, 0x72, 0xd3, 0x76, 0x77, 0x86, 0xcd, 0x44, 0xce, 0x91, 0x5a, 0x3a, 0xb5, 0x13, 0xe2, 0x81, 0x10, 0x41, 0xa1, 0x39, 0x1e, 0xe2, 0x8a, 0x5f, 0x5f, 0xf1, 0x2e, 0x72, 0xab, 0xc5, 0x62, 0x5c, 0x99, 0x56, 0x5d, 0xd4, 0x33, 0x9a, 0x61, 0x63, 0xd4, 0x8e, 0x7c, 0x0, 0xec, 0x46, 0xb, 0xc4, 0x22, 0xd9, 0xe0, 0x74, 0xe6, 0x79, 0x7b, 0x55, 0x8d, 0x8f, 0x9b, 0xf7, 0x59, 0x65, 0x10, 0x97, 0xe3, 0x12, 0x18, 0xd3, 0x76, 0x3, 0x58, 0x87, 0xc7, 0x82, 0x4c, 0x42, 0x80, 0xa2, 0xa, 0x3d, 0x66, 0xfe, 0xb6, 0xed, 0xd9, 0x38, 0x45, 0x5, 0xbe, 0x40, 0x32, 0x0, 0xd, 0x69, 0x94, 0x48, 0x5e, 0x3, 0xd4, 0x51, 0x2a, 0xf6, 0xa, 0xf0, 0x4b, 0xd8, 0x42, 0xc4, 0xc3, 0x66, 0xb8, 0x77, 0x15, 0xaf, 0x8b, 0xee, 0x68, 0xc3, 0xfe, 0x16, 0x4d, 0xd0, 0x5b, 0x97, 0xc, 0x16, 0x6c, 0xfe, 0x9e, 0xc, 0xe0, 0xe3, 0x15, 0x33, 0x6c, 0x81, 0xc1, 0x93, 0x1e, 0x1, 0x13, 0xfc, 0x17, 0xf2, 0x9c, 0xe0, 0x61, 0xe4, 0x58, 0x3a, 0xba, 0xed, 0xd9, 0x2f, 0x54, 0xdd, 0xc3, 0x7f, 0xdf, 0xc0, 0x31, 0x89, 0x1f, 0xf3, 0xcf, 0x9c, 0xac, 0x7c, 0xd, 0x91, 0x8a, 0x84, 0xf8, 0xab, 0xcc, 0x77, 0x55, 0xb6, 0x72, 0xf4, 0xb0, 0x13, 0x45, 0xbb, 0x3d, 0x44, 0xfe})

	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls12377G2.Scalar.Random(crand.Reader)
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

func TestPointBls12377G2Nil(t *testing.T) {
	bls12377G2 := BLS12377G2()
	one := bls12377G2.Point.Generator()
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, bls12377G2.Scalar.Random(nil))
	assert.False(t, one.Equal(nil))
	_, err := bls12377G2.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestPointBls12377G1Random(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Random(testRng())
	s, ok := sc.(*PointBls12377G1)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("facd83174df271a2dbd7d84f02f4d1b6a61850a926e7ec5ca34e558378feb146231e5e105fa27310843db23a49ca53", 16)
	expectedY, _ := new(big.Int).SetString("4fa90bd4c90a2d4afd01bf0f561ab112bc13bb7c0faa87a2324febab2c3fa1ff47b2ed1dd9e38b1c660dd6d2ec0a7b", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
	// Try 10 random values
	for i := 0; i < 10; i++ {
		sc := bls12377G1.Point.Random(crand.Reader)
		_, ok := sc.(*PointBls12377G1)
		assert.True(t, ok)
		assert.True(t, !sc.IsIdentity())
	}
}

func TestPointBls12377G1Hash(t *testing.T) {
	var b [32]byte
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Hash(b[:])
	s, ok := sc.(*PointBls12377G1)
	assert.True(t, ok)
	expectedX, _ := new(big.Int).SetString("8c1f4dd215430f2a1c01e1f50eded8de37033e5b70b9987c93547e0b8ec87ca918039d41e5e634773e1bcbe1e2d836", 16)
	expectedY, _ := new(big.Int).SetString("552b0bde9c7b051118a5619cf409cd9d2b25a1ebb5e35b7c7bd031f8c15f1d08979e634d2acd1b7be4ccb43a064393", 16)
	assert.Equal(t, s.X(), expectedX)
	assert.Equal(t, s.Y(), expectedY)
}

func TestPointBls12377G1Identity(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Identity()
	assert.True(t, sc.IsIdentity())
	assert.Equal(t, sc.ToAffineCompressed(), []byte{0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
}

func TestPointBls12377G1Generator(t *testing.T) {
	bls12377G1 := BLS12377G1()
	sc := bls12377G1.Point.Generator()
	s, ok := sc.(*PointBls12377G1)
	assert.True(t, ok)
	_, _, g1Aff, _ := bls12377.Generators()
	assert.True(t, s.value.Equal(&g1Aff))
}

func TestPointBls12377G1Set(t *testing.T) {
	bls12377G1 := BLS12377G1()
	iden, err := bls12377G1.Point.Set(big.NewInt(0), big.NewInt(0))
	assert.NoError(t, err)
	assert.True(t, iden.IsIdentity())
	_, _, g1Aff, _ := bls12377.Generators()
	generator := g1Aff.Bytes()
	_, err = bls12377G1.Point.Set(new(big.Int).SetBytes(generator[:48]), new(big.Int).SetBytes(generator[48:]))
	assert.NoError(t, err)
}

func TestPointBls12377G1Double(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator()
	g2 := g.Double()
	assert.True(t, g2.Equal(g.Mul(bls12377G1.Scalar.New(2))))
	i := bls12377G1.Point.Identity()
	assert.True(t, i.Double().Equal(i))
}

func TestPointBls12377G1Neg(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator().Neg()
	assert.True(t, g.Neg().Equal(bls12377G1.Point.Generator()))
	assert.True(t, bls12377G1.Point.Identity().Neg().Equal(bls12377G1.Point.Identity()))
}

func TestPointBls12377G1Add(t *testing.T) {
	bls12377G1 := BLS12377G1()
	pt := bls12377G1.Point.Generator()
	assert.True(t, pt.Add(pt).Equal(pt.Double()))
	assert.True(t, pt.Mul(bls12377G1.Scalar.New(3)).Equal(pt.Add(pt).Add(pt)))
}

func TestPointBls12377G1Sub(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator()
	pt := bls12377G1.Point.Generator().Mul(bls12377G1.Scalar.New(4))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Equal(g))
	assert.True(t, pt.Sub(g).Sub(g).Sub(g).Sub(g).IsIdentity())
}

func TestPointBls12377G1Mul(t *testing.T) {
	bls12377G1 := BLS12377G1()
	g := bls12377G1.Point.Generator()
	pt := bls12377G1.Point.Generator().Mul(bls12377G1.Scalar.New(4))
	assert.True(t, g.Double().Double().Equal(pt))
}

func TestPointBls12377G1Serialize(t *testing.T) {
	bls12377G1 := BLS12377G1()
	ss := bls12377G1.Scalar.Random(testRng())
	g := bls12377G1.Point.Generator()

	ppt := g.Mul(ss)
	assert.Equal(t, ppt.ToAffineCompressed(), []byte{0xa0, 0xd0, 0xae, 0xea, 0xaa, 0xf1, 0xf6, 0x0, 0x59, 0x39, 0x33, 0x3c, 0x60, 0x16, 0xaf, 0x68, 0x86, 0x2d, 0x3a, 0xc1, 0x73, 0x24, 0xdd, 0x2, 0xb6, 0x49, 0xde, 0xf, 0xe7, 0x42, 0xe8, 0x10, 0xf, 0xab, 0xd1, 0x63, 0xed, 0x13, 0xda, 0x0, 0x69, 0x1b, 0x20, 0x7d, 0xcd, 0x71, 0x7, 0xef})
	assert.Equal(t, ppt.ToAffineUncompressed(), []byte{0x0, 0xd0, 0xae, 0xea, 0xaa, 0xf1, 0xf6, 0x0, 0x59, 0x39, 0x33, 0x3c, 0x60, 0x16, 0xaf, 0x68, 0x86, 0x2d, 0x3a, 0xc1, 0x73, 0x24, 0xdd, 0x2, 0xb6, 0x49, 0xde, 0xf, 0xe7, 0x42, 0xe8, 0x10, 0xf, 0xab, 0xd1, 0x63, 0xed, 0x13, 0xda, 0x0, 0x69, 0x1b, 0x20, 0x7d, 0xcd, 0x71, 0x7, 0xef, 0x1, 0x78, 0x3f, 0xbd, 0xd4, 0xbd, 0x7c, 0xf5, 0x7a, 0xfd, 0x33, 0x45, 0x7, 0x39, 0xf2, 0xb7, 0x10, 0x4c, 0x1e, 0xc5, 0x2b, 0x93, 0x4, 0x67, 0x54, 0x88, 0x8b, 0x57, 0x69, 0xf, 0x74, 0x40, 0xf4, 0x58, 0x5b, 0xd7, 0x76, 0x63, 0x58, 0xd9, 0x7b, 0x6d, 0x46, 0x8e, 0x50, 0x89, 0xc4, 0x7d})
	retP, err := ppt.FromAffineCompressed(ppt.ToAffineCompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))
	retP, err = ppt.FromAffineUncompressed(ppt.ToAffineUncompressed())
	assert.NoError(t, err)
	assert.True(t, ppt.Equal(retP))

	// smoke test
	for i := 0; i < 25; i++ {
		s := bls12377G1.Scalar.Random(crand.Reader)
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

func TestPointBls12377G1Nil(t *testing.T) {
	bls12377G1 := BLS12377G1()
	one := bls12377G1.Point.Generator()
	assert.Nil(t, one.Add(nil))
	assert.Nil(t, one.Sub(nil))
	assert.Nil(t, one.Mul(nil))
	assert.Nil(t, bls12377G1.Scalar.Random(nil))
	assert.False(t, one.Equal(nil))
	_, err := bls12377G1.Scalar.SetBigInt(nil)
	assert.Error(t, err)
}

func TestPointBls12377G1SumOfProducts(t *testing.T) {
	lhs := new(PointBls12377G1).Generator().Mul(new(ScalarBls12377).New(50))
	points := make([]Point, 5)
	for i := range points {
		points[i] = new(PointBls12377G1).Generator()
	}
	scalars := []Scalar{
		new(ScalarBls12377).New(8),
		new(ScalarBls12377).New(9),
		new(ScalarBls12377).New(10),
		new(ScalarBls12377).New(11),
		new(ScalarBls12377).New(12),
	}
	rhs := lhs.SumOfProducts(points, scalars)
	assert.NotNil(t, rhs)
	assert.True(t, lhs.Equal(rhs))
}
