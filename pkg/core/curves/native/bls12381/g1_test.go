package bls12381

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
)

func TestG1IsOnCurve(t *testing.T) {
	require.Equal(t, 1, new(G1).Identity().IsOnCurve())
	require.Equal(t, 1, new(G1).Generator().IsOnCurve())

	z := fp{
		0xba7afa1f9a6fe250,
		0xfa0f5b595eafe731,
		0x3bdc477694c306e7,
		0x2149be4b3949fa24,
		0x64aa6e0649b2078c,
		0x12b108ac33643c3e,
	}

	gen := new(G1).Generator()
	test := G1{
		x: *(gen.x.Mul(&gen.x, &z)),
		y: *(gen.y.Mul(&gen.y, &z)),
		z: z,
	}
	require.Equal(t, 1, test.IsOnCurve())
	test.x = z
	require.Equal(t, 0, test.IsOnCurve())
}

func TestG1Equality(t *testing.T) {
	a := new(G1).Generator()
	b := new(G1).Identity()

	require.Equal(t, 1, a.Equal(a))
	require.Equal(t, 1, b.Equal(b))
	require.Equal(t, 0, a.Equal(b))
	require.Equal(t, 0, b.Equal(a))

	z := fp{
		0xba7afa1f9a6fe250,
		0xfa0f5b595eafe731,
		0x3bdc477694c306e7,
		0x2149be4b3949fa24,
		0x64aa6e0649b2078c,
		0x12b108ac33643c3e,
	}

	c := G1{}
	c.x.Mul(&a.x, &z)
	c.y.Mul(&a.y, &z)
	c.z.Set(&z)

	require.Equal(t, 1, c.IsOnCurve())

	require.Equal(t, 1, a.Equal(&c))
	require.Equal(t, 0, b.Equal(&c))

	c.y.Neg(&c.y)
	require.Equal(t, 1, c.IsOnCurve())

	require.Equal(t, 0, a.Equal(&c))

	c.y.Neg(&c.y)
	c.x.Set(&z)
	require.Equal(t, 0, c.IsOnCurve())
}

func TestG1Double(t *testing.T) {
	t0 := new(G1).Identity()
	t0.Double(t0)
	require.Equal(t, 1, t0.IsIdentity())
	require.Equal(t, 1, t0.IsOnCurve())

	t0.Double(t0.Generator())
	require.Equal(t, 0, t0.IsIdentity())
	require.Equal(t, 1, t0.IsOnCurve())
	e := G1{
		x: fp{
			0x53e978ce58a9ba3c,
			0x3ea0583c4f3d65f9,
			0x4d20bb47f0012960,
			0xa54c664ae5b2b5d9,
			0x26b552a39d7eb21f,
			0x0008895d26e68785,
		},
		y: fp{
			0x70110b3298293940,
			0xda33c5393f1f6afc,
			0xb86edfd16a5aa785,
			0xaec6d1c9e7b1c895,
			0x25cfc2b522d11720,
			0x06361c83f8d09b15,
		},
		z: r,
	}

	require.Equal(t, 1, e.Equal(t0))
}

func TestG1Add(t *testing.T) {
	g := new(G1).Generator()
	a := new(G1).Identity()
	b := new(G1).Identity()
	c := new(G1).Add(a, b)
	require.Equal(t, 1, c.IsIdentity())
	require.Equal(t, 1, c.IsOnCurve())

	b.Generator()
	z := fp{
		0xba7afa1f9a6fe250,
		0xfa0f5b595eafe731,
		0x3bdc477694c306e7,
		0x2149be4b3949fa24,
		0x64aa6e0649b2078c,
		0x12b108ac33643c3e,
	}
	b.x.Mul(&b.x, &z)
	b.y.Mul(&b.y, &z)
	b.z.Set(&z)
	c.Add(a, b)
	require.Equal(t, 0, c.IsIdentity())
	require.Equal(t, 1, g.Equal(c))

	a.Generator()
	a.Double(a)
	a.Double(a)
	b.Generator()
	b.Double(b)
	c.Add(a, b)
	d := new(G1).Generator()
	for i := 0; i < 5; i++ {
		d.Add(d, g)
	}
	require.Equal(t, 0, c.IsIdentity())
	require.Equal(t, 1, c.IsOnCurve())
	require.Equal(t, 0, d.IsIdentity())
	require.Equal(t, 1, d.IsOnCurve())
	require.Equal(t, 1, c.Equal(d))

	beta := fp{
		0xcd03c9e48671f071,
		0x5dab22461fcda5d2,
		0x587042afd3851b95,
		0x8eb60ebe01bacb9e,
		0x03f97d6e83d050d2,
		0x18f0206554638741,
	}
	beta.Square(&beta)
	a.Generator()
	a.Double(a)
	a.Double(a)
	b.x.Mul(&a.x, &beta)
	b.y.Neg(&a.y)
	b.z.Set(&a.z)
	require.Equal(t, 1, a.IsOnCurve())
	require.Equal(t, 1, b.IsOnCurve())
	c.Add(a, b)
	d.x.Set(&fp{
		0x29e1e987ef68f2d0,
		0xc5f3ec531db03233,
		0xacd6c4b6ca19730f,
		0x18ad9e827bc2bab7,
		0x46e3b2c5785cc7a9,
		0x07e571d42d22ddd6,
	})
	d.y.Set(&fp{
		0x94d117a7e5a539e7,
		0x8e17ef673d4b5d22,
		0x9d746aaf508a33ea,
		0x8c6d883d2516c9a2,
		0x0bc3b8d5fb0447f7,
		0x07bfa4c7210f4f44,
	})
	d.z.SetOne()
	require.Equal(t, 1, c.Equal(d))
}

func TestG1Sub(t *testing.T) {
	a := new(G1).Generator()
	b := new(G1).Generator()
	require.Equal(t, 1, a.Sub(a, b).IsIdentity())
	b.Double(b)
	a.Generator()
	require.Equal(t, 1, b.Sub(b, a).Equal(a))
}

func TestG1Mul(t *testing.T) {
	g := new(G1).Generator()
	a := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{
		0x2b568297a56da71c,
		0xd8c39ecb0ef375d1,
		0x435c38da67bfbf96,
		0x8088a05026b659b2,
	})
	b := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{
		0x785fdd9b26ef8b85,
		0xc997f25837695c18,
		0x4c8dbc39e7b756c1,
		0x70d9b6cc6d87df20,
	})
	c := Bls12381FqNew().Mul(a, b)
	t1 := new(G1).Generator()
	t1.Mul(t1, a)
	t1.Mul(t1, b)
	require.Equal(t, 1, t1.Equal(g.Mul(g, c)))
}

func TestG1Neg(t *testing.T) {
	a := new(G1).Generator()
	b := new(G1).Neg(a)
	require.Equal(t, 1, new(G1).Add(a, b).IsIdentity())
	require.Equal(t, 1, new(G1).Sub(a, b.Neg(b)).IsIdentity())
	a.Identity()
	require.Equal(t, 1, a.Neg(a).IsIdentity())
}

func TestG1InCorrectSubgroup(t *testing.T) {
	// ZCash test vector
	a := G1{
		x: fp{
			0x0abaf895b97e43c8,
			0xba4c6432eb9b61b0,
			0x12506f52adfe307f,
			0x75028c3439336b72,
			0x84744f05b8e9bd71,
			0x113d554fb09554f7,
		},
		y: fp{
			0x73e90e88f5cf01c0,
			0x37007b65dd3197e2,
			0x5cf9a1992f0d7c78,
			0x4f83c10b9eb3330d,
			0xf6a63f6f07f60961,
			0x0c53b5b97e634df3,
		},
		z: *(new(fp).SetOne()),
	}
	require.Equal(t, 0, a.InCorrectSubgroup())

	require.Equal(t, 1, new(G1).Identity().InCorrectSubgroup())
	require.Equal(t, 1, new(G1).Generator().InCorrectSubgroup())
}

func TestG1MulByX(t *testing.T) {
	// multiplying by `x` a point in G1 is the same as multiplying by
	// the equivalent scalar.
	generator := new(G1).Generator()
	x := Bls12381FqNew().SetUint64(paramX)
	x.Neg(x)
	lhs := new(G1).Mul(generator, x)
	rhs := new(G1).MulByX(generator)
	require.Equal(t, 1, lhs.Equal(rhs))

	pt := new(G1).Generator()
	s := Bls12381FqNew().SetUint64(42)
	pt.Mul(pt, s)
	lhs.Mul(pt, x)
	rhs.MulByX(pt)
	require.Equal(t, 1, lhs.Equal(rhs))
}

func TestG1ClearCofactor(t *testing.T) {
	// the generator (and the identity) are always on the curve,
	// even after clearing the cofactor
	generator := new(G1).Generator()
	generator.ClearCofactor(generator)
	require.Equal(t, 1, generator.IsOnCurve())
	id := new(G1).Identity()
	id.ClearCofactor(id)
	require.Equal(t, 1, id.IsOnCurve())

	z := fp{
		0x3d2d1c670671394e,
		0x0ee3a800a2f7c1ca,
		0x270f4f21da2e5050,
		0xe02840a53f1be768,
		0x55debeb597512690,
		0x08bd25353dc8f791,
	}

	point := G1{
		x: fp{
			0x48af5ff540c817f0,
			0xd73893acaf379d5a,
			0xe6c43584e18e023c,
			0x1eda39c30f188b3e,
			0xf618c6d3ccc0f8d8,
			0x0073542cd671e16c,
		},
		y: fp{
			0x57bf8be79461d0ba,
			0xfc61459cee3547c3,
			0x0d23567df1ef147b,
			0x0ee187bcce1d9b64,
			0xb0c8cfbe9dc8fdc1,
			0x1328661767ef368b,
		},
		z: *(&fp{}).Set(&z),
	}
	point.x.Mul(&point.x, &z)
	point.z.Square(&z)
	point.z.Mul(&point.z, &z)

	require.Equal(t, 1, point.IsOnCurve())
	require.Equal(t, 0, point.InCorrectSubgroup())
	clearedPoint := new(G1).ClearCofactor(&point)
	require.Equal(t, 1, clearedPoint.IsOnCurve())
	require.Equal(t, 1, clearedPoint.InCorrectSubgroup())

	// in BLS12-381 the cofactor in G1 can be
	// cleared multiplying by (1-x)
	hEff := Bls12381FqNew().SetOne()
	hEff.Add(hEff, Bls12381FqNew().SetUint64(paramX))
	point.Mul(&point, hEff)
	require.Equal(t, 1, clearedPoint.Equal(&point))
}

func TestG1Hash(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_")
	tests := []struct {
		input, expected string
	}{
		{"", "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a108ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265"},
		{"abc", "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f69030b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d"},
		{"abcdef0123456789", "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d9803a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709"},
		{"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "15f68eaa693b95ccb85215dc65fa81038d69629f70aeee0d0f677cf22285e7bf58d7cb86eefe8f2e9bc3f8cb84fac4881807a1d50c29f430b8cafc4f8638dfeeadf51211e1602a5f184443076715f91bb90a48ba1e370edce6ae1062f5e6dd38"},
		{"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "082aabae8b7dedb0e78aeb619ad3bfd9277a2f77ba7fad20ef6aabdc6c31d19ba5a6d12283553294c1825c4b3ca2dcfe05b84ae5a942248eea39e1d91030458c40153f3b654ab7872d779ad1e942856a20c438e8d99bc8abfbf74729ce1f7ac8"},
	}

	pt := new(G1).Identity()
	ept := new(G1).Identity()
	var b [WideFieldBytes]byte
	for _, tst := range tests {
		i := []byte(tst.input)
		e, _ := hex.DecodeString(tst.expected)
		copy(b[:], e)
		_, _ = ept.FromUncompressed(&b)
		pt.Hash(native.EllipticPointHasherSha256(), i, dst)
		require.Equal(t, 1, pt.Equal(ept))
	}
}

func TestSerialization(t *testing.T) {
	a := new(G1).Hash(native.EllipticPointHasherSha256(), []byte("a"), []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_"))
	b := new(G1).Hash(native.EllipticPointHasherSha256(), []byte("b"), []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_"))

	aBytes := a.ToCompressed()
	bBytes := b.ToCompressed()

	aa, err := new(G1).FromCompressed(&aBytes)
	require.NoError(t, err)
	require.Equal(t, 1, a.Equal(aa))

	bb, err := new(G1).FromCompressed(&bBytes)
	require.NoError(t, err)
	require.Equal(t, 1, b.Equal(bb))

	auBytes := a.ToUncompressed()
	buBytes := b.ToUncompressed()

	_, err = aa.FromUncompressed(&auBytes)
	require.NoError(t, err)
	require.Equal(t, 1, a.Equal(aa))

	_, err = bb.FromUncompressed(&buBytes)
	require.NoError(t, err)
	require.Equal(t, 1, b.Equal(bb))

	bBytes = a.ToCompressed()
	a.Neg(a)
	aBytes = a.ToCompressed()
	_, err = aa.FromCompressed(&aBytes)
	require.NoError(t, err)
	require.Equal(t, 1, a.Equal(aa))
	_, err = aa.FromCompressed(&bBytes)
	require.NoError(t, err)
	require.Equal(t, 0, a.Equal(aa))
	require.Equal(t, 1, aa.Equal(a.Neg(a)))
}

func TestSumOfProducts(t *testing.T) {
	var b [64]byte
	h0, _ := new(G1).Random(crand.Reader)
	_, _ = crand.Read(b[:])
	s := Bls12381FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	sTilde := Bls12381FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	c := Bls12381FqNew().SetBytesWide(&b)

	lhs := new(G1).Mul(h0, s)
	rhs, _ := new(G1).SumOfProducts([]*G1{h0}, []*native.Field{s})
	require.Equal(t, 1, lhs.Equal(rhs))

	u := new(G1).Mul(h0, s)
	uTilde := new(G1).Mul(h0, sTilde)
	sHat := Bls12381FqNew().Mul(c, s)
	sHat.Sub(sTilde, sHat)

	rhs.Mul(u, c)
	rhs.Add(rhs, new(G1).Mul(h0, sHat))
	require.Equal(t, 1, uTilde.Equal(rhs))
	_, _ = rhs.SumOfProducts([]*G1{u, h0}, []*native.Field{c, sHat})
	require.Equal(t, 1, uTilde.Equal(rhs))
}
