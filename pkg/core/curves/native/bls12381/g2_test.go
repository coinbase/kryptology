package bls12381

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
)

func TestG2IsOnCurve(t *testing.T) {
	require.Equal(t, 1, new(G2).Identity().IsOnCurve())
	require.Equal(t, 1, new(G2).Generator().IsOnCurve())

	z := fp2{
		A: fp{
			0xba7a_fa1f_9a6f_e250,
			0xfa0f_5b59_5eaf_e731,
			0x3bdc_4776_94c3_06e7,
			0x2149_be4b_3949_fa24,
			0x64aa_6e06_49b2_078c,
			0x12b1_08ac_3364_3c3e,
		},
		B: fp{
			0x1253_25df_3d35_b5a8,
			0xdc46_9ef5_555d_7fe3,
			0x02d7_16d2_4431_06a9,
			0x05a1_db59_a6ff_37d0,
			0x7cf7_784e_5300_bb8f,
			0x16a8_8922_c7a5_e844,
		},
	}

	test := new(G2).Generator()
	test.x.Mul(&test.x, &z)
	test.y.Mul(&test.y, &z)
	test.z.Set(&z)

	require.Equal(t, 1, test.IsOnCurve())

	test.x.Set(&z)
	require.Equal(t, 0, test.IsOnCurve())
}

func TestG2Equal(t *testing.T) {
	a := new(G2).Generator()
	b := new(G2).Identity()

	require.Equal(t, 1, a.Equal(a))
	require.Equal(t, 0, a.Equal(b))
	require.Equal(t, 1, b.Equal(b))
}

func TestG2ToAffine(t *testing.T) {
	a := new(G2).Generator()

	z := fp2{
		A: fp{
			0xba7afa1f9a6fe250,
			0xfa0f5b595eafe731,
			0x3bdc477694c306e7,
			0x2149be4b3949fa24,
			0x64aa6e0649b2078c,
			0x12b108ac33643c3e,
		},
		B: fp{
			0x125325df3d35b5a8,
			0xdc469ef5555d7fe3,
			0x02d716d2443106a9,
			0x05a1db59a6ff37d0,
			0x7cf7784e5300bb8f,
			0x16a88922c7a5e844,
		},
	}

	a.x.Mul(&a.x, &z)
	a.y.Mul(&a.y, &z)
	a.z.Set(&z)

	require.Equal(t, 1, a.ToAffine(a).Equal(new(G2).Generator()))
}

func TestG2Double(t *testing.T) {
	a := new(G2).Identity()
	require.Equal(t, 1, a.Double(a).IsIdentity())

	a.Generator()
	a.Double(a)
	e := G2{
		x: fp2{
			A: fp{
				0xe9d9e2da9620f98b,
				0x54f1199346b97f36,
				0x3db3b820376bed27,
				0xcfdb31c9b0b64f4c,
				0x41d7c12786354493,
				0x05710794c255c064,
			},
			B: fp{
				0xd6c1d3ca6ea0d06e,
				0xda0cbd905595489f,
				0x4f5352d43479221d,
				0x8ade5d736f8c97e0,
				0x48cc8433925ef70e,
				0x08d7ea71ea91ef81,
			},
		},
		y: fp2{
			A: fp{
				0x15ba26eb4b0d186f,
				0x0d086d64b7e9e01e,
				0xc8b848dd652f4c78,
				0xeecf46a6123bae4f,
				0x255e8dd8b6dc812a,
				0x164142af21dcf93f,
			},
			B: fp{
				0xf9b4a1a895984db4,
				0xd417b114cccff748,
				0x6856301fc89f086e,
				0x41c777878931e3da,
				0x3556b155066a2105,
				0x00acf7d325cb89cf,
			},
		},
		z: *((&fp2{}).SetOne()),
	}
	require.Equal(t, 1, e.Equal(a))
}

func TestG2Add(t *testing.T) {
	a := new(G2).Identity()
	b := new(G2).Identity()
	c := new(G2).Add(a, b)
	require.Equal(t, 1, c.IsIdentity())
	b.Generator()
	c.Add(a, b)
	require.Equal(t, 1, c.Equal(b))

	a.Generator()
	a.Double(a)
	a.Double(a)
	b.Double(b)
	c.Add(a, b)

	d := new(G2).Generator()
	e := new(G2).Generator()
	for i := 0; i < 5; i++ {
		e.Add(e, d)
	}
	require.Equal(t, 1, e.Equal(c))

	// Degenerate case
	beta := fp2{
		A: fp{
			0xcd03c9e48671f071,
			0x5dab22461fcda5d2,
			0x587042afd3851b95,
			0x8eb60ebe01bacb9e,
			0x03f97d6e83d050d2,
			0x18f0206554638741,
		},
		B: fp{},
	}
	beta.Square(&beta)
	b.x.Mul(&a.x, &beta)
	b.y.Neg(&a.y)
	b.z.Set(&a.z)
	require.Equal(t, 1, b.IsOnCurve())

	c.Add(a, b)

	e.x.Set(&fp2{
		A: fp{
			0x705abc799ca773d3,
			0xfe132292c1d4bf08,
			0xf37ece3e07b2b466,
			0x887e1c43f447e301,
			0x1e0970d033bc77e8,
			0x1985c81e20a693f2,
		},
		B: fp{
			0x1d79b25db36ab924,
			0x23948e4d529639d3,
			0x471ba7fb0d006297,
			0x2c36d4b4465dc4c0,
			0x82bbc3cfec67f538,
			0x051d2728b67bf952,
		},
	})
	e.y.Set(&fp2{
		A: fp{
			0x41b1bbf6576c0abf,
			0xb6cc93713f7a0f9a,
			0x6b65b43e48f3f01f,
			0xfb7a4cfcaf81be4f,
			0x3e32dadc6ec22cb6,
			0x0bb0fc49d79807e3,
		},
		B: fp{
			0x7d1397788f5f2ddf,
			0xab2907144ff0d8e8,
			0x5b7573e0cdb91f92,
			0x4cb8932dd31daf28,
			0x62bbfac6db052a54,
			0x11f95c16d14c3bbe,
		},
	})
	e.z.SetOne()
	require.Equal(t, 1, e.Equal(c))
}

func TestG2Neg(t *testing.T) {
	a := new(G2).Generator()
	b := new(G2).Neg(a)
	require.Equal(t, 1, new(G2).Add(a, b).IsIdentity())
	require.Equal(t, 1, new(G2).Sub(a, b.Neg(b)).IsIdentity())
	a.Identity()
	require.Equal(t, 1, a.Neg(a).IsIdentity())
}

func TestG2Mul(t *testing.T) {
	g := new(G2).Generator()
	a := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{
		0x2b56_8297_a56d_a71c,
		0xd8c3_9ecb_0ef3_75d1,
		0x435c_38da_67bf_bf96,
		0x8088_a050_26b6_59b2,
	})
	b := Bls12381FqNew().SetRaw(&[native.FieldLimbs]uint64{
		0x785f_dd9b_26ef_8b85,
		0xc997_f258_3769_5c18,
		0x4c8d_bc39_e7b7_56c1,
		0x70d9_b6cc_6d87_df20,
	})
	c := Bls12381FqNew().Mul(a, b)

	t1 := new(G2).Generator()
	t1.Mul(t1, a)
	t1.Mul(t1, b)
	require.Equal(t, 1, t1.Equal(g.Mul(g, c)))
}

func TestG2InCorrectSubgroup(t *testing.T) {
	a := G2{
		x: fp2{
			A: fp{
				0x89f550c813db6431,
				0xa50be8c456cd8a1a,
				0xa45b374114cae851,
				0xbb6190f5bf7fff63,
				0x970ca02c3ba80bc7,
				0x02b85d24e840fbac,
			},
			B: fp{
				0x6888bc53d70716dc,
				0x3dea6b4117682d70,
				0xd8f5f930500ca354,
				0x6b5ecb6556f5c155,
				0xc96bef0434778ab0,
				0x05081505515006ad,
			},
		},
		y: fp2{
			A: fp{
				0x3cf1ea0d434b0f40,
				0x1a0dc610e603e333,
				0x7f89956160c72fa0,
				0x25ee03decf6431c5,
				0xeee8e206ec0fe137,
				0x097592b226dfef28,
			},
			B: fp{
				0x71e8bb5f29247367,
				0xa5fe049e211831ce,
				0x0ce6b354502a3896,
				0x93b012000997314e,
				0x6759f3b6aa5b42ac,
				0x156944c4dfe92bbb,
			},
		},
		z: *(&fp2{}).SetOne(),
	}
	require.Equal(t, 0, a.InCorrectSubgroup())

	require.Equal(t, 1, new(G2).Identity().InCorrectSubgroup())
	require.Equal(t, 1, new(G2).Generator().InCorrectSubgroup())
}

func TestG2MulByX(t *testing.T) {
	// multiplying by `x` a point in G2 is the same as multiplying by
	// the equivalent scalar.
	x := Bls12381FqNew().SetUint64(paramX)
	x.Neg(x)
	t1 := new(G2).Generator()
	t1.MulByX(t1)
	t2 := new(G2).Generator()
	t2.Mul(t2, x)
	require.Equal(t, 1, t1.Equal(t2))

	point := new(G2).Generator()
	a := Bls12381FqNew().SetUint64(42)
	point.Mul(point, a)

	t1.MulByX(point)
	t2.Mul(point, x)
	require.Equal(t, 1, t1.Equal(t2))
}

func TestG2Psi(t *testing.T) {
	generator := new(G2).Generator()

	z := fp2{
		A: fp{
			0x0ef2ddffab187c0a,
			0x2424522b7d5ecbfc,
			0xc6f341a3398054f4,
			0x5523ddf409502df0,
			0xd55c0b5a88e0dd97,
			0x066428d704923e52,
		},
		B: fp{
			0x538bbe0c95b4878d,
			0xad04a50379522881,
			0x6d5c05bf5c12fb64,
			0x4ce4a069a2d34787,
			0x59ea6c8d0dffaeaf,
			0x0d42a083a75bd6f3,
		},
	}

	// `point` is a random point in the curve
	point := G2{
		x: fp2{
			A: fp{
				0xee4c8cb7c047eaf2,
				0x44ca22eee036b604,
				0x33b3affb2aefe101,
				0x15d3e45bbafaeb02,
				0x7bfc2154cd7419a4,
				0x0a2d0c2b756e5edc,
			},
			B: fp{
				0xfc224361029a8777,
				0x4cbf2baab8740924,
				0xc5008c6ec6592c89,
				0xecc2c57b472a9c2d,
				0x8613eafd9d81ffb1,
				0x10fe54daa2d3d495,
			},
		},
		y: fp2{
			A: fp{
				0x7de7edc43953b75c,
				0x58be1d2de35e87dc,
				0x5731d30b0e337b40,
				0xbe93b60cfeaae4c9,
				0x8b22c203764bedca,
				0x01616c8d1033b771,
			},
			B: fp{
				0xea126fe476b5733b,
				0x85cee68b5dae1652,
				0x98247779f7272b04,
				0xa649c8b468c6e808,
				0xb5b9a62dff0c4e45,
				0x1555b67fc7bbe73d,
			},
		},
		z: *(&fp2{}).Set(&z),
	}
	point.x.Mul(&point.x, &z)
	point.z.Square(&point.z)
	point.z.Mul(&point.z, &z)
	require.Equal(t, 1, point.IsOnCurve())

	// psi2(P) = psi(psi(P))
	tv1 := new(G2).psi2(generator)
	tv2 := new(G2).psi(generator)
	tv2.psi(tv2)
	require.Equal(t, 1, tv1.Equal(tv2))

	tv1.psi2(&point)
	tv2.psi(&point)
	tv2.psi(tv2)
	require.Equal(t, 1, tv1.Equal(tv2))

	// psi(P) is a morphism
	tv1.Double(generator)
	tv1.psi(tv1)
	tv2.psi(generator)
	tv2.Double(tv2)
	require.Equal(t, 1, tv1.Equal(tv2))

	tv1.psi(&point)
	tv2.psi(generator)
	tv1.Add(tv1, tv2)

	tv2.Set(&point)
	tv3 := new(G2).Generator()
	tv2.Add(tv2, tv3)
	tv2.psi(tv2)
	require.Equal(t, 1, tv1.Equal(tv2))
}

func TestG2ClearCofactor(t *testing.T) {
	z := fp2{
		A: fp{
			0x0ef2ddffab187c0a,
			0x2424522b7d5ecbfc,
			0xc6f341a3398054f4,
			0x5523ddf409502df0,
			0xd55c0b5a88e0dd97,
			0x066428d704923e52,
		},
		B: fp{
			0x538bbe0c95b4878d,
			0xad04a50379522881,
			0x6d5c05bf5c12fb64,
			0x4ce4a069a2d34787,
			0x59ea6c8d0dffaeaf,
			0x0d42a083a75bd6f3,
		},
	}

	// `point` is a random point in the curve
	point := G2{
		x: fp2{
			A: fp{
				0xee4c8cb7c047eaf2,
				0x44ca22eee036b604,
				0x33b3affb2aefe101,
				0x15d3e45bbafaeb02,
				0x7bfc2154cd7419a4,
				0x0a2d0c2b756e5edc,
			},
			B: fp{
				0xfc224361029a8777,
				0x4cbf2baab8740924,
				0xc5008c6ec6592c89,
				0xecc2c57b472a9c2d,
				0x8613eafd9d81ffb1,
				0x10fe54daa2d3d495,
			},
		},
		y: fp2{
			A: fp{
				0x7de7edc43953b75c,
				0x58be1d2de35e87dc,
				0x5731d30b0e337b40,
				0xbe93b60cfeaae4c9,
				0x8b22c203764bedca,
				0x01616c8d1033b771,
			},
			B: fp{
				0xea126fe476b5733b,
				0x85cee68b5dae1652,
				0x98247779f7272b04,
				0xa649c8b468c6e808,
				0xb5b9a62dff0c4e45,
				0x1555b67fc7bbe73d,
			},
		},
		z: fp2{},
	}
	point.x.Mul(&point.x, &z)
	point.z.Square(&z)
	point.z.Mul(&point.z, &z)

	require.Equal(t, 1, point.IsOnCurve())
	require.Equal(t, 0, point.InCorrectSubgroup())

	clearedPoint := new(G2).ClearCofactor(&point)

	require.Equal(t, 1, clearedPoint.IsOnCurve())
	require.Equal(t, 1, clearedPoint.InCorrectSubgroup())

	// the generator (and the identity) are always on the curve,
	// even after clearing the cofactor
	generator := new(G2).Generator()
	generator.ClearCofactor(generator)
	require.Equal(t, 1, generator.InCorrectSubgroup())
	id := new(G2).Identity()
	id.ClearCofactor(id)
	require.Equal(t, 1, id.InCorrectSubgroup())

	// test the effect on q-torsion points multiplying by h_eff modulo q
	// h_eff % q = 0x2b116900400069009a40200040001ffff
	hEffModq := [native.FieldBytes]byte{
		0xff, 0xff, 0x01, 0x00, 0x04, 0x00, 0x02, 0xa4, 0x09, 0x90, 0x06, 0x00, 0x04, 0x90, 0x16,
		0xb1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	generator.Generator()
	generator.multiply(generator, &hEffModq)
	point.Generator().ClearCofactor(&point)
	require.Equal(t, 1, point.Equal(generator))
	point.ClearCofactor(clearedPoint)
	require.Equal(t, 1, point.Equal(clearedPoint.multiply(clearedPoint, &hEffModq)))
}

func TestG2Hash(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_")

	tests := []struct {
		input, expected string
	}{
		{"", "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d60503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92"},
		{"abc", "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd802c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e600aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd161787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48"},
		{"abcdef0123456789", "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd00bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8"},
		{"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "0934aba516a52d8ae479939a91998299c76d39cc0c035cd18813bec433f587e2d7a4fef038260eef0cef4d02aae3eb9119a84dd7248a1066f737cc34502ee5555bd3c19f2ecdb3c7d9e24dc65d4e25e50d83f0f77105e955d78f4762d33c17da09bcccfa036b4847c9950780733633f13619994394c23ff0b32fa6b795844f4a0673e20282d07bc69641cee04f5e566214f81cd421617428bc3b9fe25afbb751d934a00493524bc4e065635b0555084dd54679df1536101b2c979c0152d09192"},
		{"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d0156901a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f6253403a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab520b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e"},
	}

	pt := new(G2).Identity()
	ept := new(G2).Identity()
	var b [DoubleWideFieldBytes]byte
	for _, tst := range tests {
		i := []byte(tst.input)
		e, _ := hex.DecodeString(tst.expected)
		copy(b[:], e)
		_, _ = ept.FromUncompressed(&b)
		pt.Hash(native.EllipticPointHasherSha256(), i, dst)
		require.Equal(t, 1, pt.Equal(ept))
	}
}

func TestG2SumOfProducts(t *testing.T) {
	var b [64]byte
	h0, _ := new(G2).Random(crand.Reader)
	_, _ = crand.Read(b[:])
	s := Bls12381FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	sTilde := Bls12381FqNew().SetBytesWide(&b)
	_, _ = crand.Read(b[:])
	c := Bls12381FqNew().SetBytesWide(&b)

	lhs := new(G2).Mul(h0, s)
	rhs, _ := new(G2).SumOfProducts([]*G2{h0}, []*native.Field{s})
	require.Equal(t, 1, lhs.Equal(rhs))

	u := new(G2).Mul(h0, s)
	uTilde := new(G2).Mul(h0, sTilde)
	sHat := Bls12381FqNew().Mul(c, s)
	sHat.Sub(sTilde, sHat)

	rhs.Mul(u, c)
	rhs.Add(rhs, new(G2).Mul(h0, sHat))
	require.Equal(t, 1, uTilde.Equal(rhs))
	_, _ = rhs.SumOfProducts([]*G2{u, h0}, []*native.Field{c, sHat})
	require.Equal(t, 1, uTilde.Equal(rhs))
}
