package kzg

import (
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
	bls "github.com/coinbase/kryptology/pkg/core/curves/native/bls12381"
	"github.com/stretchr/testify/require"
)

// powersOfTau outputs the first few paramaters of the Powers of Tau
// from the Zcash Sapling MPC ceremony
//
// Paramaters:
// https://archive.org/download/transcript_201804/transcript
//
// Code:
// https://github.com/ebfull/powersoftau
//
// Attestations (for transcript verification):
// https://github.com/ZcashFoundation/powersoftau-attestations/
func powersOfTau() ([]*bls.G1, []*bls.G2, error) {

	// This is just the G1 generator, g^(α^0) = g
	tau1G1, err := new(bls.G1).SetRaw(
		&[bls.Limbs]uint64{
			0x5cb38790fd530c16,
			0x7817fc679976fff5,
			0x154f95c7143ba1c1,
			0xf0ae6acdf3d0e747,
			0xedce6ecc21dbf440,
			0x120177419e0bfb75,
		},
		&[bls.Limbs]uint64{
			0xbaac93d50ce72271,
			0x8c22631a7918fd8e,
			0xdd595f13570725ce,
			0x51ac582950405194,
			0xe1c8c3fad0059c0,
			0xbbc3efc5008a26a,
		})
	if err != nil {
		return nil, nil, err
	}

	tau2G1, err := new(bls.G1).SetRaw(
		&[bls.Limbs]uint64{
			0xb1c4001f43ae605c,
			0xa3259c7580e64c19,
			0x35a375eb1c6b9758,
			0x56398c8240e84f1a,
			0xd0674229a30b6f12,
			0xc24de091cff2040,
		},
		&[bls.Limbs]uint64{
			0xfef01719660b817f,
			0x3943aa777d478029,
			0x6a21d5aadb805014,
			0x6b70779aae4bfeae,
			0xc60ae2121bd27062,
			0x11608bd86899c384,
		})
	if err != nil {
		return nil, nil, err
	}

	tau3G1, err := new(bls.G1).SetRaw(
		&[bls.Limbs]uint64{
			0x57844fae301dad5b,
			0x6f12225a86af175f,
			0x39fa6ead21492fb7,
			0x572be66fcc7196dc,
			0x4e3ac15a95ae4189,
			0x188ae4aa9c4c4d90,
		},
		&[bls.Limbs]uint64{
			0xefd841545b412395,
			0x4342a395566f6d9,
			0x7fd75a271ae69a23,
			0xb7f6dc3b17acf301,
			0xb6f1810855b7341d,
			0x7cdbdaae73dd65c,
		})
	if err != nil {
		return nil, nil, err
	}

	tau4G1, err := new(bls.G1).SetRaw(
		&[bls.Limbs]uint64{
			0xb64f1c70030b3b7f,
			0x17aeaa6e95d48b0e,
			0x17df2ad41819165c,
			0x2d5ec7a8faee782c,
			0x225af243cd6cf0a3,
			0x1008968d4e6b5e97,
		},
		&[bls.Limbs]uint64{
			0xfd59d9e9a1c5a43f,
			0xd60b040b6034d94b,
			0x475800d82c3416be,
			0x279ad48ff205573e,
			0xa0085fc33ba625e,
			0x17dc30c37a15b4a9,
		})
	if err != nil {
		return nil, nil, err
	}

	tau1G2, err := new(bls.G2).SetRaw(
		&[bls.Limbs]uint64{
			0xf5f28fa202940a10,
			0xb3f5fb2687b4961a,
			0xa1a893b53e2ae580,
			0x9894999d1a3caee9,
			0x6f67b7631863366b,
			0x58191924350bcd7,
		},
		&[bls.Limbs]uint64{
			0xa5a9c0759e23f606,
			0xaaa0c59dbccd60c3,
			0x3bb17e18e2867806,
			0x1b1ab6cc8541b367,
			0xc2b6ed0ef2158547,
			0x11922a097360edf3,
		},
		&[bls.Limbs]uint64{
			0x4c730af860494c4a,
			0x597cfa1f5e369c5a,
			0xe7e6856caa0a635a,
			0xbbefb5e96e0d495f,
			0x7d3a975f0ef25a2,
			0x83fd8e7e80dae5,
		},
		&[bls.Limbs]uint64{
			0xadc0fc92df64b05d,
			0x18aa270a2b1461dc,
			0x86adac6a3be4eba0,
			0x79495c4ec93da33a,
			0xe7175850a43ccaed,
			0xb2bc2a163de1bf2,
		})
	if err != nil {
		return nil, nil, err
	}

	tau2G2, err := new(bls.G2).SetRaw(
		&[bls.Limbs]uint64{
			0xffa0385428fec3b,
			0x510e7ec541363eb2,
			0xf13a94ca2c2d416a,
			0x7fc5f5d9562339c0,
			0x7af592386dd863a0,
			0x18593bbbb413f4ae,
		},
		&[bls.Limbs]uint64{
			0x10c324d1c2da9496,
			0x1844dd0fe7a63725,
			0x6d579c341a22077e,
			0x540042d2463f25ec,
			0x7705869256c8c705,
			0x5e25cc82f956cef,
		},
		&[bls.Limbs]uint64{
			0x83ede256224bf8dc,
			0x5b1ec84cc0d00651,
			0x454e5fc13223a92a,
			0xe4b98a3823ce7167,
			0x72edd916ce4b0dea,
			0x141c08d488fa3db8,
		},
		&[bls.Limbs]uint64{
			0xfdb54d422ee52dd3,
			0xf591f71cbeffcd3b,
			0xfcf4f200ba0a3dc2,
			0x6556768a95fb0a5c,
			0x9b8119e0d7555f16,
			0xce9a4935faa25ac,
		})
	if err != nil {
		return nil, nil, err
	}

	tau3G2, err := new(bls.G2).SetRaw(
		&[bls.Limbs]uint64{
			0xbce1a6e1b4cc4e49,
			0x5f52d58f4d9045ce,
			0x51b75755bb4840fc,
			0xb14ccbdfbfae59ac,
			0xb568776a116083f1,
			0x830e2515553f995,
		},
		&[bls.Limbs]uint64{
			0x47b3efe5c1b422b5,
			0xaf5e1a16ec5acff6,
			0x63ad7b40247c15a9,
			0x878b700492359269,
			0x6dee8a04ec81e17b,
			0xb9153833d1f902d,
		},
		&[bls.Limbs]uint64{
			0xbc37454e5592a41a,
			0x5f63d5a84099e9a1,
			0x2ef53a21150565e6,
			0x99d7334f4ffd75da,
			0xba8ddcc454795953,
			0x5aa83390eb0f93d,
		},
		&[bls.Limbs]uint64{
			0xf07e3e18aa311fba,
			0xaece70f00b4a1b52,
			0x5051ea3658aae5bb,
			0x11c54ec96ee7474f,
			0x84b337d1bf6e7a80,
			0x197670e7cde405c2,
		})
	if err != nil {
		return nil, nil, err
	}

	tau4G2, err := new(bls.G2).SetRaw(
		&[bls.Limbs]uint64{
			0xf92483b72c69f0c3,
			0x182b5ed886dfa8b4,
			0xa9781c23b13d06f3,
			0xb65aa8447a9be1ad,
			0xb0360062d2308c75,
			0x19dde52f452a35c2,
		},
		&[bls.Limbs]uint64{
			0x5ad71d69d27ed223,
			0x34b15bae6258f2e3,
			0x58454bbf3d8bb982,
			0x317b6440cf7d36a8,
			0xaf8a321a59868131,
			0x117659178a3ad24b,
		},
		&[bls.Limbs]uint64{
			0xbb4db259f864aeb4,
			0x416d7414441e8c06,
			0x15620f806beb6138,
			0xad961f75dc5ea34d,
			0x8136272b6535ec8c,
			0x1375718ec52b4595,
		},
		&[bls.Limbs]uint64{
			0x60bab8e3dd660c,
			0x3587481b8dbb8929,
			0x93b6539d30cda8c4,
			0xb9574e9f7d280546,
			0x23a727eab19cc17e,
			0x44d63ce28227873,
		})
	if err != nil {
		return nil, nil, err
	}

	return []*bls.G1{tau1G1, tau2G1, tau3G1, tau4G1}, []*bls.G2{tau1G2, tau2G2, tau3G2, tau4G2}, nil
}

func TestSetupGenerator(t *testing.T) {
	a, b, err := Setup(5)
	require.NoError(t, err, "Unable to complete setup")
	require.Equal(t, 1, new(bls.G1).Generator().Equal(a[0]))
	require.Equal(t, 1, new(bls.G2).Generator().Equal(b[0]))
}

func TestCommitVerifyPoly(t *testing.T) {
	a, b, err := Setup(3)
	require.NoError(t, err, "Unable to complete setup")

	pk, err := NewKZGSetupParamaters(a, b)
	require.NoError(t, err, "Unable to create new KZGSetupParamaters")

	poly1 := new(Polynomial).SetUInt64([]uint64{1, 2, 3})
	poly2 := new(Polynomial).SetUInt64([]uint64{1, 2, 4})

	c, err := Commit(pk, poly1)
	require.NoError(t, err, "Unable to perform commit")

	// Ensure polynomials can be verified
	v_correct, err := VerifyPoly(pk, c, poly1)
	require.NoError(t, err, "Unable to perform verify")
	require.Equal(t, 1, v_correct)
	v_incorrect, err := VerifyPoly(pk, c, poly2)
	require.NoError(t, err, "Unable to perform verify")
	require.Equal(t, 0, v_incorrect)
}

func TestBadEval(t *testing.T) {
	a, b, err := Setup(5)
	require.NoError(t, err, "Unable to complete setup")

	pk, err := NewKZGSetupParamaters(a, b)
	require.NoError(t, err, "Unable to create new KZGSetupParamaters")

	poly1 := new(Polynomial).SetUInt64([]uint64{1, 1, 1, 1, 1, 1})
	_, err = EvalPolyG1(pk, poly1)
	require.Error(t, err)
}

func TestCommitVerifyPolyTau(t *testing.T) {
	tausG1, tausG2, err := powersOfTau()
	require.NoError(t, err, "Unable to complete setup")

	pk, err := NewKZGSetupParamaters(tausG1, tausG2)
	require.NoError(t, err, "Unable to create new KZGSetupParamaters")

	poly1 := new(Polynomial).SetUInt64([]uint64{1, 2, 3})
	poly2 := new(Polynomial).SetUInt64([]uint64{1, 2, 4})

	c, err := Commit(pk, poly1)
	require.NoError(t, err, "Unable to perform commit")

	// Ensure polynomials can be verified
	v_correct, err := VerifyPoly(pk, c, poly1)
	require.NoError(t, err, "Unable to perform verify")
	require.Equal(t, 1, v_correct)
	v_incorrect, err := VerifyPoly(pk, c, poly2)
	require.NoError(t, err, "Unable to perform verify")
	require.Equal(t, 0, v_incorrect)
}

func TestSetupFlow(t *testing.T) {
	a, b, err := Setup(10)
	require.NoError(t, err, "Unable to perform setup")
	pk, err := NewKZGSetupParamaters(a, b)
	require.NoError(t, err, "Unable to create new KZGSetupParamaters")

	poly := new(Polynomial).SetUInt64([]uint64{0, 1, 0, 1, 0, 1})
	z := bls.Bls12381FqNew().SetUint64(3)
	y := bls.Bls12381FqNew().SetUint64(273)

	c, err := Commit(pk, poly)
	require.NoError(t, err, "Unable to perform commit")

	proof, err := CreateWitness(pk, poly, z, y)
	require.NoError(t, err, "Unable to create evaluation proof")

	v := VerifyEval(pk, c, proof, z, y)
	require.Equal(t, 1, v)
}

func TestTauFlow(t *testing.T) {
	tausG1, tausG2, err := powersOfTau()
	require.NoError(t, err, "Unable to init powers of tau")
	pk, err := NewKZGSetupParamaters(tausG1, tausG2)
	require.NoError(t, err, "Unable to create new KZGSetupParamaters")

	poly := new(Polynomial).SetUInt64([]uint64{10, 1, 1, 5})
	x := bls.Bls12381FqNew().SetUint64(3)
	y := bls.Bls12381FqNew().Set(poly.Evaluate(x))

	c, err := Commit(pk, poly)
	require.NoError(t, err, "Unable to perform commit")

	ver, err := VerifyPoly(pk, c, poly)
	require.NoError(t, err, "Unable to perform polynomial verification")
	require.Equal(t, 1, ver)

	proof, err := CreateWitness(pk, poly, x, y)
	require.NoError(t, err, "Unable to create witness of evaluation")

	v := VerifyEval(pk, c, proof, x, y)
	require.Equal(t, 1, v)

	fakeProof := new(bls.G1).Mul(new(bls.G1).Generator(), bls.Bls12381FqNew().SetUint64(123))

	v2 := VerifyEval(pk, c, fakeProof, x, y)
	require.Equal(t, 0, v2)

	yWrong := bls.Bls12381FqNew().Add(y, bls.Bls12381FqNew().SetUint64(321))
	v3 := VerifyEval(pk, c, fakeProof, x, yWrong)
	require.Equal(t, 0, v3)
}

func TestTauBatchFlow(t *testing.T) {
	tausG1, tausG2, err := powersOfTau()
	require.NoError(t, err, "Unable to init powers of tau")
	pk, err := NewKZGSetupParamaters(tausG1, tausG2)
	require.NoError(t, err, "Unable to create new KZGSetupParamaters")

	poly := new(Polynomial).SetUInt64([]uint64{10, 20, 30, 40})
	x := []*native.Field{
		bls.Bls12381FqNew().SetUint64(9),
		bls.Bls12381FqNew().SetUint64(8),
		bls.Bls12381FqNew().SetUint64(7),
	}
	y := []*native.Field{}
	yBad := []*native.Field{}
	var y_ *native.Field
	for _, val := range x {
		y_ = poly.Evaluate(val)

		y = append(y, y_)
		yBad = append(yBad, bls.Bls12381FqNew().Add(y_, y_))
	}

	c, err := Commit(pk, poly)
	require.NoError(t, err, "Unable to perform commit")

	ver, err := VerifyPoly(pk, c, poly)
	require.NoError(t, err, "Unable to perform polynomial verification")
	require.Equal(t, 1, ver)

	// Verify normal setup
	proof, err := CreateWitnessBatch(pk, poly, x, y)
	require.NoError(t, err, "Unable to create batch witness of evaluation")

	v, err := VerifyEvalBatch(pk, c, proof, x, y)
	require.NoError(t, err, "Unable to varify evaluation")
	require.Equal(t, 1, v)

	// Fail verification for bad proof with good data
	proofBad := new(bls.G1).Mul(new(bls.G1).Generator(), bls.Bls12381FqNew().SetUint64(99))
	require.NoError(t, err, "Unable to create batch witness of evaluation")
	vwrong, err := VerifyEvalBatch(pk, c, proofBad, x, y)
	require.NoError(t, err, "Unable to varify evaluation")
	require.Equal(t, 0, vwrong)

	// Fail verification for incorrect polynomial evaluation
	ix, err := CreateLagrangePolynomial(yBad, x)
	require.NoError(t, err, "Unable to create lagrangian")
	q, _ := poly.Sub(ix).Div(CreateZeroPolynomial(yBad))
	badProof, err := EvalPolyG1(pk, q)
	require.NoError(t, err, "Unable to perform polynomial evaluation")
	vBadY, err := VerifyEvalBatch(pk, c, badProof, x, yBad)
	require.NoError(t, err, "Unable to varify evaluation")
	require.Equal(t, 0, vBadY)

}
