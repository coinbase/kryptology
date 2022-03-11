//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
)

func TestPoseidonHash(t *testing.T) {
	// Reference https://github.com/o1-labs/proof-systems/blob/master/oracle/tests/test_vectors/3w.json
	testVectors := []struct {
		input  []*fp.Fp
		output *fq.Fq
	}{
		{
			input:  []*fp.Fp{},
			output: hexToFq("1b3251b6912d82edc78bbb0a5c88f0c6fde1781bc3e654123fa6862a4c63e617"),
		},
		{
			input: []*fp.Fp{
				hexToFp("df698e389c6f1987ffe186d806f8163738f5bf22e8be02572cce99dc6a4ab030"),
			},
			output: hexToFq("f9b1b6c5f8c98017c6b35ac74bc689b6533d6dbbee1fd868831b637a43ea720c"),
		},
		{
			input: []*fp.Fp{
				hexToFp("56b648a5a85619814900a6b40375676803fe16fb1ad2d1fb79115eb1b52ac026"),
				hexToFp("f26a8a03d9c9bbd9c6b2a1324d2a3f4d894bafe25a7e4ad1a498705f4026ff2f"),
			},
			output: hexToFq("7a556e93bcfbd27b55867f533cd1df293a7def60dd929a086fdd4e70393b0918"),
		},
		{
			input: []*fp.Fp{
				hexToFp("075c41fa23e4690694df5ded43624fd60ab7ee6ec6dd48f44dc71bc206cecb26"),
				hexToFp("a4e2beebb09bd02ad42bbccc11051e8262b6ef50445d8382b253e91ab1557a0d"),
				hexToFp("7dfc23a1242d9c0d6eb16e924cfba342bb2fccf36b8cbaf296851f2e6c469639"),
			},
			output: hexToFq("f94b39a919aab06f43f4a4b5a3e965b719a4dbd2b9cd26d2bba4197b10286b35"),
		},
		{
			input: []*fp.Fp{
				hexToFp("a1a659b14e80d47318c6fcdbbd388de4272d5c2815eb458cf4f196d52403b639"),
				hexToFp("5e33065d1801131b64d13038ff9693a7ef6283f24ec8c19438d112ff59d50f04"),
				hexToFp("38a8f4d0a9b6d0facdc4e825f6a2ba2b85401d5de119bf9f2bcb908235683e06"),
				hexToFp("3456d0313a30d7ccb23bd71ed6aa70ab234dad683d8187b677aef73f42f4f52e"),
			},
			output: hexToFq("cc1ccfa964fd6ef9ff1994beb53cfce9ebe1212847ce30e4c64f0777875aec34"),
		},
		{
			input: []*fp.Fp{
				hexToFp("bccfee48dc76bb991c97bd531cf489f4ee37a66a15f5cfac31bdd4f159d4a905"),
				hexToFp("2d106fb21a262f85fd400a995c6d74bad48d8adab2554046871c215e585b072b"),
				hexToFp("8300e93ee8587956534d0756bb2aa575e5878c670cff5c8e3e55c62632333c06"),
				hexToFp("879c32da31566f6d16afdefff94cba5260fec1057e97f19fc9a61dc2c54a6417"),
				hexToFp("9c0aa6e5501cfb2d08aeaea5b3cddac2c9bee85d13324118b44bafb63a59611e"),
			},
			output: hexToFq("cf7b9c2128f0e2c0fed4e1eca8d5954b629640c2458d24ba238c1bd3ccbc8e12"),
		},
	}
	for _, tv := range testVectors {
		ctx := new(Context).Init(ThreeW, NetworkType(NullNet))
		ctx.Update(tv.input)
		res := ctx.Digest()
		require.True(t, res.Equal(tv.output))
	}
	testVectors = []struct {
		input  []*fp.Fp
		output *fq.Fq
	}{
		{
			input: []*fp.Fp{
				hexToFp("0f48c65bd25f85f3e4ea4efebeb75b797bd743603be04b4ead845698b76bd331"),
				hexToFp("0f48c65bd25f85f3e4ea4efebeb75b797bd743603be04b4ead845698b76bd331"),
				hexToFp("f34b505e1a05ecfb327d8d664ff6272ddf5cc1f69618bb6a4407e9533067e703"),
				hexToFp("0f48c65bd25f85f3e4ea4efebeb75b797bd743603be04b4ead845698b76bd331"),
				hexToFp("ac7cb9c568955737eca56f855954f394cc6b05ac9b698ba3d974f029177cb427"),
				hexToFp("010141eca06991fe68dcbd799d93037522dc6c4dead1d77202e8c2ea8f5b1005"),
				hexToFp("0300000000000000010000000000000090010000204e0000021ce8d0d2e64012"),
				hexToFp("9b030903692b6b7b030000000000000000000000000000000000800100000000"),
				hexToFp("000000a800000000000000000000000000000000000000000000000000000000"),
			},
			output: &fq.Fq{
				1348483115953159504,
				14115862092770957043,
				15858311826851986539,
				1644043871107534594,
			},
		},
	}
	for _, tv := range testVectors {
		ctx := new(Context).Init(ThreeW, NetworkType(MainNet))
		ctx.Update(tv.input)
		res := ctx.Digest()
		require.True(t, res.Equal(tv.output))
	}
}

func hexToFp(s string) *fp.Fp {
	var buffer [32]byte
	input, _ := hex.DecodeString(s)
	copy(buffer[:], input)
	f, _ := new(fp.Fp).SetBytes(&buffer)
	return f
}

func hexToFq(s string) *fq.Fq {
	var buffer [32]byte
	input, _ := hex.DecodeString(s)
	copy(buffer[:], input)
	f, _ := new(fq.Fq).SetBytes(&buffer)
	return f
}
