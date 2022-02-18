//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package core

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandMessageXmd(t *testing.T) {
	// https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-10#appendix-K.1
	tests := []struct {
		f             func() hash.Hash
		msg           []byte
		lenInBytesHex string
		expectedHex   string
	}{
		{sha256.New, []byte(""), "20", "f659819a6473c1835b25ea59e3d38914c98b374f0970b7e4c92181df928fca88"},
		{sha256.New, []byte("abc"), "20", "1c38f7c211ef233367b2420d04798fa4698080a8901021a795a1151775fe4da7"},
		{sha256.New, []byte("abcdef0123456789"), "20", "8f7e7b66791f0da0dbb5ec7c22ec637f79758c0a48170bfb7c4611bd304ece89"},
		{sha256.New, []byte("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"), "20", "72d5aa5ec810370d1f0013c0df2f1d65699494ee2a39f72e1716b1b964e1c642"},
		{sha256.New, []byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "20", "3b8e704fc48336aca4c2a12195b720882f2162a4b7b13a9c350db46f429b771b"},
		{sha256.New, []byte(""), "80", "8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f89580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c760861c0cde2005afc2c114042ee7b5848f5303f0611cf297f"},
		{sha256.New, []byte("abc"), "80", "fe994ec51bdaa821598047b3121c149b364b178606d5e72bfbb713933acc29c186f316baecf7ea22212f2496ef3f785a27e84a40d8b299cec56032763eceeff4c61bd1fe65ed81decafff4a31d0198619c0aa0c6c51fca15520789925e813dcfd318b542f8799441271f4db9ee3b8092a7a2e8d5b75b73e28fb1ab6b4573c192"},
		{sha256.New, []byte("abcdef0123456789"), "80", "c9ec7941811b1e19ce98e21db28d22259354d4d0643e301175e2f474e030d32694e9dd5520dde93f3600d8edad94e5c364903088a7228cc9eff685d7eaac50d5a5a8229d083b51de4ccc3733917f4b9535a819b445814890b7029b5de805bf62b33a4dc7e24acdf2c924e9fe50d55a6b832c8c84c7f82474b34e48c6d43867be"},
		{sha256.New, []byte("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"), "80", "48e256ddba722053ba462b2b93351fc966026e6d6db493189798181c5f3feea377b5a6f1d8368d7453faef715f9aecb078cd402cbd548c0e179c4ed1e4c7e5b048e0a39d31817b5b24f50db58bb3720fe96ba53db947842120a068816ac05c159bb5266c63658b4f000cbf87b1209a225def8ef1dca917bcda79a1e42acd8069"},
		{sha256.New, []byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "80", "396962db47f749ec3b5042ce2452b619607f27fd3939ece2746a7614fb83a1d097f554df3927b084e55de92c7871430d6b95c2a13896d8a33bc48587b1f66d21b128a1a8240d5b0c26dfe795a1a842a0807bb148b77c2ef82ed4b6c9f7fcb732e7f94466c8b51e52bf378fba044a31f5cb44583a892f5969dcd73b3fa128816e"},

		{sha512.New, []byte(""), "20", "2eaa1f7b5715f4736e6a5dbe288257abf1faa028680c1d938cd62ac699ead642"},
		{sha512.New, []byte("abc"), "20", "0eeda81f69376c80c0f8986496f22f21124cb3c562cf1dc608d2c13005553b0f"},
		{sha512.New, []byte("abcdef0123456789"), "20", "2e375fc05e05e80dbf3083796fde2911789d9e8847e1fcebf4ca4b36e239b338"},
		{sha512.New, []byte("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"), "20", "c37f9095fe7fe4f01c03c3540c1229e6ac8583b07510085920f62ec66acc0197"},
		{sha512.New, []byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "20", "af57a7f56e9ed2aa88c6eab45c8c6e7638ae02da7c92cc04f6648c874ebd560e"},
		{sha512.New, []byte(""), "80", "0687ce02eba5eb3faf1c3c539d1f04babd3c0f420edae244eeb2253b6c6d6865145c31458e824b4e87ca61c3442dc7c8c9872b0b7250aa33e0668ccebbd2b386de658ca11a1dcceb51368721ae6dcd2d4bc86eaebc4e0d11fa02ad053289c9b28a03da6c942b2e12c14e88dbde3b0ba619d6214f47212b628f3e1b537b66efcf"},
		{sha512.New, []byte("abc"), "80", "779ae4fd8a92f365e4df96b9fde97b40486bb005c1a2096c86f55f3d92875d89045fbdbc4a0e9f2d3e1e6bcd870b2d7131d868225b6fe72881a81cc5166b5285393f71d2e68bb0ac603479959370d06bdbe5f0d8bfd9af9494d1e4029bd68ab35a561341dd3f866b3ef0c95c1fdfaab384ce24a23427803dda1db0c7d8d5344a"},
		{sha512.New, []byte("abcdef0123456789"), "80", "f0953d28846a50e9f88b7ae35b643fc43733c9618751b569a73960c655c068db7b9f044ad5a40d49d91c62302eaa26163c12abfa982e2b5d753049e000adf7630ae117aeb1fb9b61fc724431ac68b369e12a9481b4294384c3c890d576a79264787bc8076e7cdabe50c044130e480501046920ff090c1a091c88391502f0fbac"},
		{sha512.New, []byte("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"), "80", "64d3e59f0bc3c5e653011c914b419ba8310390a9585311fddb26791d26663bd71971c347e1b5e88ba9274d2445ed9dcf48eea9528d807b7952924159b7c27caa4f25a2ea94df9508e70a7012dfce0e8021b37e59ea21b80aa9af7f1a1f2efa4fbe523c4266ce7d342acaacd438e452c501c131156b4945515e9008d2b155c258"},
		{sha512.New, []byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "80", "01524feea5b22f6509f6b1e805c97df94faf4d821b01aadeebc89e9daaed0733b4544e50852fd3e019d58eaad6d267a134c8bc2c08bc46c10bfeff3ee03110bcd8a0d695d75a34092bd8b677bdd369a13325549abab54f4ac907b712bdd3567f38c4554c51902b735b81f43a7ef6f938c7690d107c052c7e7b795ac635b3200a"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("msg: %s", test.msg), func(t *testing.T) {
			DST := []byte("QUUX-V01-CS02-with-expander")
			lenInBytes, err := strconv.ParseInt(test.lenInBytesHex, 16, 64)
			require.NoError(t, err)
			expected, err := hex.DecodeString(test.expectedHex)
			require.NoError(t, err)
			actual, err := ExpandMessageXmd(test.f, test.msg, DST, int(lenInBytes))
			require.NoError(t, err)
			require.Equal(t, actual, expected)
		})
	}
}
func TestFiatShamirDeterministic(t *testing.T) {
	a := big.NewInt(1)
	hash, err := FiatShamir(a)
	require.Nil(t, err)
	require.Equal(t, hash, []byte{0x3d, 0x95, 0xc0, 0x9f, 0x41, 0x33, 0x25, 0xbb, 0x10, 0x77, 0x2d, 0x83, 0x1d, 0x3e, 0x67, 0x98, 0xce, 0x7b, 0xde, 0xd5, 0x7f, 0x9, 0x7e, 0xfc, 0x77, 0x23, 0xfc, 0x49, 0x36, 0x82, 0xdd, 0x6a})

	a = big.NewInt(0xaaa)
	hash, err = FiatShamir(a)
	require.Nil(t, err)
	require.Equal(t, hash, []byte{0x61, 0xa9, 0x7f, 0x6, 0x74, 0xec, 0x47, 0xf5, 0xac, 0x30, 0xa0, 0x4c, 0x34, 0xdb, 0x51, 0x97, 0x60, 0x7e, 0xb2, 0x4a, 0x97, 0x9, 0xa5, 0xb9, 0x1c, 0x89, 0x30, 0x39, 0xb7, 0x29, 0xe6, 0x30})
}

func TestFiatShamirEqual(t *testing.T) {
	pi, err := FiatShamir(One)
	require.Nil(t, err)
	pi_, err := FiatShamir(One)
	require.Nil(t, err)
	require.Equal(t, pi, pi_)
}

func TestFiatShamirNotEqual(t *testing.T) {
	pi, err := FiatShamir(One)
	require.Nil(t, err)
	pi_, err := FiatShamir(Two)
	require.Nil(t, err)
	require.NotEqual(t, pi, pi_)
}

func TestFiatShamirOrderDependent(t *testing.T) {
	a := big.NewInt(1)
	b := big.NewInt(100)

	pi, err := FiatShamir(a, b)
	require.Nil(t, err)
	pi_, err := FiatShamir(a, b)
	require.Nil(t, err)
	require.Equal(t, pi, pi_)

	q, _ := FiatShamir(b, a)
	require.NotEqual(t, pi, q)
}

func TestFiatShamirExtensionAttackResistance(t *testing.T) {
	a := big.NewInt(0x00FF)
	b := big.NewInt(0xFF00)

	c := big.NewInt(0x00)
	d := big.NewInt(0xFFFF00)

	pi, err := FiatShamir(a, b)
	require.Nil(t, err)
	pi_, err := FiatShamir(c, d)
	require.Nil(t, err)
	require.NotEqual(t, pi, pi_)

	a = big.NewInt(0x0000)
	b = big.NewInt(0xFFFF)

	c = big.NewInt(0x0000F)
	d = big.NewInt(0xFFF)

	q, err := FiatShamir(a, b)
	require.Nil(t, err)
	q_, err := FiatShamir(c, d)
	require.Nil(t, err)
	require.NotEqual(t, q, q_)
}
