//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls12381

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"math/big"
	"testing"
)

func (g *G1) one() *PointG1 {
	one, _ := g.fromBytesUnchecked(fromHex(48,
		"0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
		"0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
	))
	return one
}

func (g *G1) rand() *PointG1 {
	k, err := rand.Int(rand.Reader, q)
	if err != nil {
		panic(err)
	}
	return g.MulScalar(&PointG1{}, g.one(), k)
}

func TestG1Serialization(t *testing.T) {
	var err error
	g1 := NewG1()
	zero := g1.Zero()
	b0, err := g1.ToUncompressed(zero)
	if err != nil {
		t.Fatal(err)
	}
	p0, err := g1.FromUncompressed(b0)
	if err != nil {
		t.Fatal(err)
	}
	if !g1.IsZero(p0) {
		t.Fatal("bad infinity serialization 1")
	}
	b0 = g1.ToCompressed(zero)
	p0, err = g1.FromCompressed(b0)
	if err != nil {
		t.Fatal(err)
	}
	if !g1.IsZero(p0) {
		t.Fatal("bad infinity serialization 2")
	}
	b0 = g1.ToBytes(zero)
	p0, err = g1.FromBytes(b0)
	if err != nil {
		t.Fatal(err)
	}
	if !g1.IsZero(p0) {
		t.Fatal("bad infinity serialization 3")
	}
	for i := 0; i < fuz; i++ {
		a := g1.rand()
		uncompressed, err := g1.ToUncompressed(a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := g1.FromUncompressed(uncompressed)
		if err != nil {
			t.Fatal(err)
		}
		if !g1.Equal(a, b) {
			t.Fatal("bad serialization 1")
		}
		compressed := g1.ToCompressed(b)
		a, err = g1.FromCompressed(compressed)
		if err != nil {
			t.Fatal(err)
		}
		if !g1.Equal(a, b) {
			t.Fatal("bad serialization 2")
		}
	}
	for i := 0; i < fuz; i++ {
		a := g1.rand()
		uncompressed := g1.ToBytes(a)
		b, err := g1.FromBytes(uncompressed)
		if err != nil {
			t.Fatal(err)
		}
		if !g1.Equal(a, b) {
			t.Fatal("bad serialization 3")
		}
	}
}

func TestG1IsOnCurve(t *testing.T) {
	g := NewG1()
	zero := g.Zero()
	if !g.IsOnCurve(zero) {
		t.Fatal("zero must be on curve")
	}
	one := new(fe).one()
	p := &PointG1{*one, *one, *one}
	if g.IsOnCurve(p) {
		t.Fatal("(1, 1) is not on curve")
	}
}

func TestG1AdditiveProperties(t *testing.T) {
	g := NewG1()
	t0, t1 := g.New(), g.New()
	zero := g.Zero()
	for i := 0; i < fuz; i++ {
		a, b := g.rand(), g.rand()
		g.Add(t0, a, zero)
		if !g.Equal(t0, a) {
			t.Fatal("a + 0 == a")
		}
		g.Add(t0, zero, zero)
		if !g.Equal(t0, zero) {
			t.Fatal("0 + 0 == 0")
		}
		g.Sub(t0, a, zero)
		if !g.Equal(t0, a) {
			t.Fatal("a - 0 == a")
		}
		g.Sub(t0, zero, zero)
		if !g.Equal(t0, zero) {
			t.Fatal("0 - 0 == 0")
		}
		g.Neg(t0, zero)
		if !g.Equal(t0, zero) {
			t.Fatal("- 0 == 0")
		}
		g.Sub(t0, zero, a)
		g.Neg(t0, t0)
		if !g.Equal(t0, a) {
			t.Fatal(" - (0 - a) == a")
		}
		g.Double(t0, zero)
		if !g.Equal(t0, zero) {
			t.Fatal("2 * 0 == 0")
		}
		g.Double(t0, a)
		g.Sub(t0, t0, a)
		if !g.Equal(t0, a) || !g.IsOnCurve(t0) {
			t.Fatal(" (2 * a) - a == a")
		}
		g.Add(t0, a, b)
		g.Add(t1, b, a)
		if !g.Equal(t0, t1) {
			t.Fatal("a + b == b + a")
		}
		g.Sub(t0, a, b)
		g.Sub(t1, b, a)
		g.Neg(t1, t1)
		if !g.Equal(t0, t1) {
			t.Fatal("a - b == - ( b - a )")
		}
		c := g.rand()
		g.Add(t0, a, b)
		g.Add(t0, t0, c)
		g.Add(t1, a, c)
		g.Add(t1, t1, b)
		if !g.Equal(t0, t1) {
			t.Fatal("(a + b) + c == (a + c ) + b")
		}
		g.Sub(t0, a, b)
		g.Sub(t0, t0, c)
		g.Sub(t1, a, c)
		g.Sub(t1, t1, b)
		if !g.Equal(t0, t1) {
			t.Fatal("(a - b) - c == (a - c) -b")
		}
	}
}

func TestG1MultiplicativeProperties(t *testing.T) {
	g := NewG1()
	t0, t1 := g.New(), g.New()
	zero := g.Zero()
	for i := 0; i < fuz; i++ {
		a := g.rand()
		s1, s2, s3 := randScalar(q), randScalar(q), randScalar(q)
		sone := big.NewInt(1)
		g.MulScalar(t0, zero, s1)
		if !g.Equal(t0, zero) {
			t.Fatal(" 0 ^ s == 0")
		}
		g.MulScalar(t0, a, sone)
		if !g.Equal(t0, a) {
			t.Fatal(" a ^ 1 == a")
		}
		g.MulScalar(t0, zero, s1)
		if !g.Equal(t0, zero) {
			t.Fatal(" 0 ^ s == a")
		}
		g.MulScalar(t0, a, s1)
		g.MulScalar(t0, t0, s2)
		s3.Mul(s1, s2)
		g.MulScalar(t1, a, s3)
		if !g.Equal(t0, t1) {
			t.Errorf(" (a ^ s1) ^ s2 == a ^ (s1 * s2)")
		}
		g.MulScalar(t0, a, s1)
		g.MulScalar(t1, a, s2)
		g.Add(t0, t0, t1)
		s3.Add(s1, s2)
		g.MulScalar(t1, a, s3)
		if !g.Equal(t0, t1) {
			t.Errorf(" (a ^ s1) + (a ^ s2) == a ^ (s1 + s2)")
		}
	}
}

func TestZKCryptoVectorsG1UncompressedValid(t *testing.T) {
	data, err := ioutil.ReadFile("tests/g1_uncompressed_valid_test_vectors.dat")
	if err != nil {
		panic(err)
	}
	g := NewG1()
	p1 := g.Zero()
	for i := 0; i < 1000; i++ {
		vector := data[i*96 : (i+1)*96]
		p2, err := g.FromUncompressed(vector)
		if err != nil {
			t.Fatal("decoing fails", err, i)
		}
		uncompressed, err := g.ToUncompressed(p2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(vector, uncompressed) || !g.Equal(p1, p2) {
			t.Fatal("bad serialization")
		}

		g.Add(p1, p1, &g1One)
	}
}

func TestZKCryptoVectorsG1CompressedValid(t *testing.T) {
	data, err := ioutil.ReadFile("tests/g1_compressed_valid_test_vectors.dat")
	if err != nil {
		panic(err)
	}
	g := NewG1()
	p1 := g.Zero()
	for i := 0; i < 1000; i++ {
		vector := data[i*48 : (i+1)*48]
		p2, err := g.FromCompressed(vector)
		if err != nil {
			t.Fatal("decoing fails", err, i)
		}
		compressed := g.ToCompressed(p2)
		if !bytes.Equal(vector, compressed) || !g.Equal(p1, p2) {
			t.Fatal("bad serialization")
		}
		g.Add(p1, p1, &g1One)
	}
}

func TestG1MultiExpExpected(t *testing.T) {
	g := NewG1()
	one := g.one()
	var scalars [2]*big.Int
	var bases [2]*PointG1
	scalars[0] = big.NewInt(2)
	scalars[1] = big.NewInt(3)
	bases[0], bases[1] = new(PointG1).Set(one), new(PointG1).Set(one)
	expected, result := g.New(), g.New()
	g.MulScalar(expected, one, big.NewInt(5))
	_, _ = g.MultiExp(result, bases[:], scalars[:])
	if !g.Equal(expected, result) {
		t.Fatal("bad multi-exponentiation")
	}
}

func TestG1MultiExpBatch(t *testing.T) {
	g := NewG1()
	n := 1000
	bases := make([]*PointG1, n)
	scalars := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		bases[i] = g.rand()
		scalars[i], _ = rand.Int(rand.Reader, g.Q())
	}
	expected, tmp := g.New(), g.New()
	for i := 0; i < n; i++ {
		g.MulScalar(tmp, bases[i], scalars[i])
		g.Add(expected, expected, tmp)
	}
	result := g.New()
	_, _ = g.MultiExp(result, bases, scalars)
	if !g.Equal(expected, result) {
		t.Fatal("bad multi-exponentiation")
	}
}

func TestG1MapToCurve(t *testing.T) {
	for i, v := range []struct {
		u        []byte
		expected []byte
	}{
		{
			u: make([]byte, 48),
			expected: fromHex(-1,
				"11a9a0372b8f332d5c30de9ad14e50372a73fa4c45d5f2fa5097f2d6fb93bcac592f2e1711ac43db0519870c7d0ea415",
				"092c0f994164a0719f51c24ba3788de240ff926b55f58c445116e8bc6a47cd63392fd4e8e22bdf9feaa96ee773222133",
			),
		},
		{
			u: fromHex(-1, "07fdf49ea58e96015d61f6b5c9d1c8f277146a533ae7fbca2a8ef4c41055cd961fbc6e26979b5554e4b4f22330c0e16d"),
			expected: fromHex(-1,
				"1223effdbb2d38152495a864d78eee14cb0992d89a241707abb03819a91a6d2fd65854ab9a69e9aacb0cbebfd490732c",
				"0f925d61e0b235ecd945cbf0309291878df0d06e5d80d6b84aa4ff3e00633b26f9a7cb3523ef737d90e6d71e8b98b2d5",
			),
		},
		{
			u: fromHex(-1, "1275ab3adbf824a169ed4b1fd669b49cf406d822f7fe90d6b2f8c601b5348436f89761bb1ad89a6fb1137cd91810e5d2"),
			expected: fromHex(-1,
				"179d3fd0b4fb1da43aad06cea1fb3f828806ddb1b1fa9424b1e3944dfdbab6e763c42636404017da03099af0dcca0fd6",
				"0d037cb1c6d495c0f5f22b061d23f1be3d7fe64d3c6820cfcd99b6b36fa69f7b4c1f4addba2ae7aa46fb25901ab483e4",
			),
		},
		{
			u: fromHex(-1, "0e93d11d30de6d84b8578827856f5c05feef36083eef0b7b263e35ecb9b56e86299614a042e57d467fa20948e8564909"),
			expected: fromHex(-1,
				"15aa66c77eded1209db694e8b1ba49daf8b686733afaa7b68c683d0b01788dfb0617a2e2d04c0856db4981921d3004af",
				"0952bb2f61739dd1d201dd0a79d74cda3285403d47655ee886afe860593a8a4e51c5b77a22d2133e3a4280eaaaa8b788",
			),
		},
		{
			u: fromHex(-1, "015a41481155d17074d20be6d8ec4d46632a51521cd9c916e265bd9b47343b3689979b50708c8546cbc2916b86cb1a3a"),
			expected: fromHex(-1,
				"06328ce5106e837935e8da84bd9af473422e62492930aa5f460369baad9545defa468d9399854c23a75495d2a80487ee",
				"094bfdfe3e552447433b5a00967498a3f1314b86ce7a7164c8a8f4131f99333b30a574607e301d5f774172c627fd0bca",
			),
		},
	} {
		g := NewG1()
		p0, err := g.MapToCurve(v.u)
		if err != nil {
			t.Fatal("map to curve fails", i, err)
		}
		if !bytes.Equal(g.ToBytes(p0), v.expected) {
			t.Fatal("map to curve fails", i)
		}
	}
}

func TestG1EncodeToCurve(t *testing.T) {
	domain := []byte("BLS12381G1_XMD:SHA-256_SSWU_NU_TESTGEN")
	for i, v := range []struct {
		msg      []byte
		expected []byte
	}{
		{
			msg: []byte(""),
			expected: fromHex(-1,
				"1223effdbb2d38152495a864d78eee14cb0992d89a241707abb03819a91a6d2fd65854ab9a69e9aacb0cbebfd490732c",
				"0f925d61e0b235ecd945cbf0309291878df0d06e5d80d6b84aa4ff3e00633b26f9a7cb3523ef737d90e6d71e8b98b2d5",
			),
		},
		{
			msg: []byte("abc"),
			expected: fromHex(-1,
				"179d3fd0b4fb1da43aad06cea1fb3f828806ddb1b1fa9424b1e3944dfdbab6e763c42636404017da03099af0dcca0fd6",
				"0d037cb1c6d495c0f5f22b061d23f1be3d7fe64d3c6820cfcd99b6b36fa69f7b4c1f4addba2ae7aa46fb25901ab483e4",
			),
		},
		{
			msg: []byte("abcdef0123456789"),
			expected: fromHex(-1,
				"15aa66c77eded1209db694e8b1ba49daf8b686733afaa7b68c683d0b01788dfb0617a2e2d04c0856db4981921d3004af",
				"0952bb2f61739dd1d201dd0a79d74cda3285403d47655ee886afe860593a8a4e51c5b77a22d2133e3a4280eaaaa8b788",
			),
		},
		{
			msg: []byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			expected: fromHex(-1,
				"06328ce5106e837935e8da84bd9af473422e62492930aa5f460369baad9545defa468d9399854c23a75495d2a80487ee",
				"094bfdfe3e552447433b5a00967498a3f1314b86ce7a7164c8a8f4131f99333b30a574607e301d5f774172c627fd0bca",
			),
		},
	} {
		g := NewG1()
		p0, err := g.EncodeToCurve(sha256.New, v.msg, domain)
		if err != nil {
			t.Fatal("encode to point fails", i, err)
		}
		if !bytes.Equal(g.ToBytes(p0), v.expected) {
			t.Fatal("encode to point fails", i)
		}
	}
}

func TestG1HashToCurve(t *testing.T) {
	domain := []byte("BLS12381G1_XMD:SHA-256_SSWU_RO_TESTGEN")
	for i, v := range []struct {
		msg      []byte
		expected []byte
	}{
		{
			msg: []byte(""),
			expected: fromHex(-1,
				"0576730ab036cbac1d95b38dca905586f28d0a59048db4e8778782d89bff856ddef89277ead5a21e2975c4a6e3d8c79e",
				"1273e568bebf1864393c517f999b87c1eaa1b8432f95aea8160cd981b5b05d8cd4a7cf00103b6ef87f728e4b547dd7ae",
			),
		},
		{
			msg: []byte("abc"),
			expected: fromHex(-1,
				"061daf0cc00d8912dac1d4cf5a7c32fca97f8b3bf3f805121888e5eb89f77f9a9f406569027ac6d0e61b1229f42c43d6",
				"0de1601e5ba02cb637c1d35266f5700acee9850796dc88e860d022d7b9e7e3dce5950952e97861e5bb16d215c87f030d",
			),
		},
		{
			msg: []byte("abcdef0123456789"),
			expected: fromHex(-1,
				"0fb3455436843e76079c7cf3dfef75e5a104dfe257a29a850c145568d500ad31ccfe79be9ae0ea31a722548070cf98cd",
				"177989f7e2c751658df1b26943ee829d3ebcf131d8f805571712f3a7527ee5334ecff8a97fc2a50cea86f5e6212e9a57",
			),
		},
		{
			msg: []byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			expected: fromHex(-1,
				"0514af2137c1ae1d78d5cb97ee606ea142824c199f0f25ac463a0c78200de57640d34686521d3e9cf6b3721834f8a038",
				"047a85d6898416a0899e26219bca7c4f0fa682717199de196b02b95eaf9fb55456ac3b810e78571a1b7f5692b7c58ab6",
			),
		},
	} {
		g := NewG1()
		p0, err := g.HashToCurve(sha256.New, v.msg, domain)
		if err != nil {
			t.Fatal("hash to point fails", i, err)
		}
		if !bytes.Equal(g.ToBytes(p0), v.expected) {
			t.Fatal("hash to point fails", i)
		}
	}

	domain = []byte("QUUX-V01-CS02-with-expander")
	for i, v := range []struct {
		msg      []byte
		expected []byte
	}{
		{
			msg: []byte(""),
			expected: fromHex(-1,
				"140c7a6dbfff5ece70b651e951964551296f70efd3a72d64bd2c145f4469ba54840a4495f8ca4ee7a86dc25b83a54fde13871e80c7eaeb5af63ecf7e95ffa24b326ddab44cf1837ac3ba00bd7772c2b88e2f7d61271abdf84cd30deae9c0c798",
			),
		},
		{
			msg: []byte("abc"),
			expected: fromHex(-1,
				"10122323a3260d856bde2fc1662dc0fa863fda1abcd081fd932fb8cd01ff24b21af3900bd32d4e34558289b4c5d0cfc5129d3715ac3bb90229ec09e7649d2442f2991082d137072adfc664e185d879763f5c490cb261f8484c23872857bd16ce",
			),
		},
		{
			msg: []byte("abcdef0123456789"),
			expected: fromHex(-1,
				"00d6baa7c082c3bb02531bc329cfc6c00e04d32a0225faad568e081e5b761c1c9bc080020f88775e4eef90494f7f6b1719a8098791b3a8fa318a309bf84984bc32d435161df73c184c98a32351d39eb4c3a7236ad51ad28ef0151bcfcad66911",
			),
		},
		{
			msg: []byte("a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			expected: fromHex(-1,
				"1386c705ca91cefd5feb2cacb337c6beaaa2161937ebfbb2bf1838adfaac0c4922d674f0ed394f247c0d1b9befc8964d08fa7f130bd73137226438335797a20ebcf6d3699ac520aa0db1f9268865db330f36108fed71e6cf2c2f3651acb3e48a",
			),
		},
	} {
		g := NewG1()
		p0, err := g.HashToCurve(sha256.New, v.msg, domain)
		if err != nil {
			t.Fatal("hash to point fails", i, err)
		}
		if !bytes.Equal(g.ToBytes(p0), v.expected) {
			t.Fatalf("hash to point fails %d: expected: %v, got: %v", i, hex.EncodeToString(v.expected), hex.EncodeToString(g.ToBytes(p0)))
		}
	}
}

func TestCheckG1InfinityPoint(t *testing.T) {
	g1 := NewG1()
	// Zero is considered infinity point
	inf := g1.Zero()
	if !g1.InCorrectSubgroup(inf) {
		t.Fatal("infinity point not considered in subgroup")
	}
	if !g1.IsOnCurve(inf) {
		t.Fatal("infinity point not considered on curve")
	}

	zeroBytes := make([]byte, 96)
	infPoint, err := g1.FromBytes(zeroBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !g1.IsZero(infPoint) {
		t.Fatal("created point not inf point")
	}
}

func BenchmarkG1Add(t *testing.B) {
	g1 := NewG1()
	a, b, c := g1.rand(), g1.rand(), PointG1{}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		g1.Add(&c, a, b)
	}
}

func BenchmarkG1Mul(t *testing.B) {
	g1 := NewG1()
	a, e, c := g1.rand(), q, PointG1{}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		g1.MulScalar(&c, a, e)
	}
}

func BenchmarkG1MapToCurve(t *testing.B) {
	a := fromHex(48, "0x1234")
	g1 := NewG1()
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		_, err := g1.MapToCurve(a)
		if err != nil {
			t.Fatal(err)
		}
	}
}
