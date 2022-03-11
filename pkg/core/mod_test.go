//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package core

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/internal"
)

var (
	four = big.NewInt(4)

	// Large numbers for testing -- computing with independent tooling
	// x,y 100-digit numbers
	x, _     = new(big.Int).SetString("7146643783615963513942641287213372249533955323510461217840179896547799100626220786140425637990097431", 10)
	y, _     = new(big.Int).SetString("1747698065194620177681258504464368264357359841192790848951902311522815739310792522712583635858354245", 10)
	sumxy, _ = new(big.Int).SetString("8894341848810583691623899791677740513891315164703252066792082208070614839937013308853009273848451676", 10)
	xy, _    = new(big.Int).SetString("12490175513260779219420155073726764321605372267033815716483640700978475653623775696463227582174703069158832890348206546318843052423532258178885792744599932977235221784868792263260215861775082862444595", 10)

	// 101-digit modulus
	m, _ = new(big.Int).SetString("85832751158419329546684678412285185885848111422509523329716452068504806021136687603399722116388773253", 10)

	// 99-digit modulus
	n, _ = new(big.Int).SetString("604464499356780653111583485887412477603580949137220100557796699530113283915988830359783807274682723", 10)
)

func TestConstantTimeEqByteSound(t *testing.T) {
	hundoDigit := internal.B10("3593421565679030456559622742114065111786271367498220644136232358421457354322411370928949366452183472")
	tests := []struct {
		name     string
		a, b     *big.Int
		expected byte
	}{
		{"positive: 5", internal.B10("5"), internal.B10("5"), 1},
		{"positive: 100", internal.B10("100"), internal.B10("100"), 1},
		{"positive: -1204", internal.B10("-1204"), internal.B10("-1204"), 1},
		{"positive: 100 digits", hundoDigit, hundoDigit, 1},
		{"positive: 0", internal.B10("0"), internal.B10("0"), 1},
		{"positive: 0/-0", internal.B10("0"), internal.B10("-0"), 1},
		{"positive: -0/-0", internal.B10("-0"), internal.B10("-0"), 1},

		{"negative: 5/-5", internal.B10("5"), internal.B10("-5"), 0},
		{"negative: 5/500", internal.B10("5"), internal.B10("500"), 0},
		{"negative: 100/100 digit", internal.B10("100"), hundoDigit, 0},
		{"negative: -1204/-5", internal.B10("-1204"), internal.B10("-15"), 0},
		{"negative: 0/-5 digits", internal.B10("0"), internal.B10("-5"), 0},
	}
	// Run all the tests!
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := ConstantTimeEqByte(test.a, test.b)
			require.Equal(t, test.expected, actual)
		})
	}
}

func TestConstantTimeEqSound(t *testing.T) {
	hundoDigit := internal.B10("3593421565679030456559622742114065111786271367498220644136232358421457354322411370928949366452183472")
	tests := []struct {
		name     string
		a, b     *big.Int
		expected bool
	}{
		{"positive: 5", internal.B10("5"), internal.B10("5"), true},
		{"positive: 100", internal.B10("100"), internal.B10("100"), true},
		{"positive: -1204", internal.B10("-1204"), internal.B10("-1204"), true},
		{"positive: 100 digits", hundoDigit, hundoDigit, true},
		{"positive: 0", internal.B10("0"), internal.B10("0"), true},
		{"positive: 0/-0", internal.B10("0"), internal.B10("-0"), true},
		{"positive: -0/-0", internal.B10("-0"), internal.B10("-0"), true},

		{"negative: 5/-5", internal.B10("5"), internal.B10("-5"), false},
		{"negative: 5/500", internal.B10("5"), internal.B10("500"), false},
		{"negative: 100/100 digit", internal.B10("100"), hundoDigit, false},
		{"negative: -1204/-5", internal.B10("-1204"), internal.B10("-15"), false},
		{"negative: 0/-5 digits", internal.B10("0"), internal.B10("-5"), false},
	}
	// Run all the tests!
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := ConstantTimeEq(test.a, test.b)
			require.Equal(t, test.expected, actual)
		})
	}
}

// Ring membership tests
func TestIn(t *testing.T) {
	// Some large numbers for testing
	x, _ := new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	y, _ := new(big.Int).SetString("32168432167132168106409840321684604654063138460840123871234181628904319728058", 10)
	N := new(big.Int).Mul(x, y)  // N = xy
	NN := new(big.Int).Mul(N, N) // N^2 = N*N = x^2y^2
	errMember := internal.ErrZmMembership

	var tests = []struct {
		x        *big.Int
		m        *big.Int
		expected error
	}{
		//
		// Completist test for: Z_4
		//
		// Too small:  -x ∉ Z_4, \forall \x \in \N
		{big.NewInt(-4), four, errMember},
		{big.NewInt(-3), four, errMember},
		{big.NewInt(-2), four, errMember},
		{big.NewInt(-1), four, errMember},

		// Just right: {0,1,2,3} = Z_4
		{big.NewInt(0), four, nil},
		{big.NewInt(1), four, nil},
		{big.NewInt(2), four, nil},
		{big.NewInt(3), four, nil},

		// Too big: {4,5,6,7} ∉ Z_4
		{big.NewInt(4), four, errMember},
		{big.NewInt(5), four, errMember},
		{big.NewInt(6), four, errMember},
		{big.NewInt(7), four, errMember},

		//
		// Large numbers
		//
		// x,y,N < N^2
		{x, NN, nil},
		{y, NN, nil},
		{N, NN, nil},

		// N+x,N+y,2N < N^2 ⇒ x ∈ Z_N^2
		{big.NewInt(0).Add(N, x), NN, nil},
		{big.NewInt(0).Add(N, y), NN, nil},
		{big.NewInt(0).Add(N, N), NN, nil},

		// Nx,Ny < N^2 ⇒ x ∈ Z_N^2
		{big.NewInt(0).Mul(N, x), NN, nil},
		{big.NewInt(0).Mul(N, y), NN, nil},

		// -x,-y,-N ∉ Z_N^2
		{big.NewInt(0).Neg(x), NN, errMember},
		{big.NewInt(0).Neg(y), NN, errMember},
		{big.NewInt(0).Neg(N), NN, errMember},

		// N^2 ∉ Z_N^2
		{NN, NN, errMember},
	}

	// All the tests!
	for _, test := range tests {
		actual := In(test.x, test.m)
		require.Equal(t, test.expected, actual)
	}
}

// Tests for modular addition with known answers
func TestAdd(t *testing.T) {
	// Pre-compute some values
	sumXyModn, err := Add(x, y, n)
	require.Nil(t, err)

	var tests = []struct {
		x, y, m, expected *big.Int // inputs: x,y,m
	}{
		// Small number tests
		{big.NewInt(-1), big.NewInt(1), four, big.NewInt(0)},
		{big.NewInt(2), big.NewInt(1), four, big.NewInt(3)},
		{big.NewInt(0), big.NewInt(2), four, big.NewInt(2)},
		{big.NewInt(2), big.NewInt(4), four, big.NewInt(2)},
		{big.NewInt(15), big.NewInt(15), four, big.NewInt(2)},

		// Large number tests
		{x, y, m, sumxy},
		{y, x, m, sumxy},

		// Large number Zero tests
		{Zero, x, m, x},
		{x, Zero, m, x},
		{Zero, y, m, y},
		{y, Zero, m, y},

		// Commutative
		{x, y, m, sumxy},
		{y, x, m, sumxy},
		{x, y, n, sumXyModn},
		{y, x, n, sumXyModn},
		{sumXyModn, Zero, n, sumXyModn},
		{Zero, sumXyModn, n, sumXyModn},
	}
	// All the tests!
	for _, test := range tests {
		actual, err := Add(test.x, test.y, test.m)
		require.NoError(t, err)
		require.Zero(t, actual.Cmp(test.expected))
	}
}

// Tests for modular addition according to known invariants
func TestAddInvariants(t *testing.T) {
	inputs := []*big.Int{x, y, Zero, One, new(big.Int).Neg(x), new(big.Int).Neg(y)}
	moduli := []*big.Int{m, n, big.NewInt(10001)}

	// Run all combinations of the inputs/moduli
	for _, x := range inputs {
		for _, y := range inputs {
			for _, m := range moduli {

				// Addition is commutative
				z0, err := Add(x, y, m)
				require.NoError(t, err)
				z1, err := Add(y, x, m)
				require.NoError(t, err)
				require.Equal(t, z0, z1)

				// Addition is transitive: x+x+y == y+x+x == x+y+x
				a0, _ := Add(x, x, m)
				a0, _ = Add(a0, y, m)

				a1, _ := Add(y, x, m)
				a1, _ = Add(a1, x, m)

				a2, _ := Add(x, y, m)
				a2, _ = Add(a2, x, m)

				require.Equal(t, a0, a1)
				require.Equal(t, a1, a2)
			}
		}
	}
}

// Tests modular multiplication with known answers
func TestMul(t *testing.T) {
	// Pre-compute some values
	xyModm := new(big.Int).Mod(xy, m)

	var tests = []struct {
		x, y, m, expected *big.Int // inputs: x,y,m
	}{
		// Small number tests
		{big.NewInt(-1), big.NewInt(1), four, big.NewInt(3)},
		{big.NewInt(2), big.NewInt(1), four, big.NewInt(2)},
		{big.NewInt(0), big.NewInt(2), four, big.NewInt(0)},
		{big.NewInt(2), big.NewInt(4), four, big.NewInt(0)},
		{big.NewInt(15), big.NewInt(15), four, big.NewInt(1)},

		// Large number tests
		{x, y, m, xyModm},
		{y, x, m, xyModm},

		// Large number Zero tests
		{Zero, x, m, Zero},
		{x, Zero, m, Zero},
		{Zero, y, n, Zero},
	}
	// All the tests!
	for _, test := range tests {
		z, err := Mul(test.x, test.y, test.m)
		require.NoError(t, err)
		require.Zero(t, z.Cmp(test.expected))
	}
}

// Tests for modular multiplication according to known invariants
func TestMulInvariants(t *testing.T) {
	inputs := []*big.Int{x, y, Zero, One, new(big.Int).Neg(x), new(big.Int).Neg(y)}
	moduli := []*big.Int{m, n, big.NewInt(10001)}

	// Run all combinations of the inputs/moduli
	for _, x := range inputs {
		for _, y := range inputs {
			for _, m := range moduli {

				// Mul is commutative
				a, err := Mul(x, y, m)
				require.NoError(t, err)
				aʹ, err := Mul(y, x, m)
				require.NoError(t, err)
				require.Equal(t, a, aʹ)

				// Mul is transitive: (xx)y == (xy)x
				z, _ := Mul(x, x, m)
				z, _ = Mul(z, y, m)

				zʹ, _ := Mul(x, y, m)
				zʹ, _ = Mul(zʹ, x, m)
				require.Equal(t, z, zʹ)
			}
		}
	}
}

// Tests modular negation with known answers
func TestNeg(t *testing.T) {
	var tests = []struct {
		x, m, e *big.Int
	}{
		{big.NewInt(1), big.NewInt(7), big.NewInt(6)},
		{big.NewInt(2), big.NewInt(7), big.NewInt(5)},
		{big.NewInt(3), big.NewInt(7), big.NewInt(4)},
		{big.NewInt(4), big.NewInt(7), big.NewInt(3)},
		{big.NewInt(5), big.NewInt(7), big.NewInt(2)},
		{big.NewInt(6), big.NewInt(7), big.NewInt(1)},

		{big.NewInt(-1), big.NewInt(7), big.NewInt(1)},
		{big.NewInt(-2), big.NewInt(7), big.NewInt(2)},
		{big.NewInt(-3), big.NewInt(7), big.NewInt(3)},
		{big.NewInt(-4), big.NewInt(7), big.NewInt(4)},
		{big.NewInt(-5), big.NewInt(7), big.NewInt(5)},
		{big.NewInt(-6), big.NewInt(7), big.NewInt(6)},

		{big.NewInt(8), big.NewInt(7), big.NewInt(6)},
		{big.NewInt(9), big.NewInt(7), big.NewInt(5)},
		{big.NewInt(10), big.NewInt(7), big.NewInt(4)},
		{big.NewInt(11), big.NewInt(7), big.NewInt(3)},
		{big.NewInt(12), big.NewInt(7), big.NewInt(2)},
		{big.NewInt(13), big.NewInt(7), big.NewInt(1)},
	}

	for _, test := range tests {
		r, err := Neg(test.x, test.m)
		require.NoError(t, err)
		if r.Cmp(test.e) != 0 {
			t.Errorf("TestNeg failed. Expected %v, got: %v ", test.e, r)
		}
	}
}

func TestNegInvariants(t *testing.T) {
	var tests = []struct {
		x, m, e *big.Int
	}{
		{big.NewInt(0), big.NewInt(7), big.NewInt(0)},
		{big.NewInt(7), big.NewInt(7), big.NewInt(0)},
		{big.NewInt(-7), big.NewInt(7), big.NewInt(0)},
	}

	for _, test := range tests {
		r, err := Neg(test.x, test.m)
		require.NoError(t, err)
		if r.Cmp(test.e) != 0 {
			t.Errorf("TestNeg failed. Expected %v, got: %v ", test.e, r)
		}
	}
}

// Simple test for distinct Rand output
func TestRandDistinct(t *testing.T) {
	// Each value should be distinct
	a, _ := Rand(n)
	b, _ := Rand(n)
	c, _ := Rand(n)

	// ❄️❄️❄️
	require.NotEqual(t, a, b)
	require.NotEqual(t, a, c)
	require.NotEqual(t, b, c)
}

// Rand values should be O(log2(m)) bits
func TestRandIsExpectedLength(t *testing.T) {
	trials := 1000
	max := big.NewInt(-1)

	// Generate many nonces, keep the max
	for i := 0; i < trials; i++ {
		r, err := Rand(m)
		require.NoError(t, err)

		// Nonces should be < m
		if r.Cmp(m) != -1 {
			t.Errorf("nonce too large, require %v < %v", r, m)
		}

		if r.Cmp(max) == 1 {
			max = r
		}
	}

	// With high probability, the max nonce should be very close N
	lowerBound := new(big.Int).Rsh(m, 1)
	if max.Cmp(lowerBound) == -1 {
		t.Errorf("Expected max nonce: %v > %v", max, lowerBound)
	}
}

// Randomly selected nonces with a large modulus will be unique with overwhelming probability
func TestRandDistinctWithLargeModulus(t *testing.T) {
	const iterations = 1000
	testUnique(t, iterations, func() *big.Int {
		r, _ := Rand(m)
		return r
	})
}

// Calls sampleFunc() n times and asserts that the lower 64B of each output are unique.
func testUnique(t *testing.T, iterations int, sampleFunc func() *big.Int) {
	// For simplicity, we test only the lower 64B of each nonce. This is sufficient
	// to prove uniqueness and go-lang doesn't hash slices (no slices in maps)
	const size = 256 / 8
	seen := make(map[[size]byte]bool)
	var x [size]byte

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Retrieve a sample
		sample := sampleFunc()
		require.NotNil(t, sample)

		// Copy the bytes from slice>array
		copy(x[:], sample.Bytes())

		// Ensure each sample is unique
		if seen[x] {
			t.Errorf("duplicate sample found: %v", x)
		}
		seen[x] = true
	}
}

// Ensure Rand never returns 0 or 1.
func TestRandNotZeroNotOne(t *testing.T) {
	// Test for non-zero only useful when iterations >> |Z_m|
	const iterations = 1000
	m := big.NewInt(5)

	for i := 0; i < iterations; i++ {
		r, err := Rand(m)
		require.NoError(t, err)
		// Not 0 or 1
		require.NotEqual(t, r, Zero)
		require.NotEqual(t, r, One)
	}
}

func TestRand_NilModulusErrors(t *testing.T) {
	r, err := Rand(nil)
	require.Nil(t, r)
	require.Contains(t, err.Error(), internal.ErrNilArguments.Error())
}

// Double-inverse is the identity function in fields
func TestInvRoundTrip(t *testing.T) {
	m := internal.B10("1031") // Prime-order modulus

	for _, a := range []*big.Int{
		internal.B10("500"),
		internal.B10("-500"),
		internal.B10("1"),
		internal.B10("1030"),
	} {
		// Our expected value is the modular reduction of the test value
		expected := a.Mod(a, m)

		// Invert and check
		aInv, err := Inv(a, m)
		require.NoError(t, err, "a=%v", a)
		require.NotNil(t, aInv)

		// Invert again and check
		a_, err := Inv(aInv, m)
		if err != nil {
			require.Equal(t, expected, a_)
		}
	}
}

// Tests values for which there is no inverse in the given field
func TestInvNotFound(t *testing.T) {
	m := internal.B10("1024") // m = 2^10
	// 0 and even numbers will not have inverse in this ring

	for _, a := range []*big.Int{
		internal.B10("500"),
		internal.B10("-500"),
		internal.B10("0"),
		internal.B10("1024"),
		internal.B10("512"),
		internal.B10("300000000"),
	} {
		// Invert and check
		aInv, err := Inv(a, m)
		require.Error(t, err, "a=%v", a)
		require.Nil(t, aInv)
	}
}

func TestExpKnownAnswer(t *testing.T) {
	p := internal.B10("1031") // prime-order field
	pMinus1 := internal.B10("1030")
	tests := []struct {
		name     string
		x, e, m  *big.Int
		expected *big.Int
	}{
		{"fermat's little thm: 500", internal.B10("500"), p, p, internal.B10("500")},
		{"fermat's little thm (p-1): 500", internal.B10("500"), pMinus1, p, One},
		{"fermat's little thm (p-1): 5000", internal.B10("5000"), pMinus1, p, One},
		{"399^0 = 1", internal.B10("399"), Zero, p, One},
		{"673^1 = 673", internal.B10("673"), One, p, internal.B10("673")},
	}

	// Run all the tests!
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := Exp(test.x, test.e, test.m)
			if err != nil {
				require.Equal(t, test.expected, actual)
			}
		})
	}
}

// A product of two 1024b safe primes
var N1024 = internal.B10("22657252520748253292205422817162431301953923432914829530688424232913850279325496327198502914522231560238552529734156383924448818535517634061008476071362010781638360092704508943571866960229942049437914690556866055765377519627454975682400206932320319743805083072214857842762721537739950074695623974079312071498296625705376593890814889314744719469735809152488403143751157723139035869185892099006348653635981206799193781030834368833947197930944812082594326193527332208252230115672713914945889734620959932802893197325106135662762752470236627025599443912886530954179753873735786171937758916890000958846322096261981191349917")

// A product of two 256b safe primes
var N256 = internal.B10("10815068324662993508164204692909269429257853772524581783499643160896147777579932560873002543907262462663453338979819981987639157192530671167315407970757417")

func Benchmark_rand1024(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}

	for i := 0; i < b.N; i++ {
		Rand(N1024) // nolint
	}
}

func BenchmarkRand1024(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}

	for i := 0; i < b.N; i++ {
		Rand(N1024) // nolint
	}
}

func Benchmark_rand256(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}

	for i := 0; i < b.N; i++ {
		Rand(N256) // nolint
	}
}

func BenchmarkRandStar256(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping test in short mode.")
	}

	for i := 0; i < b.N; i++ {
		Rand(N256) // nolint
	}
}
