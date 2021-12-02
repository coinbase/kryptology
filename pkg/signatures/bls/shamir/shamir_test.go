package shamir

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coinbase/kryptology/pkg/signatures/bls/finitefield"
)

// Ed25519 subgroup order
var modulus, _ = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)
var globalField = finitefield.New(modulus)
var dealer = NewDealer(globalField)
var combiner = NewCombiner(globalField)

func TestSplit_invalid_args(t *testing.T) {
	secret := []byte("test")

	if _, err := dealer.Split(secret, 0, 0); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := dealer.Split(secret, 3, 2); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := dealer.Split(secret, 3, 1000); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := dealer.Split(secret, 1, 10); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := dealer.Split(nil, 2, 3); err == nil {
		t.Fatalf("expect error")
	}

	if _, err := dealer.Split(secret, 256, 300); err == nil {
		t.Fatalf("expect error")
	}

	tooBigSecret := []byte("thisistoobig-thisistoobig-thisist")
	if _, err := dealer.Split(tooBigSecret, 2, 3); err == nil {
		t.Fatalf("expect error")
	}
}

func TestCombine_invalid(t *testing.T) {
	// No shares
	shares := []*Share{
		NewShare(1, []byte("b"), globalField),
	}
	_, err := combiner.Combine(shares)
	assert.Equal(t, "less than two shares cannot be used to reconstruct the secret", err.Error())

	// No secret
	shares = []*Share{
		NewShare(1, []byte(""), globalField),
		NewShare(2, []byte(""), globalField),
	}
	_, err = combiner.Combine(shares)
	assert.Equal(t, "share must have a non-zero length secret", err.Error())

	// Zero identifier
	shares = []*Share{
		NewShare(0, []byte("abc"), globalField),
		NewShare(2, []byte("abc"), globalField),
	}
	_, err = combiner.Combine(shares)
	assert.Equal(t, "share must have non-zero identifier", err.Error())

	// Duplicate shares
	shares = []*Share{
		NewShare(1, []byte("abc"), globalField),
		NewShare(1, []byte("abc"), globalField),
	}
	_, err = combiner.Combine(shares)
	assert.Equal(t, "duplicate share detected", err.Error())
}

func TestCombine_single(t *testing.T) {
	secret := []byte("hello")

	shareSet, err := dealer.Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	shares := shareSet.Shares
	parts := []*Share{shares[0], shares[1]}
	recomb, err := combiner.Combine(parts)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(recomb, secret) {
		t.Errorf("parts: %v", parts)
		t.Fatalf("bad: %v %v", recomb, secret)
	}
}

func TestCombine_all_permutations(t *testing.T) {
	secret := []byte("hello")

	shareSet, err := dealer.Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	shares := shareSet.Shares
	// There is 5*4*3 possible choices,
	// we will just brute force try them all
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if j == i {
				continue
			}
			for k := 0; k < 5; k++ {
				if k == i || k == j {
					continue
				}
				parts := []*Share{shares[i], shares[j], shares[k]}
				recomb, err := combiner.Combine(parts)
				if err != nil {
					t.Fatalf("err: %v", err)
				}

				if !bytes.Equal(recomb, secret) {
					t.Errorf("parts: (i:%d, j:%d, k:%d) %v", i, j, k, parts)
					t.Fatalf("bad: %v %v", recomb, secret)
				}
			}
		}
	}
}

func TestShare_Add(t *testing.T) {
	field := finitefield.New(big.NewInt(7))
	one := NewShare(0, []byte{0x01}, field)
	two := NewShare(0, []byte{0x02}, field)

	// basic addition
	sum := one.Add(two)
	assert.Equal(t, byte(0), sum.Identifier)
	assert.Equal(t, []byte{0x03}, sum.Secret.Bytes())

	// addition is performed within the globalField
	sum = two.Add(NewShare(0, []byte{0x06}, field))
	assert.Equal(t, byte(0), sum.Identifier)
	assert.Equal(t, []byte{0x01}, sum.Secret.Bytes())
}

func TestShare_Add_errors(t *testing.T) {
	field := finitefield.New(big.NewInt(7))
	one := NewShare(0, []byte{0x01}, field)
	two := NewShare(1, []byte{0x02}, field)

	assert.PanicsWithValue(t, "identifiers must match for valid addition", func() { one.Add(two) })
}

func TestCombine_added_shares(t *testing.T) {
	one := []byte{0x01}
	two := []byte{0x02}

	shareSet1, err := dealer.Split(one, 2, 3)
	assert.Nil(t, err)
	shareSet2, err := dealer.Split(two, 2, 3)
	assert.Nil(t, err)

	sharesForOne := shareSet1.Shares
	sharesForTwo := shareSet2.Shares

	share1 := sharesForOne[0].Add(sharesForTwo[0])
	share2 := sharesForOne[1].Add(sharesForTwo[1])
	shares := []*Share{share1, share2}

	recomb, err := combiner.Combine(shares)
	assert.Nil(t, err)
	assert.Equal(t, []byte{0x03}, recomb)
}

func TestPolynomial_SetsIntercept(t *testing.T) {
	intercept := globalField.NewElement(big.NewInt(42))
	p, err := NewDealer(globalField).makePolynomial(intercept, 2)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !p.Coefficients[0].IsEqual(intercept) {
		t.Fatalf("bad: %v", p.Coefficients)
	}
}

func TestPolynomial_Eval(t *testing.T) {
	intercept := globalField.NewElement(big.NewInt(42))
	p, err := NewDealer(globalField).makePolynomial(intercept, 1)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if out := p.evaluate(globalField.Zero()); !out.IsEqual(intercept) {
		t.Fatalf("bad: %v", out)
	}

	out := p.evaluate(globalField.One())
	exp := intercept.Add(p.Coefficients[1])
	if !out.IsEqual(exp) {
		t.Fatalf("bad: %v %v %v", out, exp, p.Coefficients)
	}
}

func TestInterpolate_Rand(t *testing.T) {
	var (
		f1 = globalField.NewElement(big.NewInt(1))
		f2 = globalField.NewElement(big.NewInt(2))
		f3 = globalField.NewElement(big.NewInt(3))
	)

	for i := 0; i < 256; i++ {
		intercept := globalField.NewElement(big.NewInt(int64(i)))
		p, err := dealer.makePolynomial(intercept, 2)
		if err != nil {
			t.Fatalf("err: %v", err)
		}

		xVals := []*finitefield.Element{f1, f2, f3}
		yVals := []*finitefield.Element{p.evaluate(f1), p.evaluate(f2), p.evaluate(f3)}
		out := combiner.interpolatePolynomial(xVals, yVals, globalField.Zero())
		if !out.IsEqual(intercept) {
			t.Fatalf("Bad: %v %d", out, i)
		}
	}
}
