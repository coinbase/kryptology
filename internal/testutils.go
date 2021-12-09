//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package internal

import (
	"math/big"
	"testing"
)

// AssertNoError FailsNow() the test if err != nil
func AssertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("expected no error, but received: %v", err)
		t.FailNow()
	}
}

// AssertSomeError fails the test if err == nil
func AssertSomeError(t *testing.T, err error) {
	if err == nil {
		t.Errorf("expected an error, but received none")
	}
}

// AssertError fails the test if err == nil or the message does not equal msg
func AssertError(t *testing.T, err error, msg string) {
	if err == nil {
		t.Errorf("expected an error, but received none")
		return
	}

	if err.Error() != msg {
		t.Errorf("expected error with messge: \"%s\", got: \"%s\"", msg, err.Error())
	}
}

// AssertBigIntEq fails the test if a and b are not equal
func AssertBigIntEq(t *testing.T, a, b *big.Int) {
	// Bail out on nil values to avoid panic
	if a == nil || b == nil {
		t.Errorf("cannot compare nil values")
		return
	}

	if a.Cmp(b) != 0 {
		t.Errorf("%v != %v", a, b)
	}
}

// AssertBigIntNe fails the test if two big.Ints are the same value
func AssertBigIntNe(t *testing.T, a, b *big.Int) {
	// Bail out on nil values to avoid panic
	if a == nil || b == nil {
		t.Errorf("cannot compare nil values")
		return
	}

	if a.Cmp(b) == 0 {
		t.Errorf("%v == %v", a, b)
	}
}

// AssertNotNil fails if any values are nil
func AssertNotNil(t *testing.T, values ...*big.Int) {
	for _, x := range values {
		if x == nil {
			t.Errorf("result should not be nil")
		}
	}
}

// AssertNil fails the test if any of values are nil
func AssertNil(t *testing.T, values ...*big.Int) {
	for _, x := range values {
		if x != nil {
			t.Errorf("result should be nil")
		}
	}
}

// B10 creating a big.Int from a base 10 string. panics on failure to
// ensure zero-values aren't used in place of malformed strings.
func B10(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("Couldn't derive big.Int from string")
	}
	return x
}
