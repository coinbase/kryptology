//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls12381

import (
	"github.com/stretchr/testify/assert"
	"math/bits"
	mrand "math/rand"
	"testing"
)

func TestFieldElementAdd(t *testing.T) {
	for i := 0; i < 25; i++ {
		a := new(fe)
		z := new(fe)
		x := new(fe)
		y := new(fe)

		x[0] = mrand.Uint64()
		x[1] = mrand.Uint64()
		x[2] = mrand.Uint64()
		x[3] = mrand.Uint64()

		y[0] = mrand.Uint64()
		y[1] = mrand.Uint64()
		y[2] = mrand.Uint64()
		y[3] = mrand.Uint64()
		newAdd(z, x, y)
		oldAdd(a, x, y)
		assert.Equal(t, z, a)
	}
}

func newAdd(z, x, y *fe) {
	var carry uint64

	z[0], carry = bits.Add64(x[0], y[0], 0)
	z[1], carry = bits.Add64(x[1], y[1], carry)
	z[2], carry = bits.Add64(x[2], y[2], carry)
	z[3], carry = bits.Add64(x[3], y[3], carry)
	z[4], carry = bits.Add64(x[4], y[4], carry)
	z[5], _ = bits.Add64(x[5], y[5], carry)

	setZConstantTime(z)
}

func setZConstantTime(z *fe) {
	// Get q as fe
	q := &fe{
		13402431016077863595,
		2210141511517208575,
		7435674573564081700,
		7239337960414712511,
		5412103778470702295,
		1873798617647539866,
	}

	// if z > q -> 1
	// if z < q -> -1
	// if z == q -> 0
	cmpZQ := z.cmp(q)
	// twiddle cmpZQ st 1 --> 1, {-1,0} --> 0
	flag := ^((cmpZQ - 1) >> 31) & 1

	// z-q
	zPrime := &fe{}
	var b uint64
	zPrime[0], b = bits.Sub64(z[0], q[0], 0)
	zPrime[1], b = bits.Sub64(z[1], q[1], b)
	zPrime[2], b = bits.Sub64(z[2], q[2], b)
	zPrime[3], b = bits.Sub64(z[3], q[3], b)
	zPrime[4], b = bits.Sub64(z[4], q[4], b)
	zPrime[5], _ = bits.Sub64(z[5], q[5], b)

	z.cmove(uint(flag), zPrime)
}

func oldAdd(z, x, y *fe) {
	var carry uint64

	z[0], carry = bits.Add64(x[0], y[0], 0)
	z[1], carry = bits.Add64(x[1], y[1], carry)
	z[2], carry = bits.Add64(x[2], y[2], carry)
	z[3], carry = bits.Add64(x[3], y[3], carry)
	z[4], carry = bits.Add64(x[4], y[4], carry)
	z[5], _ = bits.Add64(x[5], y[5], carry)

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[5] < 1873798617647539866 || (z[5] == 1873798617647539866 && (z[4] < 5412103778470702295 || (z[4] == 5412103778470702295 && (z[3] < 7239337960414712511 || (z[3] == 7239337960414712511 && (z[2] < 7435674573564081700 || (z[2] == 7435674573564081700 && (z[1] < 2210141511517208575 || (z[1] == 2210141511517208575 && (z[0] < 13402431016077863595))))))))))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 13402431016077863595, 0)
		z[1], b = bits.Sub64(z[1], 2210141511517208575, b)
		z[2], b = bits.Sub64(z[2], 7435674573564081700, b)
		z[3], b = bits.Sub64(z[3], 7239337960414712511, b)
		z[4], b = bits.Sub64(z[4], 5412103778470702295, b)
		z[5], _ = bits.Sub64(z[5], 1873798617647539866, b)
	}
}

func TestFieldElementSub(t *testing.T) {
	for i := 0; i < 25; i++ {
		a := new(fe)
		z := new(fe)
		x := new(fe)
		y := new(fe)

		x[0] = mrand.Uint64()
		x[1] = mrand.Uint64()
		x[2] = mrand.Uint64()
		x[3] = mrand.Uint64()

		y[0] = mrand.Uint64()
		y[1] = mrand.Uint64()
		y[2] = mrand.Uint64()
		y[3] = mrand.Uint64()
		newSub(z, x, y)
		oldSub(a, x, y)
		assert.Equal(t, z, a)
	}
}

func oldSub(z, x, y *fe) {
	var b uint64
	z[0], b = bits.Sub64(x[0], y[0], 0)
	z[1], b = bits.Sub64(x[1], y[1], b)
	z[2], b = bits.Sub64(x[2], y[2], b)
	z[3], b = bits.Sub64(x[3], y[3], b)
	z[4], b = bits.Sub64(x[4], y[4], b)
	z[5], b = bits.Sub64(x[5], y[5], b)
	if b != 0 {
		var c uint64
		z[0], c = bits.Add64(z[0], 13402431016077863595, 0)
		z[1], c = bits.Add64(z[1], 2210141511517208575, c)
		z[2], c = bits.Add64(z[2], 7435674573564081700, c)
		z[3], c = bits.Add64(z[3], 7239337960414712511, c)
		z[4], c = bits.Add64(z[4], 5412103778470702295, c)
		z[5], _ = bits.Add64(z[5], 1873798617647539866, c)
	}
}

func newSub(z, x, y *fe) {
	var b uint64
	z[0], b = bits.Sub64(x[0], y[0], 0)
	z[1], b = bits.Sub64(x[1], y[1], b)
	z[2], b = bits.Sub64(x[2], y[2], b)
	z[3], b = bits.Sub64(x[3], y[3], b)
	z[4], b = bits.Sub64(x[4], y[4], b)
	z[5], b = bits.Sub64(x[5], y[5], b)

	setZConstantTimeSub(z, b)
}

func setZConstantTimeSub(z *fe, b uint64) {
	// Get cmove flag based off of b
	bIsZero := b == 0
	isZeroToMap := make(map[bool]uint)
	isZeroToMap[true] = 0
	isZeroToMap[false] = 1

	flag := isZeroToMap[bIsZero]

	// To set if B is not Zero
	zPrime := &fe{}
	var c uint64
	zPrime[0], c = bits.Add64(z[0], 13402431016077863595, 0)
	zPrime[1], c = bits.Add64(z[1], 2210141511517208575, c)
	zPrime[2], c = bits.Add64(z[2], 7435674573564081700, c)
	zPrime[3], c = bits.Add64(z[3], 7239337960414712511, c)
	zPrime[4], c = bits.Add64(z[4], 5412103778470702295, c)
	zPrime[5], _ = bits.Add64(z[5], 1873798617647539866, c)

	// Move zPrime into z if flag
	z.cmove(flag, zPrime)
}

func TestFieldElementNeg(t *testing.T) {
	for i := 0; i < 25; i++ {
		a := new(fe)
		z := new(fe)
		x := new(fe)

		x[0] = mrand.Uint64()
		x[1] = mrand.Uint64()
		x[2] = mrand.Uint64()
		x[3] = mrand.Uint64()

		newNeg(z, x)
		oldNeg(a, x)
		assert.Equal(t, z, a)
	}
}

func oldNeg(z *fe, x *fe) {
	if x.isZero() {
		z.zero()
		return
	}
	var borrow uint64
	z[0], borrow = bits.Sub64(13402431016077863595, x[0], 0)
	z[1], borrow = bits.Sub64(2210141511517208575, x[1], borrow)
	z[2], borrow = bits.Sub64(7435674573564081700, x[2], borrow)
	z[3], borrow = bits.Sub64(7239337960414712511, x[3], borrow)
	z[4], borrow = bits.Sub64(5412103778470702295, x[4], borrow)
	z[5], _ = bits.Sub64(1873798617647539866, x[5], borrow)
}

func newNeg(z *fe, x *fe) {
	var borrow uint64
	z[0], borrow = bits.Sub64(13402431016077863595, x[0], 0)
	z[1], borrow = bits.Sub64(2210141511517208575, x[1], borrow)
	z[2], borrow = bits.Sub64(7435674573564081700, x[2], borrow)
	z[3], borrow = bits.Sub64(7239337960414712511, x[3], borrow)
	z[4], borrow = bits.Sub64(5412103778470702295, x[4], borrow)
	z[5], _ = bits.Sub64(1873798617647539866, x[5], borrow)

	isZeroToMap := make(map[bool]uint)
	isZeroToMap[true] = 1
	isZeroToMap[false] = 0

	flag := isZeroToMap[x.isZero()]
	zPrime := &fe{}
	zPrime.zero()

	z.cmove(flag, zPrime)
}
