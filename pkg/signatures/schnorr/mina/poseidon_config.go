//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
)

// SBox is the type of exponentiation to perform
type SBox int

const (
	Cube    = iota // x^3
	Quint          // x^5
	Sept           // x^7
	Inverse        // x^-1
)

// Exp mutates f by computing x^3, x^5, x^7 or x^-1 as described in
// https://eprint.iacr.org/2019/458.pdf page 8
func (sbox SBox) Exp(f *fp.Fp) {
	switch sbox {
	case Cube:
		t := new(fp.Fp).Square(f)
		f.Mul(t, f)
	case Quint:
		t := new(fp.Fp).Square(f)
		t.Square(t)
		f.Mul(t, f)
	case Sept:
		f2 := new(fp.Fp).Square(f)
		f4 := new(fp.Fp).Square(f2)
		t := new(fp.Fp).Mul(f2, f4)
		f.Mul(t, f)
	case Inverse:
		f.Invert(f)
	default:
	}
}

// Permutation is the permute function to use
type Permutation int

const (
	ThreeW = iota
	FiveW
	Three
)

// Permute executes the poseidon hash function
func (p Permutation) Permute(ctx *Context) {
	switch p {
	case ThreeW:
		for r := 0; r < ctx.fullRounds; r++ {
			ark(ctx, r)
			sbox(ctx)
			mds(ctx)
		}
		ark(ctx, ctx.fullRounds)
	case Three:
		fallthrough
	case FiveW:
		// Full rounds only
		for r := 0; r < ctx.fullRounds; r++ {
			sbox(ctx)
			mds(ctx)
			ark(ctx, r)
		}
	default:
	}
}

func ark(ctx *Context, round int) {
	for i := 0; i < ctx.spongeWidth; i++ {
		ctx.state[i].Add(ctx.state[i], ctx.roundKeys[round][i])
	}
}

func sbox(ctx *Context) {
	for i := 0; i < ctx.spongeWidth; i++ {
		ctx.sBox.Exp(ctx.state[i])
	}
}

func mds(ctx *Context) {
	state2 := make([]*fp.Fp, len(ctx.state))
	for i := range ctx.state {
		state2[i] = new(fp.Fp).SetZero()
	}
	for row := 0; row < ctx.spongeWidth; row++ {
		for col := 0; col < ctx.spongeWidth; col++ {
			t := new(fp.Fp).Mul(ctx.state[col], ctx.mdsMatrix[row][col])
			state2[row].Add(state2[row], t)
		}
	}
	for i, f := range state2 {
		ctx.state[i].Set(f)
	}
}

// NetworkType is which Mina network id to use
type NetworkType int

const (
	TestNet = iota
	MainNet
	NullNet
)
