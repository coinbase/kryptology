//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package proof

import (
	"math/big"

	"github.com/coinbase/kryptology/internal"
	core "github.com/coinbase/kryptology/pkg/core"
)

// inc computes the incremented commitment in the extension ring:
// (N+1)^\alpha * \beta^N  mod N^2
func inc(alpha, beta, n *big.Int) (*big.Int, error) {
	if core.AnyNil(n, alpha, beta) {
		return nil, internal.ErrNilArguments
	}
	np1 := new(big.Int).Add(n, core.One) // (N+1)
	nn, err := core.Mul(n, n, nil)       // N^2
	if err != nil {
		return nil, err
	}

	// It's pedersen commits all the way down :)
	return pedersen(np1, beta, alpha, n, nn) // (N+1)^\alpha * \beta^N  mod N^2
}

// Computes Pedersen's commitment: g^\alpha * h^beta (mod N~)
func pedersen(g, h, alpha, beta, n *big.Int) (*big.Int, error) {
	// Don't accept nil inputs
	if core.AnyNil(g, h, alpha, beta, n) {
		return nil, internal.ErrNilArguments
	}

	gAlpha, err := core.Exp(g, alpha, n) // g^alpha
	if err != nil {
		return nil, err
	}
	hBeta, err := core.Exp(h, beta, n) // h^beta
	if err != nil {
		return nil, err
	}

	// g^\alpha * h^beta (mod N)
	return core.Mul(gAlpha, hBeta, n)
}

// Computes Claus Schnorr's proof: xy+z \in Z
func schnorr(x, y, z *big.Int) (*big.Int, error) {
	// Don't accept nil inputs
	if core.AnyNil(x, y, z) {
		return nil, internal.ErrNilArguments
	}

	r, err := core.Mul(x, y, nil) // r = xy
	if err != nil {
		return nil, err
	}
	return r.Add(r, z), nil // r+z = xy+z
}
