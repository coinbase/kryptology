//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Pedersen Verifiable Secret Sharing Scheme
type Pedersen struct {
	threshold, limit uint32
	generator        *curves.EcPoint
}

// PedersenResult contains all the data from calling Split
type PedersenResult struct {
	Blinding                     *big.Int
	BlindingShares, SecretShares []*ShamirShare
	BlindedVerifiers             []*ShareVerifier
	Verifiers                    []*ShareVerifier
}

// NewPedersen creates a new pedersen VSS
func NewPedersen(threshold, limit uint32, generator *curves.EcPoint) (*Pedersen, error) {
	if limit < threshold {
		return nil, fmt.Errorf("limit cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}

	if generator == nil {
		return nil, internal.ErrNilArguments
	}
	if generator.IsIdentity() {
		return nil, fmt.Errorf("generator point cannot be at infinity")
	}
	if !generator.IsOnCurve() {
		return nil, fmt.Errorf("generator point must be on the curve")
	}

	return &Pedersen{
		threshold, limit, generator,
	}, nil
}

// Split creates the verifiers, blinding and shares
func (pd Pedersen) Split(secret []byte) (*PedersenResult, error) {
	// generate a random blinding factor
	blinding, err := crand.Int(crand.Reader, pd.generator.Curve.Params().N)

	if err != nil {
		return nil, err
	}

	field := curves.NewField(pd.generator.Curve.Params().N)
	shamir := Shamir{pd.threshold, pd.limit, field}
	// split the secret into shares
	shares, polySecret, err := shamir.GetSharesAndPolynomial(secret)
	if err != nil {
		return nil, err
	}

	// split the blinding into shares
	blindingShares, polyBlinding, err := shamir.GetSharesAndPolynomial(blinding.Bytes())
	if err != nil {
		return nil, err
	}

	// Generate the verifiable commitments to the polynomial for the shares
	blindedverifiers := make([]*ShareVerifier, pd.threshold)
	verifiers := make([]*ShareVerifier, pd.threshold)

	// ({p0 * G + b0 * H}, ...,{pt * G + bt * H})
	for i, c := range polySecret.Coefficients {
		s, err := curves.NewScalarBaseMult(pd.generator.Curve, c.Value)
		if err != nil {
			return nil, err
		}
		b, err := pd.generator.ScalarMult(polyBlinding.Coefficients[i].Value)
		if err != nil {
			return nil, err
		}

		bv, err := s.Add(b)
		if err != nil {
			return nil, err
		}

		blindedverifiers[i] = bv
		verifiers[i] = s
	}
	return &PedersenResult{
		blinding, blindingShares, shares, blindedverifiers, verifiers,
	}, nil
}

// Combine recreates the original secret from the shares
func (pd Pedersen) Combine(shares ...*ShamirShare) ([]byte, error) {
	field := curves.NewField(pd.generator.Curve.Params().N)
	shamir := Shamir{pd.threshold, pd.limit, field}
	return shamir.Combine(shares...)
}

// Verify checks a share for validity
func (pd Pedersen) Verify(share *ShamirShare, blinding *ShamirShare, blindedverifiers []*ShareVerifier) (bool, error) {
	if len(blindedverifiers) < int(pd.threshold) {
		return false, fmt.Errorf("not enough blindedverifiers to check")
	}
	field := curves.NewField(pd.generator.Curve.Params().N)

	xBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(xBytes, share.Identifier)
	x := field.ElementFromBytes(xBytes)

	i := share.Value.Modulus.One()

	// c_0
	rhs := blindedverifiers[0]

	// Compute the sum of products
	// c_0 * c_1^i * c_2^{i^2} * c_3^{i^3} ... c_t^{i_t}
	for j := 1; j < len(blindedverifiers); j++ {
		// i *= x
		i = i.Mul(x)

		c, err := blindedverifiers[j].ScalarMult(i.Value)
		if err != nil {
			return false, err
		}

		// ... * c_j^{i^j}
		rhs, err = rhs.Add(c)
		if err != nil {
			return false, err
		}
	}

	lhs, err := curves.NewScalarBaseMult(pd.generator.Curve, share.Value.Value)
	if err != nil {
		return false, err
	}
	tmp, err := pd.generator.ScalarMult(blinding.Value.Value)
	if err != nil {
		return false, err
	}
	lhs, err = lhs.Add(tmp)
	if err != nil {
		return false, err
	}

	// Check if lhs == rhs
	return lhs.Equals(rhs), nil
}

// K256GeneratorFromHashedBytes computes a generator whose discrete log is unknown
// from a bytes sequence
func K256GeneratorFromHashedBytes(bytes []byte) (x, y *big.Int, err error) {
	pt := new(curves.PointK256).Hash(bytes)
	p, _ := pt.(*curves.PointK256)
	x = p.X().BigInt()
	y = p.Y().BigInt()
	err = nil
	return
}
