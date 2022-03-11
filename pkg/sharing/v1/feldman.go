//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"crypto/elliptic"
	"encoding/binary"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Feldman Verifiable Secret Sharing Scheme
type Feldman struct {
	threshold, limit uint32
	curve            elliptic.Curve
}

// FeldmanResult contains all the data from calling Split
type FeldmanResult struct {
	SecretShares []*ShamirShare
	Verifiers    []*ShareVerifier
}

func NewFeldman(threshold, limit uint32, curve elliptic.Curve) (*Feldman, error) {
	if limit < threshold {
		return nil, fmt.Errorf("limit cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	return &Feldman{
		threshold, limit, curve,
	}, nil
}

func (f Feldman) Split(secret []byte) ([]*ShareVerifier, []*ShamirShare, error) {
	field := curves.NewField(f.curve.Params().N)
	shamir := Shamir{f.threshold, f.limit, field}
	shares, poly, err := shamir.GetSharesAndPolynomial(secret)
	if err != nil {
		return nil, nil, err
	}
	// Generate the verifiable commitments to the polynomial for the shares
	verifiers := make([]*ShareVerifier, len(poly.Coefficients))
	for i, c := range poly.Coefficients {
		v, err := curves.NewScalarBaseMult(f.curve, c.Value)
		if err != nil {
			return nil, nil, err
		}
		verifiers[i] = v
	}
	return verifiers, shares, nil
}

func (f Feldman) Combine(shares ...*ShamirShare) ([]byte, error) {
	field := curves.NewField(f.curve.Params().N)
	shamir := Shamir{f.threshold, f.limit, field}
	return shamir.Combine(shares...)
}

// Verify checks a share for validity
func (f Feldman) Verify(share *ShamirShare, verifiers []*ShareVerifier) (bool, error) {
	if len(verifiers) < int(f.threshold) {
		return false, fmt.Errorf("not enough verifiers to check")
	}
	field := curves.NewField(f.curve.Params().N)

	xBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(xBytes, share.Identifier)
	x := field.ElementFromBytes(xBytes)

	i := share.Value.Modulus.One()

	// c_0
	rhs := verifiers[0]

	// Compute the sum of products
	// c_0 * c_1^i * c_2^{i^2} * c_3^{i^3} ... c_t^{i_t}
	for j := 1; j < len(verifiers); j++ {
		// i *= x
		i = i.Mul(x)

		c, err := verifiers[j].ScalarMult(i.Value)
		if err != nil {
			return false, err
		}

		// ... * c_j^{i^j}
		rhs, err = rhs.Add(c)
		if err != nil {
			return false, err
		}
	}

	lhs, err := curves.NewScalarBaseMult(f.curve, share.Value.Value)
	if err != nil {
		return false, err
	}

	// Check if lhs == rhs
	return lhs.Equals(rhs), nil
}
