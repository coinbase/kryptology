//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// ShamirShare is the data from splitting a secret
type ShamirShare struct {
	// x-coordinate
	Identifier uint32 `json:"identifier"`
	// y-coordinate
	Value *curves.Element `json:"value"`
}

// NewShamirShare creates a ShamirShare given the Identifier, value, and Field for the value
func NewShamirShare(x uint32, y []byte, f *curves.Field) *ShamirShare {
	return &ShamirShare{
		Identifier: x,
		Value:      f.ElementFromBytes(y),
	}
}

// Bytes returns the representation of the share in bytes with the identifier as the first
// 4 bytes
func (s ShamirShare) Bytes() []byte {
	a := make([]byte, 4)
	binary.BigEndian.PutUint32(a, s.Identifier)
	a = append(a, s.Value.Bytes()...)
	return a
}

// Add returns the sum of two Shamir shares
func (s ShamirShare) Add(other *ShamirShare) *ShamirShare {
	if s.Identifier != other.Identifier {
		panic("identifiers must match for valid addition")
	}
	newSecret := s.Value.Add(other.Value)
	return NewShamirShare(s.Identifier, newSecret.Bytes(), s.Value.Field())
}

// Shamir is the Shamir secret sharing scheme
type Shamir struct {
	threshold, limit uint32
	field            *curves.Field
}

// NewShamir creates a Shamir secret sharing scheme
func NewShamir(threshold, limit int, field *curves.Field) (*Shamir, error) {
	if limit < threshold {
		return nil, fmt.Errorf("limit cannot be less than threshold")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	return &Shamir{
		uint32(threshold), uint32(limit), field,
	}, nil
}

// Split takes a secret and splits it into multiple shares that requires
// threshold to reconstruct
func (s *Shamir) Split(secret []byte) ([]*ShamirShare, error) {
	shares, _, err := s.GetSharesAndPolynomial(secret)
	return shares, err
}

// Combine takes any number of shares and tries to combine them into the original secret
func (s *Shamir) Combine(shares ...*ShamirShare) ([]byte, error) {
	if len(shares) < int(s.threshold) {
		return nil, fmt.Errorf("not enough shares to combine")
	}

	dups := make(map[uint32]bool)
	xCoordinates := make([]*curves.Element, s.threshold)
	yCoordinates := make([]*curves.Element, s.threshold)

	for i := 0; i < int(s.threshold); i++ {
		r := shares[i]
		if r.Identifier > s.limit || r.Identifier < 1 {
			return nil, fmt.Errorf("invalid share identifier")
		}
		if _, ok := dups[r.Identifier]; ok {
			return nil, fmt.Errorf("duplicate shares cannot be used")
		}

		xBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(xBytes, r.Identifier)
		xCoordinates[i] = s.field.ElementFromBytes(xBytes)
		yCoordinates[i] = r.Value
	}

	secret, err := s.Interpolate(xCoordinates, yCoordinates)
	if err != nil {
		return nil, err
	}
	return secret.Bytes(), nil
}

// getSharesAndPolynomial returns the shares for the specified secret and the polynomial
// used to create the shares
func (s *Shamir) GetSharesAndPolynomial(secret []byte) ([]*ShamirShare, *polynomial, error) {
	if len(secret) == 0 {
		return nil, nil, fmt.Errorf("cannot split an empty secret")
	}
	intSecret := new(big.Int).SetBytes(secret)
	if !s.field.IsValid(intSecret) {
		return nil, nil, fmt.Errorf("secret is too large")
	}

	elemSecret := s.field.NewElement(intSecret)
	poly, err := newPoly(elemSecret, s.threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate polynomial: %w", err)
	}

	shares := make([]*ShamirShare, s.limit)
	for i := uint32(0); i < s.limit; i++ {
		x := s.field.NewElement(big.NewInt(int64(i + 1)))
		y := poly.evaluate(x)
		shares[i] = &ShamirShare{
			Identifier: i + 1,
			Value:      y,
		}
	}
	return shares, &poly, nil
}

// interpolate calculates the lagrange interpolation
func (s *Shamir) Interpolate(xCoordinates, yCoordinates []*curves.Element) (*curves.Element, error) {
	if len(xCoordinates) < int(s.threshold) ||
		len(yCoordinates) < int(s.threshold) {
		return nil, fmt.Errorf("not enough points")
	}

	zero := xCoordinates[0].Field().Zero()
	result := yCoordinates[0].Field().Zero()

	for i := 0; i < int(s.threshold); i++ {
		basis := xCoordinates[0].Field().One()
		for j := 0; j < int(s.threshold); j++ {
			if i == j {
				continue
			}

			// x_m - x_j
			denom := xCoordinates[j].Sub(xCoordinates[i])
			if denom.IsEqual(zero) {
				return nil, fmt.Errorf("invalid x coordinates")
			}
			// x_m / x_m - x_j
			basis = basis.Mul(xCoordinates[j].Div(denom))
		}

		result = result.Add(yCoordinates[i].Mul(basis))
	}

	return result, nil
}

// ComputeL is a function that computes all Lagrange coefficients.
// This function is particularly needed in FROST tSchnorr signature.
func (s Shamir) ComputeL(shares ...*ShamirShare) ([]*curves.Element, error) {
	if len(shares) < int(s.threshold) {
		return nil, fmt.Errorf("Not enough shares to compute Lagrange coefficients")
	}
	dups := make(map[uint32]bool)
	xCoordinates := make([]*curves.Element, s.threshold)
	for i := 0; i < int(s.threshold); i++ {
		r := shares[i]
		if r.Identifier > s.limit || r.Identifier < 1 {
			return nil, fmt.Errorf("ComputeL: invalid share identifier")
		}
		if _, ok := dups[r.Identifier]; ok {
			return nil, fmt.Errorf("ComputeL: duplicate shares cannot be used")
		}

		xBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(xBytes, r.Identifier)
		xCoordinates[i] = s.field.ElementFromBytes(xBytes)
	}

	zero := xCoordinates[0].Field().Zero()
	result := make([]*curves.Element, s.threshold)

	for i := 0; i < int(s.threshold); i++ {
		basis := xCoordinates[0].Field().One()
		for j := 0; j < int(s.threshold); j++ {
			if i == j {
				continue
			}
			// x_m - x_j
			denom := xCoordinates[j].Sub(xCoordinates[i])
			if denom.IsEqual(zero) {
				return nil, fmt.Errorf("invalid x coordinates")
			}
			// x_m / x_m - x_j
			basis = basis.Mul(xCoordinates[j].Div(denom))
		}
		result[i] = basis
	}
	return result, nil
}
