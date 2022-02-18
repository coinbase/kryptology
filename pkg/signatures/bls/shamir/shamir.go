//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package shamir is kept for legacy reasons, for our implementation of shamir secret sharing,
// checkout "pkg/sharing/shamir.go".
//
// Originally, this was a port of the hashicorp/vault implementation of Shamir's Secret Sharing
// which has been modified to work with a finite field rather than arbitrary length content.
//
// Their implementation splits every byte independently into shares and transposes the output
// together to form a single secret. For our purposes, we expect to be able to combine secrets using
// addition and then reconstruct a shared polynomial which doesn't work with the byte wise sharing.
//
// This implementation IS NOT constant time as it leverages math/big for big number operations through the finitefield
// package.
package shamir

import (
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/pkg/signatures/bls/finitefield"
	"github.com/pkg/errors"
)

// Polynomial represents a polynomial of arbitrary degree
type Polynomial struct {
	Coefficients []*finitefield.Element
}

// Dealer knows the secret and constructs the polynomial
type Dealer struct {
	field *finitefield.Field
}

// Combiner reconstructs the secret
type Combiner struct {
	field *finitefield.Field
}

// Share is a part of the split secret
type Share struct {
	Identifier byte                 // x-coordinate
	Secret     *finitefield.Element // y-coordinate
}

// ShareSet represents a set of shares generated from the embedded polynomial. The polynomial is included so that
// consumers of the shamir package can generate a VSS from the output.
type ShareSet struct {
	Shares []*Share
	Polynomial
}

// NewShare is a Share constructor
func NewShare(x byte, y []byte, f *finitefield.Field) *Share {
	return &Share{x, f.ElementFromBytes(y)}
}

// Order is the order of the Share's finite field.
func (s Share) Order() *big.Int {
	return s.field().Modulus
}

// Field is the Share's finite Field.
func (s Share) field() *finitefield.Field {
	return s.Secret.Field
}

// Add returns the sum of two Shares.
func (s Share) Add(other *Share) *Share {
	if s.Identifier != other.Identifier {
		panic("identifiers must match for valid addition")
	}

	newSecret := s.Secret.Add(other.Secret)

	return NewShare(s.Identifier, newSecret.Bytes(), s.field())
}

// Bytes returns the byte representation of the share: `identifier(1-byte) || secret`
func (s Share) Bytes() []byte {
	out := make([]byte, len(s.Secret.Bytes())+1)
	copy(out, s.Secret.Bytes())
	out[len(out)-1] = s.Identifier

	return out
}

func (s Share) BytesLe() []byte {
	bytes := make([]byte, len(s.Secret.Bytes()))
	copy(bytes, s.Secret.Bytes())

	// reverse slice
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	return bytes
}

func ShareFromBytes(b []byte, f *finitefield.Field) *Share {
	identifier := b[len(b)-1]
	secret := b[:len(b)-1]

	return NewShare(identifier, secret, f)
}

func NewDealer(f *finitefield.Field) *Dealer {
	return &Dealer{f}
}

// Split takes secret and generates a `parts` number of shares, `threshold` of which are required to reconstruct the
// secret. The parts and threshold must be at least 2, and less than 256. The returned shares are each one byte longer
// than the secret as they attach a tag used to reconstruct the secret.
func (d Dealer) Split(secret []byte, threshold, parts int) (*ShareSet, error) {
	field := d.field
	// Sanity check the input
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}
	intSecret := new(big.Int).SetBytes(secret)
	if !field.IsValid(intSecret) {
		return nil, fmt.Errorf("secret is too large")
	}

	// Create the random polynomial of degree threshold-1 to split the secret with
	secretElem := field.NewElement(intSecret)
	polynomial, err := d.makePolynomial(secretElem, uint8(threshold-1))
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate polynomial")
	}

	// Generate a `parts` number of (x,y) pairs and place into shares variable to be returned.
	// x coordinates increment from 1 to parts+1. 0 is reserved for the secret.
	shares := make([]*Share, parts)
	for i := 0; i < parts; i++ {
		xByte := uint8(i) + 1
		x := field.ElementFromBytes([]byte{xByte})
		y := polynomial.evaluate(x)

		shares[i] = NewShare(xByte, y.Bytes(), d.field)
	}

	return &ShareSet{shares, polynomial}, nil
}

func NewCombiner(f *finitefield.Field) *Combiner {
	return &Combiner{f}
}

// Combine is used to reverse a Split and reconstruct a secret
// once at least `threshold` number of parts are available.
func (c Combiner) Combine(shares []*Share) ([]byte, error) {
	field := c.field
	// Verify enough shares provided
	if len(shares) < 2 {
		return nil, fmt.Errorf("less than two shares cannot be used to reconstruct the secret")
	}

	// Verify the secrets are non-empty and identifiers are valid
	for _, s := range shares {
		if len(s.Secret.Bytes()) == 0 {
			return nil, fmt.Errorf("share must have a non-zero length secret")
		}

		if s.Identifier == 0 {
			return nil, fmt.Errorf("share must have non-zero identifier")
		}
	}

	// Ensure there are no duplicate identifiers as that doesn't make sense for reconstruction
	checkMap := map[byte]bool{}
	for _, s := range shares {
		samp := s.Identifier
		if exists := checkMap[samp]; exists {
			return nil, fmt.Errorf("duplicate share detected")
		}
		checkMap[samp] = true
	}

	// Set the (x, y) value for each sample
	xSamples := make([]*finitefield.Element, len(shares))
	ySamples := make([]*finitefield.Element, len(shares))
	for i, s := range shares {
		xSamples[i] = field.NewElement(big.NewInt(int64(s.Identifier)))
		ySamples[i] = s.Secret
	}

	// Interpolate the polynomial and compute the value at 0
	secret := c.interpolatePolynomial(xSamples, ySamples, field.Zero())

	return secret.Bytes(), nil
}

// makePolynomial constructs a random polynomial of the given degree but with the provided intercept
// value.
func (d Dealer) makePolynomial(intercept *finitefield.Element, degree uint8) (Polynomial, error) {
	// Create a wrapper
	p := Polynomial{
		Coefficients: make([]*finitefield.Element, degree+1),
	}

	// Ensure the intercept is set
	p.Coefficients[0] = intercept

	// Assign random co-efficients to the polynomial
	// Start at 1 since 0 is the intercept and it is not chosen randomly
	for i := 1; i < len(p.Coefficients); i++ {
		coefficient, err := d.field.RandomElement(nil)
		if err != nil {
			return p, err
		}
		p.Coefficients[i] = coefficient
	}

	return p, nil
}

// evaluate returns the value of the polynomial for the given x
func (p Polynomial) evaluate(x *finitefield.Element) *finitefield.Element {
	// Special case the origin
	if x.BigInt().Cmp(big.NewInt(0)) == 0 {
		return p.Coefficients[0]
	}

	// Compute the polynomial value using Horner's method.
	degree := len(p.Coefficients) - 1
	out := p.Coefficients[degree].Clone()
	for i := degree - 1; i >= 0; i-- {
		out = out.Mul(x).Add(p.Coefficients[i])
	}

	return out
}

// interpolatePolynomial takes N sample points and returns
// the value at a given x using a lagrange interpolation.
func (c Combiner) interpolatePolynomial(
	xSamples, ySamples []*finitefield.Element,
	x *finitefield.Element,
) *finitefield.Element {
	field := c.field
	limit := len(xSamples)
	result := field.Zero()

	for i := 0; i < limit; i++ {
		basis := field.One()
		for j := 0; j < limit; j++ {
			if i == j {
				continue
			}
			num := x.Sub(xSamples[j])             // x - x_m
			denom := xSamples[i].Sub(xSamples[j]) // x_j - x_m
			basis = basis.Mul(num.Div(denom))
		}
		group := ySamples[i].Mul(basis)
		result = result.Add(group)
	}

	return result
}
