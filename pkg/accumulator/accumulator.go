//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"fmt"
	"git.sr.ht/~sircmpwn/go-bare"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type structMarshal struct {
	Value []byte `bare:"value"`
	Curve string `bare:"curve"`
}

type Element curves.Scalar

// Coefficient is a point
type Coefficient curves.Point

// Accumulator is a point
type Accumulator struct {
	value curves.Point
}

// New creates a new accumulator.
func (acc *Accumulator) New(curve *curves.PairingCurve) (*Accumulator, error) {
	// If we need to support non-membership witness, we need to implement Accumulator Initialization
	// as described in section 6 of <https://eprint.iacr.org/2020/777.pdf>
	// for now we don't need non-membership witness

	// i.e., it computes V0 = prod(y + α) * P, y ∈ Y_V0, P is a generator of G1. Since we do not use non-membership witness
	// we just set the initial accumulator a G1 generator.
	acc.value = curve.Scalar.Point().Generator()
	return acc, nil
}

// WithElements initializes a new accumulator prefilled with entries
// Each member is assumed to be hashed
// V = prod(y + α) * V0, for all y∈ Y_V
func (acc *Accumulator) WithElements(curve *curves.PairingCurve, key *SecretKey, m []Element) (*Accumulator, error) {
	_, err := acc.New(curve)
	if err != nil {
		return nil, err
	}
	y, err := key.BatchAdditions(m)
	if err != nil {
		return nil, err
	}
	acc.value = acc.value.Mul(y)
	return acc, nil
}

// AddElements accumulates a set of elements into the accumulator.
func (acc *Accumulator) AddElements(key *SecretKey, m []Element) (*Accumulator, error) {
	if acc.value == nil || key.value == nil {
		return nil, fmt.Errorf("accumulator and secret key should not be nil")
	}
	y, err := key.BatchAdditions(m)
	if err != nil {
		return nil, err
	}
	acc.value = acc.value.Mul(y)
	return acc, nil
}

// Add accumulates a single element into the accumulator
// V' = (y + alpha) * V
func (acc *Accumulator) Add(key *SecretKey, e Element) (*Accumulator, error) {
	if acc.value == nil || acc.value.IsIdentity() || key.value == nil || e == nil {
		return nil, fmt.Errorf("accumulator, secret key and element should not be nil")
	}
	y := e.Add(key.value) // y + alpha
	acc.value = acc.value.Mul(y)
	return acc, nil
}

// Remove removes a single element from accumulator if it exists
// V' = 1/(y+alpha) *  V
func (acc *Accumulator) Remove(key *SecretKey, e Element) (*Accumulator, error) {
	if acc.value == nil || acc.value.IsIdentity() || key.value == nil || e == nil {
		return nil, fmt.Errorf("accumulator, secret key and element should not be nil")
	}
	y := e.Add(key.value) // y + alpha
	y, err := y.Invert()  // 1/(y+alpha)
	if err != nil {
		return nil, err
	}
	acc.value = acc.value.Mul(y)
	return acc, nil
}

// Update performs a batch addition and deletion as described on page 7, section 3 in
// https://eprint.iacr.org/2020/777.pdf
func (acc *Accumulator) Update(key *SecretKey, additions []Element, deletions []Element) (*Accumulator, []Coefficient, error) {
	if acc.value == nil || acc.value.IsIdentity() || key.value == nil {
		return nil, nil, fmt.Errorf("accumulator and secret key should not be nil")
	}

	// Compute dA(-alpha) = prod(y + alpha), y in the set of A ⊆ ACC-Y_V
	a, err := key.BatchAdditions(additions)
	if err != nil {
		return nil, nil, err
	}

	// Compute dD(-alpha) = 1/prod(y + alpha), y in the set of D ⊆ Y_V
	d, err := key.BatchDeletions(deletions)
	if err != nil {
		return nil, nil, err
	}

	// dA(-alpha)/dD(-alpha)
	div := a.Mul(d)
	newAcc := acc.value.Mul(div)

	// build an array of coefficients
	elements, err := key.CreateCoefficients(additions, deletions)
	if err != nil {
		return nil, nil, err
	}

	coefficients := make([]Coefficient, len(elements))
	for i := 0; i < len(elements); i++ {
		coefficients[i] = acc.value.Mul(elements[i])
	}
	acc.value = newAcc
	return acc, coefficients, nil
}

// MarshalBinary converts Accumulator to bytes
func (acc Accumulator) MarshalBinary() ([]byte, error) {
	if acc.value == nil {
		return nil, fmt.Errorf("accumulator cannot be nil")
	}
	tv := &structMarshal{
		Value: acc.value.ToAffineCompressed(),
		Curve: acc.value.CurveName(),
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary sets Accumulator from bytes
func (acc *Accumulator) UnmarshalBinary(data []byte) error {
	tv := new(structMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("invalid curve")
	}

	value, err := curve.NewIdentityPoint().FromAffineCompressed(tv.Value)

	if err != nil {
		return err
	}
	acc.value = value
	return nil
}
