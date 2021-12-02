//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type polynomial struct {
	Coefficients []*curves.Element
}

// newPoly creates a random polynomial of the given degree but with the provided intercept value
func newPoly(intercept *curves.Element, degree uint32) (polynomial, error) {
	p := polynomial{
		Coefficients: make([]*curves.Element, degree),
	}

	// Intercept is the value to be split
	p.Coefficients[0] = intercept

	// random coefficients
	for i := uint32(1); i < degree; i++ {
		c, err := intercept.Field().RandomElement(nil)
		if err != nil {
			return p, err
		}
		p.Coefficients[i] = c
	}

	return p, nil
}

// evaluate returns the value of the polynomial for the given x
func (p polynomial) evaluate(x *curves.Element) *curves.Element {
	// Compute the polynomial value using Horner's Method

	degree := len(p.Coefficients) - 1
	result := p.Coefficients[degree].Clone()
	for i := degree - 1; i >= 0; i-- {
		result = result.Mul(x).Add(p.Coefficients[i])
	}

	return result
}
