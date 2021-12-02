//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math"
)

// dad constructs two polynomials - dA(x) and dD(x)
// dA(y) = prod(y_A,t - y), t = 1...n
// dD(y) = prod(y_D,t - y), t = 1...n
func dad(values []Element, y Element) (Element, error) {
	if values == nil || y == nil {
		return nil, fmt.Errorf("curve, values or y should not be nil")
	}

	for _, value := range values {
		if value == nil {
			return nil, fmt.Errorf("some element is nil")
		}
	}

	result := y.One()
	if len(values) == 1 {
		a := values[0]
		result = a.Sub(y)
	} else {
		for i := 0; i < len(values); i++ {
			temp := values[i].Sub(y)
			result = result.Mul(temp)
		}
	}
	return result, nil
}

type polynomialPoint []curves.Point

// evaluate evaluates a PolynomialG1 on input x.
func (p polynomialPoint) evaluate(x curves.Scalar) (curves.Point, error) {
	if p == nil {
		return nil, fmt.Errorf("p cannot be empty")
	}
	for i := 0; i < len(p); i++ {
		if p[i] == nil {
			return nil, fmt.Errorf("some coefficient in p is nil")
		}
	}

	pp := x
	res := p[0]
	for i := 1; i < len(p); i++ {
		r := p[i].Mul(pp)
		res = res.Add(r)
		pp = pp.Mul(x)
	}
	return res, nil
}

// Add adds two PolynomialG1
func (p polynomialPoint) Add(rhs polynomialPoint) (polynomialPoint, error) {
	maxLen := int(math.Max(float64(len(p)), float64(len(rhs))))

	result := make(polynomialPoint, maxLen)

	for i, c := range p {
		if c == nil {
			return nil, fmt.Errorf("invalid coefficient at %d", i)
		}
		result[i] = c.Add(c.Identity())
	}

	for i, c := range rhs {
		if c == nil {
			return nil, fmt.Errorf("invalid coefficient at %d", i)
		}
		if result[i] == nil {
			result[i] = c.Add(c.Identity())
		} else {
			result[i] = result[i].Add(c)
		}
	}
	return result, nil
}

// Mul for PolynomialG1 computes rhs * p, p is a polynomial, rhs is a value
func (p polynomialPoint) Mul(rhs curves.Scalar) (polynomialPoint, error) {
	result := make(polynomialPoint, len(p))

	for i, c := range p {
		if c == nil {
			return nil, fmt.Errorf("invalid coefficient at %d", i)
		}
		result[i] = c.Mul(rhs)
	}

	return result, nil
}

type polynomial []curves.Scalar

// Add adds two polynomials
func (p polynomial) Add(rhs polynomial) (polynomial, error) {
	maxLen := int(math.Max(float64(len(p)), float64(len(rhs))))
	result := make([]curves.Scalar, maxLen)

	for i, c := range p {
		if c == nil {
			return nil, fmt.Errorf("invalid coefficient at %d", i)
		}
		result[i] = c.Clone()
	}

	for i, c := range rhs {
		if c == nil {
			return nil, fmt.Errorf("invalid coefficient at %d", i)
		}
		if result[i] == nil {
			result[i] = c.Clone()
		} else {
			result[i] = result[i].Add(c)
		}
	}

	return result, nil
}

// Sub computes p-rhs and returns
func (p polynomial) Sub(rhs polynomial) (polynomial, error) {
	maxLen := int(math.Max(float64(len(p)), float64(len(rhs))))
	result := make([]curves.Scalar, maxLen)

	for i, c := range p {
		if c == nil {
			return nil, fmt.Errorf("invalid coefficient at %d", i)
		}
		result[i] = c.Clone()
	}

	for i, c := range rhs {
		if c == nil {
			return nil, fmt.Errorf("invalid coefficient at %d", i)
		}
		if result[i] == nil {
			result[i] = c.Neg()
		} else {
			result[i] = result[i].Sub(c)
		}
	}

	return result, nil
}

// Mul multiplies two polynomials - p * rhs
func (p polynomial) Mul(rhs polynomial) (polynomial, error) {
	// Check for each coefficient that should not be nil
	for i, c := range p {
		if c == nil {
			return nil, fmt.Errorf("coefficient in p at %d is nil", i)
		}
	}

	for i, c := range rhs {
		if c == nil {
			return nil, fmt.Errorf("coefficient in rhs at %d is nil", i)
		}
	}

	m := len(p)
	n := len(rhs)

	// Initialize the product polynomial
	prod := make(polynomial, m+n-1)
	for i := 0; i < len(prod); i++ {
		prod[i] = p[0].Zero()
	}

	// Multiply two polynomials term by term
	for i, cp := range p {
		for j, cr := range rhs {
			temp := cp.Mul(cr)
			prod[i+j] = prod[i+j].Add(temp)
		}
	}
	return prod, nil
}

// MulScalar computes p * rhs, where rhs is a scalar value
func (p polynomial) MulScalar(rhs curves.Scalar) (polynomial, error) {
	result := make(polynomial, len(p))
	for i, c := range p {
		if c == nil {
			return nil, fmt.Errorf("coefficient at %d is nil", i)
		}
		result[i] = c.Mul(rhs)
	}
	return result, nil
}
