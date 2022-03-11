//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bulletproof

import (
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// innerProduct takes two lists of scalars (a, b) and performs the dot product returning a single scalar
func innerProduct(a, b []curves.Scalar) (curves.Scalar, error) {
	if len(a) != len(b) {
		return nil, errors.New("length of scalar vectors must be the same")
	}
	if len(a) < 1 {
		return nil, errors.New("length of vectors must be at least one")
	}
	// Get a new scalar of value zero of the same curve as input arguments
	innerProduct := a[0].Zero()
	for i, aElem := range a {
		bElem := b[i]
		// innerProduct = aElem*bElem + innerProduct
		innerProduct = aElem.MulAdd(bElem, innerProduct)
	}

	return innerProduct, nil
}

// splitPointVector takes a vector of points, splits it in half returning each half
func splitPointVector(points []curves.Point) ([]curves.Point, []curves.Point, error) {
	if len(points) < 1 {
		return nil, nil, errors.New("length of points must be at least one")
	}
	if len(points)&0x01 != 0 {
		return nil, nil, errors.New("length of points must be even")
	}
	nPrime := len(points) >> 1
	firstHalf := points[:nPrime]
	secondHalf := points[nPrime:]
	return firstHalf, secondHalf, nil
}

// splitScalarVector takes a vector of scalars, splits it in half returning each half
func splitScalarVector(scalars []curves.Scalar) ([]curves.Scalar, []curves.Scalar, error) {
	if len(scalars) < 1 {
		return nil, nil, errors.New("length of scalars must be at least one")
	}
	if len(scalars)&0x01 != 0 {
		return nil, nil, errors.New("length of scalars must be even")
	}
	nPrime := len(scalars) >> 1
	firstHalf := scalars[:nPrime]
	secondHalf := scalars[nPrime:]
	return firstHalf, secondHalf, nil
}

// multiplyScalarToPointVector takes a single scalar and a list of points, multiplies each point by scalar
func multiplyScalarToPointVector(x curves.Scalar, g []curves.Point) []curves.Point {
	products := make([]curves.Point, len(g))
	for i, gElem := range g {
		product := gElem.Mul(x)
		products[i] = product
	}

	return products
}

// multiplyScalarToScalarVector takes a single scalar (x) and a list of scalars (a), multiplies each scalar in the vector by the scalar
func multiplyScalarToScalarVector(x curves.Scalar, a []curves.Scalar) []curves.Scalar {
	products := make([]curves.Scalar, len(a))
	for i, aElem := range a {
		product := aElem.Mul(x)
		products[i] = product
	}

	return products
}

// multiplyPairwisePointVectors takes two lists of points (g, h) and performs a pairwise multiplication returning a list of points
func multiplyPairwisePointVectors(g, h []curves.Point) ([]curves.Point, error) {
	if len(g) != len(h) {
		return nil, errors.New("length of point vectors must be the same")
	}
	product := make([]curves.Point, len(g))
	for i, gElem := range g {
		product[i] = gElem.Add(h[i])
	}

	return product, nil
}

// multiplyPairwiseScalarVectors takes two lists of points (a, b) and performs a pairwise multiplication returning a list of scalars
func multiplyPairwiseScalarVectors(a, b []curves.Scalar) ([]curves.Scalar, error) {
	if len(a) != len(b) {
		return nil, errors.New("length of point vectors must be the same")
	}
	product := make([]curves.Scalar, len(a))
	for i, aElem := range a {
		product[i] = aElem.Mul(b[i])
	}

	return product, nil
}

// addPairwiseScalarVectors takes two lists of scalars (a, b) and performs a pairwise addition returning a list of scalars
func addPairwiseScalarVectors(a, b []curves.Scalar) ([]curves.Scalar, error) {
	if len(a) != len(b) {
		return nil, errors.New("length of scalar vectors must be the same")
	}
	sum := make([]curves.Scalar, len(a))
	for i, aElem := range a {
		sum[i] = aElem.Add(b[i])
	}

	return sum, nil
}

// subtractPairwiseScalarVectors takes two lists of scalars (a, b) and performs a pairwise subtraction returning a list of scalars
func subtractPairwiseScalarVectors(a, b []curves.Scalar) ([]curves.Scalar, error) {
	if len(a) != len(b) {
		return nil, errors.New("length of scalar vectors must be the same")
	}
	diff := make([]curves.Scalar, len(a))
	for i, aElem := range a {
		diff[i] = aElem.Sub(b[i])
	}
	return diff, nil
}

// invertScalars takes a list of scalars then returns a list with each element inverted
func invertScalars(xs []curves.Scalar) ([]curves.Scalar, error) {
	xinvs := make([]curves.Scalar, len(xs))
	for i, x := range xs {
		xinv, err := x.Invert()
		if err != nil {
			return nil, errors.Wrap(err, "bulletproof helpers invertx")
		}
		xinvs[i] = xinv
	}

	return xinvs, nil
}

// isPowerOfTwo returns whether a number i is a power of two or not
func isPowerOfTwo(i int) bool {
	return i&(i-1) == 0
}

// get2nVector returns a scalar vector 2^n such that [1, 2, 4, ... 2^(n-1)]
// See k^n and 2^n definitions on pg 12 of https://eprint.iacr.org/2017/1066.pdf
func get2nVector(len int, curve curves.Curve) []curves.Scalar {
	vector2n := make([]curves.Scalar, len)
	vector2n[0] = curve.Scalar.One()
	vector2n[1] = vector2n[0].Double()
	for i := 2; i < len; i++ {
		vector2n[i] = vector2n[i-1].Double()
	}
	return vector2n
}

func get1nVector(len int, curve curves.Curve) []curves.Scalar {
	vector1n := make([]curves.Scalar, len)
	for i := 0; i < len; i++ {
		vector1n[i] = curve.Scalar.One()
	}
	return vector1n
}

func getknVector(k curves.Scalar, len int, curve curves.Curve) []curves.Scalar {
	vectorkn := make([]curves.Scalar, len)
	vectorkn[0] = curve.Scalar.One()
	vectorkn[1] = k
	for i := 2; i < len; i++ {
		vectorkn[i] = vectorkn[i-1].Mul(k)
	}
	return vectorkn
}
