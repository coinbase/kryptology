//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bulletproof

import (
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// generators contains a list of points to be used as generators for bulletproofs
type generators []curves.Point

// ippGenerators holds generators necessary for an Inner Product Proof
// It includes a single u generator, and a list of generators divided in half to G and H
// See lines 10 on pg 16 of https://eprint.iacr.org/2017/1066.pdf
type ippGenerators struct {
	G generators
	H generators
}

// getGeneratorPoints generates generators using HashToCurve with Shake256(domain) as input
// lenVector is the length of the scalars used for the Inner Product Proof
// getGeneratorPoints will return 2*lenVector + 1 total points, split between a single u generator
// and G and H lists of vectors per the IPP specification
// See lines 10 on pg 16 of https://eprint.iacr.org/2017/1066.pdf
func getGeneratorPoints(lenVector int, domain []byte, curve curves.Curve) (*ippGenerators, error) {
	shake := sha3.NewShake256()
	_, err := shake.Write(domain)
	if err != nil {
		return nil, errors.Wrap(err, "getGeneratorPoints shake.Write")
	}
	numPoints := lenVector * 2
	points := make([]curves.Point, numPoints)
	for i := 0; i < numPoints; i++ {
		bytes := [64]byte{}
		_, err := shake.Read(bytes[:])
		if err != nil {
			return nil, errors.Wrap(err, "getGeneratorPoints shake.Read")
		}
		nextPoint := curve.Point.Hash(bytes[:])
		points[i] = nextPoint
	}
	// Get G and H by splitting points in half
	G, H, err := splitPointVector(points)
	if err != nil {
		return nil, errors.Wrap(err, "getGeneratorPoints splitPointVector")
	}
	out := ippGenerators{G: G, H: H}

	return &out, nil
}
