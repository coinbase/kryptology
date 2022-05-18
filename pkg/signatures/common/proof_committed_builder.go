//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package common

import (
	"fmt"
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

const limit = 65535

// ProofCommittedBuilder is used to create
// proofs from multiple commitments where
// each secret is committed with a random blinding factor
// and turned into a Schnorr proof
type ProofCommittedBuilder struct {
	points  []curves.Point
	scalars []curves.Scalar
	curve   *curves.Curve
}

// NewProofCommittedBuilder creates a new builder using the specified curve
func NewProofCommittedBuilder(curve *curves.Curve) *ProofCommittedBuilder {
	return &ProofCommittedBuilder{
		points:  []curves.Point{},
		scalars: []curves.Scalar{},
		curve:   curve,
	}
}

// CommitRandom uses the specified point and commits a random value to it
func (pcb *ProofCommittedBuilder) CommitRandom(point curves.Point, reader io.Reader) error {
	if len(pcb.points) > limit {
		return fmt.Errorf("limit for commitments reached")
	}
	pcb.points = append(pcb.points, point)
	pcb.scalars = append(pcb.scalars, pcb.curve.Scalar.Random(reader))
	return nil
}

// Commit uses the specified point and scalar to create a commitment
func (pcb *ProofCommittedBuilder) Commit(point curves.Point, scalar curves.Scalar) error {
	if len(pcb.points) > limit {
		return fmt.Errorf("limit for commitments reached")
	}
	pcb.points = append(pcb.points, point)
	pcb.scalars = append(pcb.scalars, scalar)
	return nil
}

// Get returns the point and scalar at the specified index
func (pcb *ProofCommittedBuilder) Get(index int) (curves.Point, curves.Scalar) {
	if index >= len(pcb.points) || index < 0 {
		return nil, nil
	}
	return pcb.points[index], pcb.scalars[index]
}

// GetChallengeContribution returns the bytes that should be added to
// a sigma protocol transcript for generating the challenge
func (pcb ProofCommittedBuilder) GetChallengeContribution() []byte {
	commitment := pcb.curve.Point.SumOfProducts(pcb.points, pcb.scalars)
	if commitment == nil {
		return nil
	}
	return commitment.ToAffineCompressed()
}

// GenerateProof converts the blinding factors and secrets into Schnorr proofs
func (pcb ProofCommittedBuilder) GenerateProof(challenge curves.Scalar, secrets []curves.Scalar) ([]curves.Scalar, error) {
	if len(secrets) != len(pcb.scalars) {
		return nil, fmt.Errorf("secrets is not equal to blinding factors")
	}

	proofs := make([]curves.Scalar, len(pcb.scalars))
	for i, sc := range pcb.scalars {
		proofs[i] = secrets[i].MulAdd(challenge, sc)
	}
	return proofs, nil
}
