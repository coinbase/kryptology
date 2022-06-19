//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package schnorr implements a Schnorr proof, as described and used in Doerner, et al. https://eprint.iacr.org/2018/499.pdf
// see Functionalities 6. it also implements a "committed" version, as described in Functionality 7.
package schnorr

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

type Commitment = []byte

type Prover struct {
	curve           *curves.Curve
	basePoint       curves.Point
	uniqueSessionId []byte
}

// Proof contains the (c, s) schnorr proof. `Statement` is the curve point you're proving knowledge of discrete log of,
// with respect to the base point.
type Proof struct {
	C         curves.Scalar
	S         curves.Scalar
	Statement curves.Point
}

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
// We allow the option `basePoint == nil`, in which case `basePoint` is auto-assigned to be the "default" generator for the group.
func NewProver(curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte) *Prover {
	if basepoint == nil {
		basepoint = curve.NewGeneratorPoint()
	}
	return &Prover{
		curve:           curve,
		basePoint:       basepoint,
		uniqueSessionId: uniqueSessionId,
	}
}

// Prove generates and returns a Schnorr proof, given the scalar witness `x`.
// in the process, it will actually also construct the statement (just one curve mult in this case)
func (p *Prover) Prove(x curves.Scalar) (*Proof, error) {
	// assumes that params, and pub are already populated. populates the fields c and s...
	result := &Proof{}
	result.Statement = p.basePoint.Mul(x)
	k := p.curve.Scalar.Random(rand.Reader)
	random := p.basePoint.Mul(k)

	var buff bytes.Buffer
	_, _ = buff.Write(p.uniqueSessionId) // Buffer.Write doesn't err
	_, _ = buff.Write(p.basePoint.ToAffineCompressed())
	_, _ = buff.Write(result.Statement.ToAffineCompressed())
	_, _ = buff.Write(random.ToAffineCompressed())

	result.C = p.curve.Scalar.Hash(buff.Bytes())
	result.S = result.C.Mul(x).Add(k)
	return result, nil
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve`.
// As for the prover, we allow `basePoint == nil`, in this case, it's auto-assigned to be the group's default generator.
func Verify(proof *Proof, curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte) error {
	if basepoint == nil {
		basepoint = curve.NewGeneratorPoint()
	}
	gs := basepoint.Mul(proof.S)
	xc := proof.Statement.Mul(proof.C.Neg())
	random := gs.Add(xc)

	var buff bytes.Buffer
	_, _ = buff.Write(uniqueSessionId)
	_, _ = buff.Write(basepoint.ToAffineCompressed())
	_, _ = buff.Write(proof.Statement.ToAffineCompressed())
	_, _ = buff.Write(random.ToAffineCompressed())

	ComputedC := curve.Scalar.Hash(buff.Bytes())
	if proof.C.Cmp(ComputedC) != 0 {
		return fmt.Errorf("schnorr verification failed")
	}
	return nil
}

// ProveCommit generates _and_ commits to a schnorr proof which is later revealed; see Functionality 7.
// returns the Proof and Commitment.
func (p *Prover) ProveCommit(x curves.Scalar) (*Proof, Commitment, error) {
	proof, err := p.Prove(x)
	if err != nil {
		return nil, nil, err
	}
	hash := sha3.New256()
	if _, err = hash.Write(proof.C.Bytes()); err != nil {
		return nil, nil, err
	}
	if _, err = hash.Write(proof.S.Bytes()); err != nil {
		return nil, nil, err
	}
	return proof, hash.Sum(nil), nil
}

// DecommitVerify receives a `Proof` and a `Commitment`; it first checks that the proof actually opens the commitment;
// then it verifies the proof. returns and error if either on eof thse fail.
func DecommitVerify(proof *Proof, commitment Commitment, curve *curves.Curve, basepoint curves.Point, uniqueSessionId []byte) error {
	hash := sha3.New256()
	if _, err := hash.Write(proof.C.Bytes()); err != nil {
		return err
	}
	if _, err := hash.Write(proof.S.Bytes()); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), commitment) != 1 {
		return fmt.Errorf("initial hash decommitment failed")
	}
	return Verify(proof, curve, basepoint, uniqueSessionId)
}
