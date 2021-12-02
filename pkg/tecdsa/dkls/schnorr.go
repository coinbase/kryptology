//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkls

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
)

type Schnorr struct {
	params *Params
	Pub    *curves.EcPoint // this is the public point.
	C      *big.Int
	S      *big.Int
}

func (proof *Schnorr) Prove(x *big.Int) error {
	// assumes that params, Base, and pub are already populated. populates the fields c and s...
	var err error
	proof.Pub, err = curves.NewScalarBaseMult(proof.params.Curve, x) // populate the statement
	if err != nil {
		return err
	}
	k, err := proof.params.Scalar.Random()
	if err != nil {
		return err
	}
	random, err := curves.NewScalarBaseMult(proof.params.Curve, k)
	if err != nil {
		return err
	}
	hash := sha256.New()
	if _, err = hash.Write(proof.Pub.Bytes()); err != nil {
		return err
	}
	if _, err = hash.Write(random.Bytes()); err != nil {
		return err
	}
	// do we need to hash anything further here...? maybe some kind of session token or something?
	proof.C = new(big.Int).SetBytes(hash.Sum(nil))
	proof.S = proof.params.Scalar.Add(proof.params.Scalar.Mul(proof.C, x), k)
	return nil
}

func (proof *Schnorr) Verify() error {
	gs, err := curves.NewScalarBaseMult(proof.params.Curve, proof.S)
	if err != nil {
		return err
	}
	xc, err := proof.Pub.ScalarMult(proof.params.Scalar.Neg(proof.C))
	if err != nil {
		return err
	}
	random, err := gs.Add(xc)
	if err != nil {
		return err
	}
	hash := sha256.New()
	if _, err = hash.Write(proof.Pub.Bytes()); err != nil {
		return err
	}
	if _, err = hash.Write(random.Bytes()); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(proof.params.Scalar.Bytes(proof.C), hash.Sum(nil)) != 1 {
		return fmt.Errorf("Schnorr verification failed")
	}
	return nil
}

// this "commits to" a schnorr proof which is later revealed; see Functionality 7.
// it mutates `st` by adding a proof to it, and then also returns the commitment to the proof.
func (proof *Schnorr) ProveCommit(x *big.Int) ([]byte, error) {
	// it remains to be seen why this is actually necessary in the paper. it's unsual.
	// i suspect it is some "abstract nonsense" necessary for the security proof to go through.
	// in the implementation (see https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/zkpok.rs),
	// they implement this just by hashing the schnorr proof; we do the same (using c, s as the proof instead of K, s).
	// it's a bit weird that no randomness is used, but "hiding" shouldn't really be an issue, as the proof is random.
	// confirm that this actually matches how they implement it, and/or is secure. i don't think it should be an issue.
	if err := proof.Prove(x); err != nil {
		return nil, err
	}
	hash := sha256.New()
	if _, err := hash.Write(proof.params.Scalar.Bytes(proof.C)); err != nil {
		return nil, err
	}
	if _, err := hash.Write(proof.params.Scalar.Bytes(proof.S)); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (proof *Schnorr) DecommitVerify(com []byte) error {
	hash := sha256.New()
	if _, err := hash.Write(proof.params.Scalar.Bytes(proof.C)); err != nil {
		return err
	}
	if _, err := hash.Write(proof.params.Scalar.Bytes(proof.S)); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hash.Sum(nil), com) != 1 {
		return fmt.Errorf("initial hash decommitment failed")
	}
	return proof.Verify()
}
