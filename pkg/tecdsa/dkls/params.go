//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkls

import (
	"crypto/elliptic"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"

	"golang.org/x/crypto/sha3"
)

const (
	kappa   = 256 // Computational security parameter.
	s       = 80  // statistical security parameter. does this have to be so high?! i've seen 40. // TODO: investigate why 80
	kappaOT = kappa + s
)

type Params struct {
	Curve     elliptic.Curve
	Scalar    curves.EcScalar
	Generator *curves.EcPoint
	gadget    [2*kappa + 2*s]*big.Int
}

// NewParams receives an implementation of the curve and scalar interfaces and
// sets the parameters needed for DKG and Threshold ECDSA of DKLS.
func NewParams(curve elliptic.Curve, scalar curves.EcScalar) (*Params, error) {
	params := &Params{Curve: curve, Scalar: scalar}
	params.Generator = &curves.EcPoint{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}
	for i := 0; i < kappa; i++ {
		params.gadget[i] = new(big.Int).Lsh(big.NewInt(1), uint(i))
	}
	shake := sha3.NewCShake256(nil, []byte("Play as a championship team."))
	for i := kappa; i < 2*kappa+2*s; i++ {
		var err error
		bytes := [32]byte{}
		if _, err = shake.Read(bytes[:]); err != nil {
			return nil, err
		}
		params.gadget[i] = new(big.Int).SetBytes(bytes[:])
	}
	return params, nil
}
