//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Signature is a BBS+ signature
// as described in 4.3 in
// <https://eprint.iacr.org/2016/663.pdf>
type Signature struct {
	a    curves.PairingPoint
	e, s curves.Scalar
}

// Init creates an empty signature to a specific curve
// which should be followed by UnmarshalBinary or Create
func (sig *Signature) Init(curve *curves.PairingCurve) *Signature {
	sig.a = curve.NewG1IdentityPoint()
	sig.e = curve.NewScalar()
	sig.s = curve.NewScalar()
	return sig
}

func (sig Signature) MarshalBinary() ([]byte, error) {
	out := append(sig.a.ToAffineCompressed(), sig.e.Bytes()...)
	out = append(out, sig.s.Bytes()...)
	return out, nil
}

func (sig *Signature) UnmarshalBinary(data []byte) error {
	pointLength := len(sig.a.ToAffineCompressed())
	scalarLength := len(sig.s.Bytes())
	expectedLength := pointLength + scalarLength*2
	if len(data) != expectedLength {
		return fmt.Errorf("invalid byte sequence")
	}
	a, err := sig.a.FromAffineCompressed(data[:pointLength])
	if err != nil {
		return err
	}
	e, err := sig.e.SetBytes(data[pointLength:(pointLength + scalarLength)])
	if err != nil {
		return err
	}
	s, err := sig.s.SetBytes(data[(pointLength + scalarLength):])
	if err != nil {
		return err
	}
	sig.a = a.(curves.PairingPoint)
	sig.e = e
	sig.s = s
	return nil
}
