//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
)

// BlindSignature is a BBS+ blind signature
// structurally identical to `Signature` but
// is used to help avoid misuse and confusion.
//
// 1 or more message have been hidden by the
// potential signature holder so the signer
// only knows a subset of the messages to be signed
type BlindSignature struct {
	a    curves.PairingPoint
	e, s curves.Scalar
}

// Init creates an empty signature to a specific curve
// which should be followed by UnmarshalBinary
func (sig *BlindSignature) Init(curve *curves.PairingCurve) *BlindSignature {
	sig.a = curve.NewG1IdentityPoint()
	sig.e = curve.NewScalar()
	sig.s = curve.NewScalar()
	return sig
}

func (sig BlindSignature) MarshalBinary() ([]byte, error) {
	out := append(sig.a.ToAffineCompressed(), sig.e.Bytes()...)
	out = append(out, sig.s.Bytes()...)
	return out, nil
}

func (sig *BlindSignature) UnmarshalBinary(data []byte) error {
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

func (sig BlindSignature) ToUnblinded(blinder common.SignatureBlinding) *Signature {
	return &Signature{
		a: sig.a,
		e: sig.e,
		s: sig.s.Add(blinder),
	}
}
