//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package accumulator

import (
	"fmt"
	"git.sr.ht/~sircmpwn/go-bare"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// SecretKey is the secret alpha only held by the accumulator manager.
type SecretKey struct {
	value curves.Scalar
}

// New creates a new secret key from the seed.
func (sk *SecretKey) New(curve *curves.PairingCurve, seed []byte) (*SecretKey, error) {
	sk.value = curve.Scalar.Hash(seed)
	return sk, nil
}

// GetPublicKey creates a public key from SecretKey sk
func (sk SecretKey) GetPublicKey(curve *curves.PairingCurve) (*PublicKey, error) {
	if sk.value == nil || curve == nil {
		return nil, fmt.Errorf("curve and sk value cannot be nil")
	}
	value := curve.Scalar.Point().(curves.PairingPoint).OtherGroup().Generator().Mul(sk.value)
	return &PublicKey{value.(curves.PairingPoint)}, nil
}

// MarshalBinary converts SecretKey to bytes
func (sk SecretKey) MarshalBinary() ([]byte, error) {
	if sk.value == nil {
		return nil, fmt.Errorf("sk cannot be empty")
	}
	tv := &structMarshal{
		Value: sk.value.Bytes(),
		Curve: sk.value.Point().CurveName(),
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary sets SecretKey from bytes
func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	tv := new(structMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("invalid curve")
	}

	value, err := curve.NewScalar().SetBytes(tv.Value)

	if err != nil {
		return err
	}
	sk.value = value
	return nil
}

// BatchAdditions computes product(y + sk) for y in additions and output the product
func (sk SecretKey) BatchAdditions(additions []Element) (Element, error) {
	if sk.value == nil {
		return nil, fmt.Errorf("secret key cannot be empty")
	}
	mul := sk.value.One()
	for i := 0; i < len(additions); i++ {
		if additions[i] == nil {
			return nil, fmt.Errorf("some element in additions is nil")
		}
		// y + alpha
		temp := additions[i].Add(sk.value)
		// prod(y + alpha)
		mul = mul.Mul(temp)
	}
	return mul, nil
}

// BatchDeletions computes 1/product(y + sk) for y in deletions and output it
func (sk SecretKey) BatchDeletions(deletions []Element) (Element, error) {
	v, err := sk.BatchAdditions(deletions)
	if err != nil {
		return nil, err
	}
	y, err := v.Invert()
	if err != nil {
		return nil, err
	}
	return y, nil
}

// CreateCoefficients creates the Batch Polynomial coefficients
// See page 7 of https://eprint.iacr.org/2020/777.pdf
func (sk SecretKey) CreateCoefficients(additions []Element, deletions []Element) ([]Element, error) {
	if sk.value == nil {
		return nil, fmt.Errorf("secret key should not be nil")
	}

	// vD(x) = ∑^{m}_{s=1}{ ∏ 1..s {yD_i + alpha}^-1 ∏ 1 ..s-1 {yD_j - x}
	one := sk.value.One()
	m1 := one.Neg() // m1 is -1
	vD := make(polynomial, 0, len(deletions))
	for s := 0; s < len(deletions); s++ {
		// ∏ 1..s (yD_i + alpha)^-1
		c, err := sk.BatchDeletions(deletions[0 : s+1])
		if err != nil {
			return nil, fmt.Errorf("error in sk batchDeletions")
		}
		poly := make(polynomial, 1, s+2)
		poly[0] = one

		// ∏ 1..(s-1) (yD_j - x)
		for j := 0; j < s; j++ {
			t := make(polynomial, 2)
			// yD_j
			t[0] = deletions[j]
			// -x
			t[1] = m1

			// polynomial multiplication (yD_1-x) * (yD_2 - x) ...
			poly, err = poly.Mul(t)
			if err != nil {
				return nil, err
			}
		}
		poly, err = poly.MulScalar(c)
		if err != nil {
			return nil, err
		}
		vD, err = vD.Add(poly)
		if err != nil {
			return nil, err
		}
	}

	//vD(x) * ∏ 1..n (yA_i + alpha)
	bAdd, err := sk.BatchAdditions(additions)
	if err != nil {
		return nil, fmt.Errorf("error in sk batchAdditions")
	}
	vD, err = vD.MulScalar(bAdd)
	if err != nil {
		return nil, err
	}

	// vA(x) = ∑^n_{s=1}{ ∏ 1..s-1 {yA_i + alpha} ∏ s+1..n {yA_j - x} }
	vA := make(polynomial, 0, len(additions))
	for s := 0; s < len(additions); s++ {
		// ∏ 1..s-1 {yA_i + alpha}
		var c Element
		if s == 0 {
			c = one
		} else {
			c, err = sk.BatchAdditions(additions[0:s])
			if err != nil {
				return nil, err
			}
		}
		poly := make(polynomial, 1, s+2)
		poly[0] = one

		// ∏ s+1..n {yA_j - x}
		for j := s + 1; j < len(additions); j++ {
			t := make(polynomial, 2)
			t[0] = additions[j]
			t[1] = m1

			// polynomial multiplication (yA_1-x) * (yA_2 - x) ...
			poly, err = poly.Mul(t)
			if err != nil {
				return nil, err
			}
		}
		poly, err = poly.MulScalar(c)
		if err != nil {
			return nil, err
		}
		vA, err = vA.Add(poly)
		if err != nil {
			return nil, err
		}
	}

	// vA - vD
	vA, err = vA.Sub(vD)
	if err != nil {
		return nil, err
	}
	result := make([]Element, len(vA))
	for i := 0; i < len(vA); i++ {
		result[i] = vA[i]
	}
	return result, nil
}

// PublicKey is the public key of accumulator, it should be sk * generator of G2
type PublicKey struct {
	value curves.PairingPoint
}

// MarshalBinary converts PublicKey to bytes
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	if pk.value == nil {
		return nil, fmt.Errorf("public key cannot be nil")
	}
	tv := &structMarshal{
		Value: pk.value.ToAffineCompressed(),
		Curve: pk.value.CurveName(),
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary sets PublicKey from bytes
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	tv := new(structMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetPairingCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("invalid curve")
	}

	value, err := curve.NewScalar().Point().FromAffineCompressed(tv.Value)

	if err != nil {
		return err
	}
	pk.value = value.(curves.PairingPoint)
	return nil
}
