//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	"fmt"

	"git.sr.ht/~sircmpwn/go-bare"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// CipherText represents verifiably encrypted ciphertext
// using El-Gamal encryption
type CipherText struct {
	C1, C2      curves.Point
	Nonce       []byte
	Aead        []byte
	MsgIsHashed bool
}

// HomomorphicCipherText represents encrypted ciphertexts
// that have been added together. The result when decrypted
// does not include the AEAD encrypted ciphertexts since
// these are not homomorphic. This is solely for checking
// results or ignoring the AEAD ciphertext.
type HomomorphicCipherText struct {
	C1, C2 curves.Point
}

type cipherTextMarshal struct {
	C1          []byte `bare:"c1"`
	C2          []byte `bare:"c2"`
	Nonce       []byte `bare:"nonce"`
	Aead        []byte `bare:"aead"`
	Curve       string `bare:"curve"`
	MsgIsHashed bool   `bare:"msgIsHashed"`
}

type homomorphicCipherTextMarshal struct {
	C1    []byte `bare:"c1"`
	C2    []byte `bare:"c2"`
	Curve string `bare:"curve"`
}

func (c CipherText) MarshalBinary() ([]byte, error) {
	tv := new(cipherTextMarshal)
	tv.C1 = c.C1.ToAffineCompressed()
	tv.C2 = c.C2.ToAffineCompressed()
	tv.Nonce = make([]byte, len(c.Nonce))
	copy(tv.Nonce, c.Nonce)
	tv.Aead = make([]byte, len(c.Aead))
	tv.Curve = c.C1.CurveName()
	copy(tv.Aead, c.Aead)
	tv.MsgIsHashed = c.MsgIsHashed
	return bare.Marshal(tv)
}

func (c *CipherText) UnmarshalBinary(data []byte) error {
	tv := new(cipherTextMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("unknown curve")
	}
	c1, err := curve.Point.FromAffineCompressed(tv.C1)
	if err != nil {
		return err
	}
	c2, err := curve.Point.FromAffineCompressed(tv.C2)
	if err != nil {
		return err
	}
	c.C1 = c1
	c.C2 = c2
	c.Aead = tv.Aead
	c.Nonce = tv.Nonce
	c.MsgIsHashed = tv.MsgIsHashed

	return nil
}

// ToHomomorphicCipherText returns the El-Gamal points that can be
// homomorphically multiplied
func (c CipherText) ToHomomorphicCipherText() *HomomorphicCipherText {
	return &HomomorphicCipherText{
		C1: c.C1,
		C2: c.C2,
	}
}

// Add combines two ciphertexts multiplicatively homomorphic
func (c HomomorphicCipherText) Add(rhs *HomomorphicCipherText) *HomomorphicCipherText {
	return &HomomorphicCipherText{
		C1: c.C1.Add(rhs.C1),
		C2: c.C2.Add(rhs.C2),
	}
}

// Decrypt returns the C2 - C1
func (c HomomorphicCipherText) Decrypt(dk *DecryptionKey) (curves.Point, error) {
	if dk == nil {
		return nil, internal.ErrNilArguments
	}
	return c.C2.Sub(c.C1.Mul(dk.x)), nil
}

func (c HomomorphicCipherText) MarshalBinary() ([]byte, error) {
	tv := new(homomorphicCipherTextMarshal)
	tv.C1 = c.C1.ToAffineCompressed()
	tv.C2 = c.C2.ToAffineCompressed()
	tv.Curve = c.C1.CurveName()
	return bare.Marshal(tv)
}

func (c *HomomorphicCipherText) UnmarshalBinary(in []byte) error {
	tv := new(homomorphicCipherTextMarshal)
	err := bare.Unmarshal(in, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("unknown curve")
	}
	c1, err := curve.Point.FromAffineCompressed(tv.C1)
	if err != nil {
		return err
	}
	c2, err := curve.Point.FromAffineCompressed(tv.C2)
	if err != nil {
		return err
	}
	c.C1 = c1
	c.C2 = c2
	return nil
}
