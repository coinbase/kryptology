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
	c1, c2      curves.Point
	nonce       []byte
	aead        []byte
	msgIsHashed bool
}

// HomomorphicCipherText represents encrypted ciphertexts
// that have been added together. The result when decrypted
// does not include the AEAD encrypted ciphertexts since
// these are not homomorphic. This is solely for checking
// results or ignoring the AEAD ciphertext.
type HomomorphicCipherText struct {
	c1, c2 curves.Point
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
	tv.C1 = c.c1.ToAffineCompressed()
	tv.C2 = c.c2.ToAffineCompressed()
	tv.Nonce = make([]byte, len(c.nonce))
	copy(tv.Nonce, c.nonce)
	tv.Aead = make([]byte, len(c.aead))
	tv.Curve = c.c1.CurveName()
	copy(tv.Aead, c.aead)
	tv.MsgIsHashed = c.msgIsHashed
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
	c.c1 = c1
	c.c2 = c2
	c.aead = tv.Aead
	c.nonce = tv.Nonce
	c.msgIsHashed = tv.MsgIsHashed

	return nil
}

// ToHomomorphicCipherText returns the El-Gamal points that can be
// homomorphically multiplied
func (c CipherText) ToHomomorphicCipherText() *HomomorphicCipherText {
	return &HomomorphicCipherText{
		c1: c.c1,
		c2: c.c2,
	}
}

// Add combines two ciphertexts multiplicatively homomorphic
func (c HomomorphicCipherText) Add(rhs *HomomorphicCipherText) *HomomorphicCipherText {
	return &HomomorphicCipherText{
		c1: c.c1.Add(rhs.c1),
		c2: c.c2.Add(rhs.c2),
	}
}

// Decrypt returns the C2 - C1
func (c HomomorphicCipherText) Decrypt(dk *DecryptionKey) (curves.Point, error) {
	if dk == nil {
		return nil, internal.ErrNilArguments
	}
	return c.c2.Sub(c.c1.Mul(dk.x)), nil
}

func (c HomomorphicCipherText) MarshalBinary() ([]byte, error) {
	tv := new(homomorphicCipherTextMarshal)
	tv.C1 = c.c1.ToAffineCompressed()
	tv.C2 = c.c2.ToAffineCompressed()
	tv.Curve = c.c1.CurveName()
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
	c.c1 = c1
	c.c2 = c2
	return nil
}
