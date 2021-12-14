//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"fmt"
	"git.sr.ht/~sircmpwn/go-bare"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
)

type encryptionKeyMarshal struct {
	Value []byte `bare:"value"`
	Curve string `bare:"curve"`
}

// EncryptParams is all the options for doing verifiable encryption.
// Message must be supplied and is the value to be encrypted.
// MessageIsHashed defines whether Message represents an unhashed arbitrary
// byte sequence or already represents a scalar in the elliptic curve.
// Domain is an optional domain separation tag and used to generate a separate
// point for the pedersen commitment in El-Gamal ciphertexts.
// Blinding is blinding factor (bf) of the El-Gamal ciphertext. If nil
// a bf is generated at random.
// GenProof indicates whether to return a proof of encryption correctness to the
// corresponding public key.
// ProofNonce is the nonce used to generate the one time proof. This value
// is required if GenProof is true.
type EncryptParams struct {
	MessageIsHashed bool
	Domain          []byte
	Blinding        curves.Scalar
	GenProof        bool
	ProofNonce      []byte
}

// EncryptionKey encrypts a message to a ciphertext from which
// zero-knowledge proofs can be derived
type EncryptionKey struct {
	value curves.Point
}

// NewKeys creates a new key pair for El-Gamal encryption
func NewKeys(curve *curves.Curve) (*EncryptionKey, *DecryptionKey, error) {
	if curve == nil {
		return nil, nil, fmt.Errorf("invalid curve")
	}
	x := curve.Scalar.Random(crand.Reader)
	if x == nil {
		return nil, nil, fmt.Errorf("cannot generate decryption key")
	}
	value := curve.Point.Generator().Mul(x)
	if value == nil {
		return nil, nil, fmt.Errorf("cannot generate encryption key")
	}
	return &EncryptionKey{value}, &DecryptionKey{x}, nil
}

// MarshalBinary serializes a key to bytes
func (ek EncryptionKey) MarshalBinary() ([]byte, error) {
	tv := new(encryptionKeyMarshal)
	tv.Curve = ek.value.CurveName()
	tv.Value = ek.value.ToAffineCompressed()
	return bare.Marshal(tv)
}

// UnmarshalBinary deserializes a key from bytes
func (ek *EncryptionKey) UnmarshalBinary(data []byte) error {
	tv := new(encryptionKeyMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)
	if curve == nil {
		return fmt.Errorf("unknown curve")
	}
	value, err := curve.Point.FromAffineCompressed(tv.Value)
	if err != nil {
		return err
	}
	ek.value = value
	return nil
}

func (ek EncryptionKey) HomomorphicEncrypt(msg curves.Scalar) (*HomomorphicCipherText, error) {
	r := ek.value.Scalar().Random(crand.Reader)
	return &HomomorphicCipherText{
		C1: ek.value.Generator().Mul(r),
		C2: ek.value.Mul(r).Add(ek.value.Generator().Mul(msg)),
	}, nil
}

func (ek EncryptionKey) encryptWithRandNonce(msg []byte, msgIsHashed bool, r curves.Scalar, h curves.Point, nonce []byte) (*CipherText, error) {
	// r * Q
	t := ek.value.Mul(r)
	// Derive AEAD encryption key
	aeadKey, err := core.FiatShamir(new(big.Int).SetBytes(t.ToAffineCompressed()))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// C1 = r * G
	c1 := ek.value.Generator().Mul(r)
	// C2 = m * H + r * Q
	msgScalar := r.New(0)
	if msgIsHashed {
		msgScalar, err = msgScalar.SetBytes(msg)
		if err != nil {
			return nil, err
		}
	} else {
		msgScalar = msgScalar.Hash(msg)
	}
	c2 := h.Mul(msgScalar).Add(t)

	aad := c1.ToAffineUncompressed()
	aad = append(aad, c2.ToAffineUncompressed()...)
	// AAD = C1 || C2
	// this protects them from modifications
	aead := aesGcm.Seal(nil, nonce, msg, aad)

	return &CipherText{
		c1, c2, nonce, aead, msgIsHashed,
	}, nil
}

func (ek EncryptionKey) genNonce() []byte {
	var nonce [12]byte
	n, err := crand.Read(nonce[:])
	if err != nil {
		return nil
	}
	if n != 12 {
		return nil
	}
	return nonce[:]
}
