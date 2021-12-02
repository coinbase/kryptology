//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// This file implements the Ed25519 signature algorithm. See
// https://ed25519.cr.yp.to/.
//
// These functions are also compatible with the “Ed25519” function defined in
// RFC 8032. However, unlike RFC 8032's formulation, this package's private key
// representation includes a public key suffix to make multiple signing
// operations with the same key more efficient. This package refers to the RFC
// 8032 private key as the “seed”.
// This code is a port of the public domain, “ref10” implementation of ed25519
// from SUPERCOP.

package ted25519

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"io"
	"strconv"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32
	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey []byte

// Bytes returns the publicKey in byte array
func (p PublicKey) Bytes() []byte {
	return p
}

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (priv PrivateKey) Seed() []byte {
	seed := make([]byte, SeedSize)
	copy(seed, priv[:32])
	return seed
}

// Sign signs the given message with priv.
// Ed25519 performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to
// indicate the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) as the value for opts.
func (priv PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("ed25519: cannot sign hashed message")
	}
	sig, err := Sign(priv, message)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey, err := NewKeyFromSeed(seed)
	if err != nil {
		return nil, nil, err
	}
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[32:])

	return publicKey, privateKey, nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) (PrivateKey, error) {
	// Outline the function body so that the returned key can be stack-allocated.
	privateKey := make([]byte, PrivateKeySize)
	err := newKeyFromSeed(privateKey, seed)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func newKeyFromSeed(privateKey, seed []byte) error {
	if l := len(seed); l != SeedSize {
		return fmt.Errorf("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var hBytes [32]byte
	copy(hBytes[:], digest[:])

	h, err := new(curves.ScalarEd25519).SetBytesClamping(hBytes[:])
	if err != nil {
		return err
	}
	ed25519 := curves.ED25519()
	A := ed25519.ScalarBaseMult(h)

	publicKeyBytes := A.ToAffineCompressed()
	copy(privateKey, seed)
	copy(privateKey[32:], publicKeyBytes[:])
	return nil
}

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not PrivateKeySize.
func Sign(privateKey PrivateKey, message []byte) ([]byte, error) {
	// Outline the function body so that the returned signature can be
	// stack-allocated.
	signature := make([]byte, SignatureSize)
	err := sign(signature, privateKey, message)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func sign(signature, privateKey, message []byte) error {
	if l := len(privateKey); l != PrivateKeySize {
		return fmt.Errorf("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	var err error
	h := sha512.New()
	_, err = h.Write(privateKey[:32])
	if err != nil {
		return err
	}

	var digest1, messageDigest, hramDigest [64]byte
	var expandedSecretKey [32]byte
	_ = h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	h.Reset()
	_, err = h.Write(digest1[32:])
	if err != nil {
		return err
	}
	_, _ = h.Write(message)
	if err != nil {
		return err
	}
	_ = h.Sum(messageDigest[:0])

	r, err := new(curves.ScalarEd25519).SetBytesWide(messageDigest[:])
	if err != nil {
		return err
	}

	// R = r * G
	R := curves.ED25519().Point.Generator().Mul(r)
	encodedR := R.ToAffineCompressed()

	h.Reset()
	_, err = h.Write(encodedR[:])
	if err != nil {
		return err
	}
	_, err = h.Write(privateKey[32:])
	if err != nil {
		return err
	}
	_, err = h.Write(message)
	if err != nil {
		return err
	}
	_ = h.Sum(hramDigest[:0])

	// Set k and s
	k, err := new(curves.ScalarEd25519).SetBytesWide(hramDigest[:])
	if err != nil {
		return err
	}

	s, err := new(curves.ScalarEd25519).SetBytesClamping(expandedSecretKey[:])
	if err != nil {
		return err
	}

	// S = k*s + r
	S := k.MulAdd(s, r)
	copy(signature[:], encodedR[:])
	copy(signature[32:], S.Bytes()[:])
	return nil
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
// Previously publicKey is of type PublicKey
func Verify(publicKey PublicKey, message, sig []byte) (bool, error) {
	if l := len(publicKey); l != PublicKeySize {
		return false, fmt.Errorf("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&224 != 0 {
		return false, fmt.Errorf("ed25519: bad signature size: " + strconv.Itoa(len(sig)))
	}

	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)

	A, err := new(curves.PointEd25519).FromAffineCompressed(publicKeyBytes[:])
	if err != nil {
		return false, err
	}

	// Negate sets A = -A, and returns A. It actually negates X and T but keep Y and Z
	negA := A.Neg()

	h := sha512.New()
	_, err = h.Write(sig[:32])
	if err != nil {
		panic(err)
	}

	_, err = h.Write(publicKey[:])
	if err != nil {
		return false, err
	}

	_, err = h.Write(message)
	if err != nil {
		return false, err
	}

	var digest [64]byte
	_ = h.Sum(digest[:0])

	hReduced, err := new(curves.ScalarEd25519).SetBytesWide(digest[:])
	if err != nil {
		return false, err
	}

	var s [32]byte
	copy(s[:], sig[32:])
	sScalar, err := new(curves.ScalarEd25519).SetBytesCanonical(s[:])
	if err != nil {
		return false, err
	}

	// R' = hash * A + s * BasePoint
	R := new(curves.PointEd25519).VarTimeDoubleScalarBaseMult(hReduced, negA, sScalar)
	// Check R == R'
	return bytes.Equal(sig[:32], R.ToAffineCompressed()), nil
}
