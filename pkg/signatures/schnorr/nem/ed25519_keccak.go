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

package nem

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"fmt"
	"io"
	"strconv"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/internal"
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

func Keccak512(data []byte) ([]byte, error) {
	k512 := sha3.NewLegacyKeccak512()
	_, err := k512.Write(data)
	if err != nil {
		return nil, err
	}
	return k512.Sum(nil), nil
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

	// Weird required step to get compatibility with the NEM test vectors
	// Have to reverse the bytes from the given seed
	digest, err := Keccak512(internal.ReverseScalarBytes(seed))
	if err != nil {
		return err
	}

	sc, err := edwards25519.NewScalar().SetBytesWithClamping(digest[:32])
	if err != nil {
		return err
	}

	A := edwards25519.Point{}
	A.ScalarBaseMult(sc)
	publicKeyBytes := A.Bytes()

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

	seed := privateKey[:32]
	digest, err := Keccak512(internal.ReverseScalarBytes(seed))
	if err != nil {
		return err
	}

	// H(seed) ie. privkey
	expandedSecretKey := digest[:32]
	sc, err := edwards25519.NewScalar().SetBytesWithClamping(expandedSecretKey)
	if err != nil {
		return err
	}

	// r = H(H(seed) + msg)
	hEngine := sha3.NewLegacyKeccak512()
	_, err = hEngine.Write(digest[32:])
	if err != nil {
		return err
	}

	_, err = hEngine.Write(message)
	if err != nil {
		return err
	}

	var hOut1 [64]byte
	hEngine.Sum(hOut1[:0])

	// hash output -> scalar
	// Take 64 byte output from keccak512 so need to set bytes as long
	r, err := edwards25519.NewScalar().SetUniformBytes(hOut1[:])
	if err != nil {
		return err
	}

	// R = r*G
	R := edwards25519.Point{}
	R.ScalarBaseMult(r)
	RBytes := R.Bytes()

	// s = H(R + pubkey + msg)
	hEngine.Reset()
	_, err = hEngine.Write(RBytes)
	if err != nil {
		return err
	}

	_, err = hEngine.Write(privateKey[32:])
	if err != nil {
		return err
	}

	_, err = hEngine.Write(message)
	if err != nil {
		return err
	}

	var hOut2 [64]byte
	hEngine.Sum(hOut2[:0])

	// hash output -> scalar
	// Take 64 byte output from keccak512 so need to set bytes as long
	h, err := edwards25519.NewScalar().SetUniformBytes(hOut2[:])
	if err != nil {
		return err
	}

	// s = (r + h * privKey)
	s := edwards25519.NewScalar().MultiplyAdd(h, sc, r)

	copy(signature[:], RBytes)
	copy(signature[32:], s.Bytes())

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

	RBytes := sig[:32]
	sBytes := sig[32:]

	var publicKeyBytes [32]byte
	copy(publicKeyBytes[:], publicKey)

	A := edwards25519.Point{}
	_, err := A.SetBytes(publicKeyBytes[:])
	if err != nil {
		return false, err
	}

	negA := edwards25519.Point{}
	negA.Negate(&A)

	// h = H(R + pubkey + msg)
	hEngine := sha3.NewLegacyKeccak512()
	_, err = hEngine.Write(RBytes)
	if err != nil {
		return false, err
	}

	_, err = hEngine.Write(publicKeyBytes[:])
	if err != nil {
		return false, err
	}

	_, err = hEngine.Write(message)
	if err != nil {
		return false, err
	}

	var hOut1 [64]byte
	hEngine.Sum(hOut1[:0])

	// hash output -> scalar
	// Take 64 byte output from keccak512 so need to set bytes as long
	h, err := edwards25519.NewScalar().SetUniformBytes(hOut1[:])
	if err != nil {
		return false, err
	}

	// s was generated in sign so can set as canonical
	s, err := edwards25519.NewScalar().SetCanonicalBytes(sBytes)
	if err != nil {
		return false, err
	}

	// R' = s*G - h*Pubkey = h*negPubkey + s*G
	RPrime := edwards25519.Point{}
	RPrime.VarTimeDoubleScalarBaseMult(h, &negA, s)
	RPrimeBytes := RPrime.Bytes()

	// Check R == R'
	return bytes.Equal(RBytes, RPrimeBytes), nil
}
