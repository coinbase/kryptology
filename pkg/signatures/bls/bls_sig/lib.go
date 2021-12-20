//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls_sig

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"

	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/finitefield"
	"github.com/coinbase/kryptology/pkg/signatures/bls/shamir"
	"golang.org/x/crypto/hkdf"
)

// Secret key in Fr
const SecretKeySize = 32

// Secret key share with identifier byte in Fr
const SecretKeyShareSize = 33

// The salt used with generating secret keys
// See section 2.3 from https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
const hkdfKeyGenSalt = "BLS-SIG-KEYGEN-SALT-"

var blsEngine = bls12381.NewEngine()

// Represents a value mod r where r is the curve order or
// order of the subgroups in G1 and G2
type SecretKey struct {
	value big.Int
}

func allRowsUnique(data [][]byte) bool {
	seen := make(map[string]bool)
	for _, row := range data {
		m := string(row)
		if _, ok := seen[m]; ok {
			return false
		}
		seen[m] = true
	}
	return true
}

func generateRandBytes(count int) ([]byte, error) {
	ikm := make([]byte, count)
	cnt, err := rand.Read(ikm)
	if err != nil {
		return nil, err
	}
	if cnt != count {
		return nil, fmt.Errorf("unable to read sufficient random data")
	}
	return ikm, nil
}

// Creates a new BLS secret key
// Input key material (ikm) MUST be at least 32 bytes long,
// but it MAY be longer.
func (sk SecretKey) Generate(ikm []byte) (*SecretKey, error) {
	if len(ikm) < 32 {
		return nil, fmt.Errorf("ikm is too short. Must be at least 32")
	}

	// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
	h := sha256.New()
	n, err := h.Write([]byte(hkdfKeyGenSalt))
	if err != nil {
		return nil, err
	}
	if n != len(hkdfKeyGenSalt) {
		return nil, fmt.Errorf("incorrect salt bytes written to be hashed")
	}
	salt := h.Sum(nil)

	ikm = append(ikm, 0)
	// Leaves key_info parameter as the default empty string
	// and just adds parameter I2OSP(L, 2)
	kdf := hkdf.New(sha256.New, ikm, salt, []byte{0, 48})
	okm := make([]byte, 48)
	read, err := kdf.Read(okm)
	if err != nil {
		return nil, err
	}
	if read != 48 {
		return nil, fmt.Errorf("failed to create private key")
	}
	x := new(big.Int).SetBytes(okm)
	v := new(big.Int).Mod(x, blsEngine.G1.Q())
	return &SecretKey{value: *v}, nil
}

// Serialize a secret key to raw bytes
func (sk SecretKey) MarshalBinary() ([]byte, error) {
	bytes := sk.value.Bytes()
	padding := make([]byte, SecretKeySize-len(bytes))
	bytes = append(padding, bytes...)
	return bytes, nil
}

// Deserialize a secret key from raw bytes
// Cannot be zero. Must be 32 bytes and cannot be all zeroes.
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03#section-2.3
func (sk *SecretKey) UnmarshalBinary(data []byte) error {
	if len(data) != SecretKeySize {
		return fmt.Errorf("secret key must be %d bytes", SecretKeySize)
	}
	zeros := make([]byte, len(data))
	if subtle.ConstantTimeCompare(data, zeros) == 1 {
		return fmt.Errorf("secret key cannot be zero")
	}
	sk.value.SetBytes(data)
	return nil
}

// SecretKeyShare is shamir share of a private key
type SecretKeyShare struct {
	value shamir.Share
}

// Serialize a secret key share to raw bytes
func (sks SecretKeyShare) MarshalBinary() ([]byte, error) {
	return sks.value.Bytes(), nil
}

// Deserialize a secret key share from raw bytes
func (sks *SecretKeyShare) UnmarshalBinary(data []byte) error {
	if len(data) != SecretKeyShareSize {
		return fmt.Errorf("secret key share must be %d bytes", SecretKeyShareSize)
	}

	zeros := make([]byte, len(data))
	if subtle.ConstantTimeCompare(data, zeros) == 1 {
		return fmt.Errorf("secret key share cannot be zero")
	}
	q := blsEngine.G1.Q()
	sks.value = *shamir.ShareFromBytes(data, finitefield.New(q))
	return nil
}

// thresholdizeSecretKey splits a composite secret key such that
// `threshold` partial signatures can be combined to form a composite signature
func thresholdizeSecretKey(secretKey *SecretKey, threshold, total uint) ([]*SecretKeyShare, error) {
	// Verify our parametes are acceptable.
	if secretKey == nil {
		return nil, fmt.Errorf("secret key is nil")
	}
	if threshold > total {
		return nil, fmt.Errorf("threshold cannot be greater than the total")
	}
	if threshold == 0 {
		return nil, fmt.Errorf("threshold cannot be zero")
	}
	if total <= 1 {
		return nil, fmt.Errorf("total must be larger than 1")
	}
	if total > 255 || threshold > 255 {
		return nil, fmt.Errorf("cannot have more than 255 shares")
	}

	// Marshal and split our secret key into shares
	sk, err := secretKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	q := blsEngine.G1.Q()
	shareSet, err := shamir.NewDealer(finitefield.New(q)).Split(sk, int(threshold), int(total))
	if err != nil {
		return nil, err
	}
	shares := shareSet.Shares

	// Verify we got the expected number of shares
	if uint(len(shares)) != total {
		return nil, fmt.Errorf("shamir.NewDealer return %v != %v shares", len(shares), total)
	}

	// Package our shares
	secrets := make([]*SecretKeyShare, len(shares))
	for i, s := range shares {
		sks := &SecretKeyShare{value: *s}
		secrets[i] = sks
	}

	return secrets, nil
}
