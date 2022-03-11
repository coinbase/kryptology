//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// SecretKey is a BBS+ signing key
type SecretKey struct {
	value curves.PairingScalar
}

func NewSecretKey(curve *curves.PairingCurve) (*SecretKey, error) {
	// The salt used with generating secret keys
	// See section 2.3 from https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04
	const hkdfKeyGenSalt = "BLS-SIG-KEYGEN-SALT-"
	const Size = 33
	var ikm [Size]byte
	cnt, err := crand.Read(ikm[:32])
	if err != nil {
		return nil, err
	}
	if cnt != Size-1 {
		return nil, fmt.Errorf("unable to read sufficient random data")
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

	// Leaves key_info parameter as the default empty string
	// and just adds parameter I2OSP(L, 2)
	kdf := hkdf.New(sha256.New, ikm[:], salt, []byte{0, 48})
	var okm [64]byte
	read, err := kdf.Read(okm[:48])
	if err != nil {
		return nil, err
	}
	if read != 48 {
		return nil, fmt.Errorf("failed to create secret key")
	}
	v, err := curve.Scalar.SetBytesWide(okm[:])
	if err != nil {
		return nil, err
	}
	value, ok := v.(curves.PairingScalar)
	if !ok {
		return nil, fmt.Errorf("invalid scalar")
	}
	return &SecretKey{
		value: value.SetPoint(curve.PointG2),
	}, nil
}

func NewKeys(curve *curves.PairingCurve) (*PublicKey, *SecretKey, error) {
	sk, err := NewSecretKey(curve)
	if err != nil {
		return nil, nil, err
	}
	return sk.PublicKey(), sk, nil
}

func (sk *SecretKey) Init(curve *curves.PairingCurve) *SecretKey {
	sk.value = curve.NewScalar()
	return sk
}

func (sk SecretKey) MarshalBinary() ([]byte, error) {
	return sk.value.Bytes(), nil
}

func (sk *SecretKey) UnmarshalBinary(in []byte) error {
	value, err := sk.value.SetBytes(in)
	if err != nil {
		return err
	}
	var ok bool
	sk.value, ok = value.(curves.PairingScalar)
	if !ok {
		return errors.New("incorrect type conversion")
	}
	return nil
}

// Sign generates a new signature where all messages are known to the signer
func (sk *SecretKey) Sign(generators *MessageGenerators, msgs []curves.Scalar) (*Signature, error) {
	if generators.length < len(msgs) {
		return nil, fmt.Errorf("not enough message generators")
	}
	if len(msgs) < 1 {
		return nil, fmt.Errorf("invalid messages")
	}
	if sk.value.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}

	drbg := sha3.NewShake256()
	_, _ = drbg.Write(sk.value.Bytes())
	addDeterministicNonceData(generators, msgs, drbg)
	// Should yield non-zero values for `e` and `s`, very small likelihood of being zero
	e := getNonZeroScalar(sk.value, drbg)
	s := getNonZeroScalar(sk.value, drbg)
	b := computeB(s, msgs, generators)
	exp, err := e.Add(sk.value).Invert()
	if err != nil {
		return nil, err
	}
	return &Signature{
		a: b.Mul(exp).(curves.PairingPoint),
		e: e,
		s: s,
	}, nil
}

// PublicKey returns the corresponding public key
func (sk *SecretKey) PublicKey() *PublicKey {
	return &PublicKey{
		value: sk.value.Point().Generator().Mul(sk.value).(curves.PairingPoint),
	}
}

// computes g1 + s * h0 + msgs[0] * h[0] + msgs[1] * h[1] ...
func computeB(s curves.Scalar, msgs []curves.Scalar, generators *MessageGenerators) curves.PairingPoint {
	nMsgs := len(msgs)
	points := make([]curves.Point, nMsgs+2)
	points[1] = generators.Get(0)
	points[0] = points[1].Generator()

	scalars := make([]curves.Scalar, nMsgs+2)
	scalars[0] = msgs[0].One()
	scalars[1] = s
	for i, m := range msgs {
		points[i+2] = generators.Get(i + 1)
		scalars[i+2] = m
	}
	pt := points[0].SumOfProducts(points, scalars)
	return pt.(curves.PairingPoint)
}

func addDeterministicNonceData(generators *MessageGenerators, msgs []curves.Scalar, drbg io.Writer) {
	for i := 0; i <= generators.length; i++ {
		_, _ = drbg.Write(generators.Get(i).ToAffineUncompressed())
	}
	for _, m := range msgs {
		_, _ = drbg.Write(m.Bytes())
	}
}

func getNonZeroScalar(sc curves.Scalar, reader io.Reader) curves.Scalar {
	// Should yield non-zero values for `e` and `s`, very small likelihood of being zero
	e := sc.Random(reader)
	for e.IsZero() {
		e = sc.Random(reader)
	}
	return e
}
