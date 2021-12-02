//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"crypto/sha512"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"strconv"
)

// GeAdd returns the sum of two public keys, a and b.
func GeAdd(a PublicKey, b PublicKey) PublicKey {
	aPoint, err := new(curves.PointEd25519).FromAffineCompressed(a)
	if err != nil {
		panic("attempted to add invalid point: a")
	}
	bPoint, err := new(curves.PointEd25519).FromAffineCompressed(b)
	if err != nil {
		panic("attempted to add invalid point: b")
	}

	sum := aPoint.Add(bPoint)
	return sum.ToAffineCompressed()
}

// ExpandSeed applies the standard Ed25519 transform to the seed to turn it into the real private
// key that is used for signing. It returns the expanded seed.
func ExpandSeed(seed []byte) []byte {
	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	return digest[:32]
}

// reverseBytes returns a new slice of the input bytes reversed
func reverseBytes(inBytes []byte) []byte {
	outBytes := make([]byte, len(inBytes))

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}

// ThresholdSign is used for creating signatures for threshold protocols that replace the values of
// the private key and nonce with shamir shares instead. Because of this we must have a custom
// signing implementation that accepts arguments for values that cannot be derived anymore and
// removes the extended key generation since that should be done before the secret is shared.
//
// expandedSecretKeyShare and rShare must be little-endian.
func ThresholdSign(
	expandedSecretKeyShare []byte, publicKey PublicKey,
	message []byte,
	rShare []byte, R PublicKey, // nolint:gocritic
) []byte {
	// These length checks are are sanity checks where we panic if a provided value falls outside of the expected range.
	// These should never fail in practice but serve to protect us from some bug that would cause us to produce
	// signatures using a zero value or clipping off extra bytes unintentionally.
	//
	// We don't specifically check for 32 byte values as any value within the subgroup field could show up here. This is
	// different than the upstream Ed25519 which does, but this seems to be a result of how they initialize their byte
	// slices to constants and does not guarantee the value itself is 32 bytes without padding.
	if l := len(expandedSecretKeyShare); l == 0 || l > 32 {
		panic("ed25519: bad key share length: " + strconv.Itoa(l))
	}
	if l := len(rShare); l == 0 || l > 32 {
		panic("ed25519: bad nonce share length: " + strconv.Itoa(l))
	}

	var expandedSecretKey, rBytes [32]byte
	copy(expandedSecretKey[:], expandedSecretKeyShare)
	copy(rBytes[:], rShare)

	// c = H(R || A || m) mod q
	var hramDigest [64]byte
	var err error
	h := sha512.New()
	_, err = h.Write(R[:])
	if err != nil {
		panic(err)
	}
	_, err = h.Write(publicKey[:])
	if err != nil {
		panic(err)
	}
	_, err = h.Write(message)
	if err != nil {
		panic(err)
	}
	_ = h.Sum(hramDigest[:0])

	// Set c, x and r
	c, err := new(curves.ScalarEd25519).SetBytesWide(hramDigest[:])
	if err != nil {
		panic(err)
	}

	x, err := new(curves.ScalarEd25519).SetBytesCanonical(expandedSecretKey[:])
	if err != nil {
		panic(err)
	}

	r, err := new(curves.ScalarEd25519).SetBytesCanonical(rBytes[:])
	if err != nil {
		panic(err)
	}

	// s = cx+r
	s := c.MulAdd(x, r)

	signature := make([]byte, SignatureSize)
	copy(signature, R[:])
	copy(signature[32:], s.Bytes()[:])

	return signature
}
