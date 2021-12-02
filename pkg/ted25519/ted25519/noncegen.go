//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"crypto/rand"
	"crypto/sha256"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"golang.org/x/crypto/hkdf"
	"io"
)

// NonceShare represents a share of a generated nonce.
type NonceShare struct {
	*KeyShare
}

// NewNonceShare is a NonceShare construction
func NewNonceShare(identifier byte, secret []byte) *NonceShare {
	return &NonceShare{NewKeyShare(identifier, secret)}
}

// NonceShareFromBytes unmashals a NonceShare from its bytes representation
func NonceShareFromBytes(bytes []byte) *NonceShare {
	return &NonceShare{KeyShareFromBytes(bytes)}
}

func generateSharableNonce(s *KeyShare, p PublicKey, m Message) (PublicKey, []byte, error) {
	// Create an HKDF reader that produces random bytes that we will use to create a nonce
	hkdf, err := generateRandomHkdf(s, p, m)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random nonce that is within the field range so that we can share it.
	//
	// This diverges from how the standard implementation treats it because their scalar
	// multiplication accepts values up to the curve order, but we must constrain it to be able to
	// split it and aggregate.
	//
	// WARN: This operation is not constant time and we are dealing with a secret value
	nonce, err := curves.NewField(curves.Ed25519Order()).RandomElement(hkdf)
	if err != nil {
		return nil, nil, err
	}

	nonceBytes := nonce.Bytes()
	reverseBytes := reverseBytes(nonceBytes)
	var reverseInput [32]byte
	copy(reverseInput[:], reverseBytes)
	scalar, err := new(curves.ScalarEd25519).SetBytesCanonical(reverseInput[:])
	if err != nil {
		return nil, nil, err
	}

	// Generate the nonce pubkey by multiplying it by the base point.
	noncePubkey := curves.ED25519().Point.Generator().Mul(scalar)

	return noncePubkey.ToAffineCompressed(), nonceBytes, nil
}

// GenerateSharedNonce generates a random nonce, splits it, and returns the nonce pubkey, nonce shares, and
// VSS commitments.
func GenerateSharedNonce(config *ShareConfiguration, s *KeyShare, p PublicKey, m Message) (
	PublicKey,
	[]*NonceShare,
	Commitments,
	error,
) {
	noncePubkey, nonce, err := generateSharableNonce(s, p, m)
	if err != nil {
		return nil, nil, nil, err
	}
	keyShares, vssCommitments, err := splitPrivateKey(config, nonce)
	if err != nil {
		return nil, nil, nil, err
	}

	nonceShares := make([]*NonceShare, len(keyShares))
	for i, k := range keyShares {
		nonceShares[i] = &NonceShare{k}
	}
	return noncePubkey, nonceShares, vssCommitments, nil
}

// Add returns the sum of two NonceShares.
func (n NonceShare) Add(other *NonceShare) *NonceShare {
	return &NonceShare{
		&KeyShare{
			// use Add method from the shamir.Share type to sum the shares
			// WARN: This is not constant time and deals with secrets
			n.ShamirShare.Add(other.ShamirShare),
		},
	}
}

// generateRandomHkdf returns an HMAC-based extract-and-expand Key Derivation Function (see RFC 5869).
func generateRandomHkdf(s *KeyShare, p PublicKey, m Message) (io.Reader, error) {
	// We _must_ introduce randomness to the HKDF to make the output non-deterministic because deterministic nonces open
	// up threshold schemes to potential nonce-reuse attacks. We continue to use the HKDF that takes in context about
	// what is going to be signed as it adds some protection against bad local randomness.
	randNonce := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand.Reader, randNonce); err != nil {
		return nil, err
	}

	var secret []byte
	secret = append(secret, s.Bytes()...)
	secret = append(secret, randNonce...)

	info := []byte("ted25519nonce")
	// We use info for non-secret inputs to limit an attacker's ability to influence the key.
	info = append(info, p.Bytes()...)
	info = append(info, m...)

	return hkdf.New(sha256.New, secret, nil, info), nil
}
