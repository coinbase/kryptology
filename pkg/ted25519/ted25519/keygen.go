//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import (
	"encoding/binary"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
)

// PublicKeyFromBytes converts byte array into PublicKey byte array
func PublicKeyFromBytes(bytes []byte) ([]byte, error) {
	if l := len(bytes); l != PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: %d", l)
	}

	return bytes, nil
}

// KeyShare represents a share of a generated key.
type KeyShare struct {
	*v1.ShamirShare
}

// NewKeyShare is a KeyShare constructor.
func NewKeyShare(identifier byte, secret []byte) *KeyShare {
	field := curves.NewField(curves.Ed25519Order())
	return &KeyShare{v1.NewShamirShare(uint32(identifier), secret, field)}
}

// Commitments is a collection of public keys with each coefficient of a polynomial as the secret keys.
type Commitments []curves.Point

// CommitmentsToBytes converts commitments to bytes
func (commitments Commitments) CommitmentsToBytes() [][]byte {
	bytes := make([][]byte, len(commitments))

	for i, c := range commitments {
		bytes[i] = c.ToAffineCompressed()
	}

	return bytes
}

// CommitmentsFromBytes converts bytes to commitments
func CommitmentsFromBytes(bytes [][]byte) (Commitments, error) {
	comms := make([]curves.Point, len(bytes))
	for i, pubKeyBytes := range bytes {
		pubKey, err := PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			return nil, err
		}
		comms[i], err = new(curves.PointEd25519).FromAffineCompressed(pubKey)
		if err != nil {
			return nil, err
		}
	}
	return comms, nil
}

// KeyShareFromBytes converts byte array into KeyShare type
func KeyShareFromBytes(bytes []byte) *KeyShare {
	field := curves.NewField(curves.Ed25519Order())
	element := field.ElementFromBytes(bytes[4:])

	// We set first 4 bytes as identifier
	identifier := binary.BigEndian.Uint32(bytes[:4])
	return &KeyShare{&v1.ShamirShare{Identifier: identifier, Value: element}}
}

// ShareConfiguration sets threshold and limit for the protocol
type ShareConfiguration struct {
	T int // threshold
	N int // total shares
}

// generateSharableKey generates a random key and returns the public key and private key in
// big-endian encoding. It returns an error if it cannot acquire sufficient randomness.
func generateSharableKey() (PublicKey, []byte, error) {
	pub, priv, err := GenerateKey(nil)
	if err != nil {
		return nil, nil, err
	}

	// Internally the PrivateKey type is represented as the seed || public key, but we want to pull
	// out seed to share which is the actual private key.
	seed := priv.Seed()

	// We must apply the key expansion to the seed before splitting the key.
	// Ed25519 signing by default will apply this during signature generation, but since it involves
	// a hash function, it breaks the relationship between shares and breaks aggregating signatures.
	// Our signature generation does not apply this mutation at signing time.
	//
	// As per anything that comes from the ed25519 library this value should be treated as
	// little-endian so we reverse it before using it.
	expandedSeed := reverseBytes(ExpandSeed(seed))

	// Lastly we must reduce this value into the size of the field so we can share it. This diverges
	// from how the standard implementation treats this because their scalar multiplication accepts
	// values up to the curve order but we must constrain it to be able to split it and aggregate.
	//
	// If you read the documentation for the ReducedElementFromBytes function we call below, it
	// includes a big warning about how it will return non-uniform outputs depending on the input.
	// This is true, but not a concern for keygen specifically because the value we are providing it
	// has been generated as the ed25519 spec requires, which has a slight bias by definition of how
	// the ExpandSeed operation works.
	field := &curves.Field{Int: curves.Ed25519Order()}
	expandedSeedReduced := field.ReducedElementFromBytes(expandedSeed)

	return pub, expandedSeedReduced.Bytes(), nil
}

// GenerateSharedKey generates a random key, splits it, and returns the public key, shares, and VSS commitments.
func GenerateSharedKey(config *ShareConfiguration) (PublicKey, []*KeyShare, Commitments, error) {
	pub, priv, err := generateSharableKey()
	//pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, nil, err
	}

	keyShares, commitments, err := splitPrivateKey(config, priv)
	if err != nil {
		return nil, nil, nil, err
	}

	return pub, keyShares, commitments, nil
}

// splitPrivateKey splits the secret into a set of secret shares and creates a set of commitments of them.
func splitPrivateKey(config *ShareConfiguration, priv []byte) ([]*KeyShare, Commitments, error) {
	commitments, shares, err := split(priv, config)
	if err != nil {
		return nil, nil, err
	}

	keyShares := make([]*KeyShare, len(shares))
	for i, s := range shares {
		keyShares[i] = &KeyShare{s}
	}
	return keyShares, commitments, nil
}

// split contains core operations to split the secret and generate commitments.
func split(secret []byte, config *ShareConfiguration) ([]curves.Point, []*v1.ShamirShare, error) {
	field := curves.NewField(curves.Ed25519Order())
	shamir, err := v1.NewShamir(config.T, config.N, field)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in NewShamir")
	}
	shares, poly, err := shamir.GetSharesAndPolynomial(secret)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in GetSharesAndPolynomial")
	}

	// Generate the verifiable commitments to the polynomial for the shares
	verifiers := make([]curves.Point, len(poly.Coefficients))
	// curve := sharing.Ed25519()
	for i, c := range poly.Coefficients {
		// We have to reverse each coefficient, which is different than the method sharing.Split
		reverseC := reverseBytes(c.Bytes())
		var reverseInput [32]byte
		copy(reverseInput[:], reverseC)
		cScalar, err := new(curves.ScalarEd25519).SetBytesCanonical(reverseInput[:])
		if err != nil {
			return nil, nil, fmt.Errorf("Error in SetBytesCanonical reverseC")
		}
		v := curves.ED25519().Point.Generator().Mul(cScalar)
		verifiers[i] = v
	}
	return verifiers, shares, nil
}

// Reconstruct recovers the secret from a set of secret shares.
func Reconstruct(keyShares []*KeyShare, config *ShareConfiguration) ([]byte, error) {
	curve := v1.Ed25519()
	field := curves.NewField(curve.Params().N)
	shamir, err := v1.NewShamir(config.T, config.N, field)
	if err != nil {
		return nil, err
	}

	shares := make([]*v1.ShamirShare, len(keyShares))
	for i, s := range keyShares {
		shares[i] = s.ShamirShare
	}
	return shamir.Combine(shares...)
}

// VerifyVSS validates that a Share represents a solution to a Shamir polynomial
// in which len(commitments) + 1 solutions are required to construct the private
// key for the public key at commitments[0].
func (share *KeyShare) VerifyVSS(commitments Commitments, config *ShareConfiguration) (bool, error) {
	if len(commitments) < config.T {
		return false, fmt.Errorf("not enough verifiers to check")
	}
	field := curves.NewField(curves.Ed25519Order())
	xBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(xBytes, share.Identifier)
	x := field.ElementFromBytes(xBytes)
	i := share.Value.Modulus.One()

	// c_0
	rhs := commitments[0]

	// Compute the sum of products
	// c_0 * c_1^i * c_2^{i^2} *c_3^{i^3}
	for j := 1; j < len(commitments); j++ {
		// i *= x
		i = i.Mul(x)

		var iBytes [32]byte
		copy(iBytes[:], i.Bytes()[:])
		iScalar, err := new(curves.ScalarEd25519).SetBytesCanonical(iBytes[:])
		if err != nil {
			return false, fmt.Errorf("Error in SetBytesCanonical iBytes")
		}
		c := commitments[j].Mul(iScalar)

		// ...* c_j^{i^j}
		rhs = rhs.Add(c)
	}

	vValue := reverseBytes(share.Value.Bytes())
	var vInput [32]byte
	copy(vInput[:], vValue)
	vScalar, err := new(curves.ScalarEd25519).SetBytes(vInput[:])
	if err != nil {
		return false, err
	}
	lhs := curves.ED25519().ScalarBaseMult(vScalar)

	// Check if lhs == rhs
	return lhs.Equal(rhs), nil
}
