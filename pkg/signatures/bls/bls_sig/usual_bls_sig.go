package bls_sig

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	bls12381 "github.com/coinbase/kryptology/pkg/core/curves/native/bls12-381"
	"github.com/coinbase/kryptology/pkg/signatures/bls/finitefield"
)

// Implement BLS signatures on the BLS12-381 curve
// according to https://crypto.standford.edu/~dabo/pubs/papers/BLSmultisig.html
// and https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
// this file implements signatures in G2 and public keys in G1.
// Public Keys and Signatures can be aggregated but the consumer
// must use proofs of possession to defend against rogue-key attacks.

const (
	// Public key size in G1
	PublicKeySize = 48
	// Signature size in G2
	SignatureSize = 96
	// Proof of Possession in G2
	ProofOfPossessionSize = 96
)

// Represents a public key in G1
type PublicKey struct {
	value bls12381.PointG1
}

// Serialize a public key to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return blsEngine.G1.ToCompressed(&pk.value), nil
}

// Deserialize a public key from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the public key
// otherwise it will return an error
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return fmt.Errorf("public key must be %d bytes", PublicKeySize)
	}
	p1, err := blsEngine.G1.FromCompressed(data)
	if err != nil {
		return err
	}
	if blsEngine.G1.IsZero(p1) {
		return fmt.Errorf("public keys cannot be zero")
	}
	pk.value = *p1
	return nil
}

// Represents a BLS signature in G2
type Signature struct {
	Value bls12381.PointG2
}

// Serialize a signature to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (sig Signature) MarshalBinary() ([]byte, error) {
	return blsEngine.G2.ToCompressed(&sig.Value), nil
}

func (sig Signature) verify(pk *PublicKey, message []byte, signDst string) (bool, error) {
	return pk.verifySignature(message, &sig, signDst)
}

// The AggregateVerify algorithm checks an aggregated signature over
// several (PK, message) pairs.
// The Signature is the output of aggregateSignatures
// Each message must be different or this will return false
// See section 3.1.1 from
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
func (sig Signature) aggregateVerify(pks []*PublicKey, msgs [][]byte, signDst string) (bool, error) {
	return sig.coreAggregateVerify(pks, msgs, signDst)
}

func (sig Signature) coreAggregateVerify(pks []*PublicKey, msgs [][]byte, signDst string) (bool, error) {
	if len(pks) < 1 {
		return false, fmt.Errorf("at least one key is required")
	}
	if len(msgs) < 1 {
		return false, fmt.Errorf("at least one message is required")
	}
	if len(pks) != len(msgs) {
		return false, fmt.Errorf("the number of public keys does not match the number of messages: %v != %v", len(pks), len(msgs))
	}
	if !blsEngine.G2.InCorrectSubgroup(&sig.Value) {
		return false, fmt.Errorf("signature is not in the correct subgroup")
	}

	dst := []byte(signDst)
	engine := bls12381.NewEngine()
	// e(pk_1, H(m_1))*...*e(pk_N, H(m_N)) == e(g1, s)
	// However, we use only one miller loop
	// by doing the equivalent of
	// e(pk_1, H(m_1))*...*e(pk_N, H(m_N)) * e(g1^-1, s) == 1
	for i, pk := range pks {
		if pk == nil {
			return false, fmt.Errorf("public key at %d is nil", i)
		}
		if engine.G1.IsZero(&pk.value) || !engine.G1.InCorrectSubgroup(&pk.value) {
			return false, fmt.Errorf("public key at %d is not in the correct subgroup", i)
		}
		p2, err := engine.G2.HashToCurve(sha256.New, msgs[i], dst)
		if err != nil {
			return false, err
		}
		engine.AddPair(&pk.value, p2)
	}
	engine.AddPairInv(engine.G1.One(), &sig.Value)
	return engine.Check()
}

// Deserialize a signature from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error
func (sig *Signature) UnmarshalBinary(data []byte) error {
	if len(data) != SignatureSize {
		return fmt.Errorf("signature must be %d bytes", SignatureSize)
	}
	p2, err := blsEngine.G2.FromCompressed(data)
	if err != nil {
		return err
	}
	if blsEngine.G2.IsZero(p2) {
		return fmt.Errorf("signatures cannot be zero")
	}
	sig.Value = *p2
	return nil
}

// Get the corresponding public key from a secret key
// Verifies the public key is in the correct subgroup
func (sk SecretKey) GetPublicKey() (*PublicKey, error) {
	result := blsEngine.G1.New()
	blsEngine.G1.MulScalar(result, blsEngine.G1.One(), &sk.value)
	if !blsEngine.G1.InCorrectSubgroup(result) || blsEngine.G1.IsZero(result) {
		return nil, fmt.Errorf("point is not in correct subgroup")
	}
	return &PublicKey{value: *result}, nil
}

// Compute a signature from a secret key and message
// This signature is deterministic which protects against
// attacks arising from signing with bad randomness like
// the nonce reuse attack on ECDSA. `message` is
// hashed to a point in G2 as described in to
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1
// See Section 2.6 in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
// nil message is not permitted but empty slice is allowed
func (sk SecretKey) createSignature(message []byte, dst string) (*Signature, error) {
	if message == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}
	if sk.value.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("invalid secret key")
	}
	p2, err := blsEngine.G2.HashToCurve(sha256.New, message, []byte(dst))
	if err != nil {
		return nil, err
	}
	result := blsEngine.G2.New()
	blsEngine.G2.MulScalar(result, p2, &sk.value)
	if !blsEngine.G2.InCorrectSubgroup(result) {
		return nil, fmt.Errorf("point is not on correct subgroup")
	}
	return &Signature{Value: *result}, nil
}

// Verify a signature is valid for the message under this public key.
// See Section 2.7 in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
func (pk PublicKey) verifySignature(message []byte, signature *Signature, dst string) (bool, error) {
	if signature == nil || message == nil || blsEngine.G1.IsZero(&pk.value) {
		return false, fmt.Errorf("signature and message and public key cannot be nil or zero")
	}
	if blsEngine.G2.IsZero(&signature.Value) || !blsEngine.G2.InCorrectSubgroup(&signature.Value) {
		return false, fmt.Errorf("signature is not in the correct subgroup")
	}
	engine := bls12381.NewEngine()

	p2, err := engine.G2.HashToCurve(sha256.New, message, []byte(dst))
	if err != nil {
		return false, err
	}
	// e(pk, H(m)) == e(g1, s)
	// However, we can reduce the number of miller loops
	// by doing the equivalent of
	// e(pk^-1, H(m)) * e(g1, s) == 1
	engine.AddPair(&pk.value, p2)
	engine.AddPairInv(engine.G1.One(), &signature.Value)
	return engine.Check()
}

// Combine public keys into one aggregated key
func aggregatePublicKeys(pks ...*PublicKey) (*PublicKey, error) {
	if len(pks) < 1 {
		return nil, fmt.Errorf("at least one public key is required")
	}
	result := blsEngine.G1.New()
	for i, k := range pks {
		if k == nil {
			return nil, fmt.Errorf("key at %d is nil, keys cannot be nil", i)
		}
		if !blsEngine.G1.InCorrectSubgroup(&k.value) {
			return nil, fmt.Errorf("key at %d is not in the correct subgroup", i)
		}
		blsEngine.G1.Add(result, result, &k.value)
	}
	return &PublicKey{value: *result}, nil
}

// Combine signatures into one aggregated signature
func aggregateSignatures(sigs ...*Signature) (*Signature, error) {
	if len(sigs) < 1 {
		return nil, fmt.Errorf("at least one signature is required")
	}
	result := blsEngine.G2.New()
	for i, s := range sigs {
		if s == nil {
			return nil, fmt.Errorf("signature at %d is nil, signature cannot be nil", i)
		}
		if !blsEngine.G2.InCorrectSubgroup(&s.Value) {
			return nil, fmt.Errorf("signature at %d is not in the correct subgroup", i)
		}
		blsEngine.G2.Add(result, result, &s.Value)
	}
	return &Signature{Value: *result}, nil
}

// A proof of possession scheme uses a separate public key validation
// step, called a proof of possession, to defend against rogue key
// attacks. This enables an optimization to aggregate signature
// verification for the case that all signatures are on the same
// message.
type ProofOfPossession struct {
	value bls12381.PointG2
}

// Generates a proof-of-possession (PoP) for this secret key. The PoP signature should be verified before
// before accepting any aggregate signatures related to the corresponding pubkey.
func (sk SecretKey) createProofOfPossession(popDst string) (*ProofOfPossession, error) {
	pk, err := sk.GetPublicKey()
	if err != nil {
		return nil, err
	}
	msg, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sig, err := sk.createSignature(msg, popDst)
	if err != nil {
		return nil, err
	}
	return &ProofOfPossession{value: sig.Value}, nil
}

// Serialize a proof of possession to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pop ProofOfPossession) MarshalBinary() ([]byte, error) {
	return blsEngine.G2.ToCompressed(&pop.value), nil
}

// Deserialize a proof of possession from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error
func (pop *ProofOfPossession) UnmarshalBinary(data []byte) error {
	p2 := new(Signature)
	err := p2.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	pop.value = p2.Value
	return nil
}

// Verifies that PoP is valid for this pubkey. In order to prevent rogue key attacks, a PoP must be validated
// for each pubkey in an aggregated signature.
func (pop ProofOfPossession) verify(pk *PublicKey, popDst string) (bool, error) {
	if pk == nil {
		return false, fmt.Errorf("public key cannot be nil")
	}
	msg, err := pk.MarshalBinary()
	if err != nil {
		return false, err
	}
	return pk.verifySignature(msg, &Signature{Value: pop.value}, popDst)
}

// Represents an MultiSignature in G2. A multisignature is used when multiple signatures
// are calculated over the same message vs an aggregate signature where each message signed
// is a unique.
type MultiSignature struct {
	value bls12381.PointG2
}

// Serialize a multi-signature to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (sig MultiSignature) MarshalBinary() ([]byte, error) {
	return blsEngine.G2.ToCompressed(&sig.value), nil
}

// Check a multisignature is valid for a multipublickey and a message
func (sig MultiSignature) verify(pk *MultiPublicKey, message []byte, signDst string) (bool, error) {
	if pk == nil {
		return false, fmt.Errorf("public key cannot be nil")
	}
	p := PublicKey{value: pk.value}
	return p.verifySignature(message, &Signature{Value: sig.value}, signDst)
}

// Deserialize a signature from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error
func (sig *MultiSignature) UnmarshalBinary(data []byte) error {
	if len(data) != SignatureSize {
		return fmt.Errorf("multi signature must be %v bytes", SignatureSize)
	}
	s2 := new(Signature)
	err := s2.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	sig.value = s2.Value
	return nil
}

// Represents accumulated multiple Public Keys in G1 for verifying a multisignature
type MultiPublicKey struct {
	value bls12381.PointG1
}

// Serialize a public key to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pk MultiPublicKey) MarshalBinary() ([]byte, error) {
	return blsEngine.G1.ToCompressed(&pk.value), nil
}

// Deserialize a public key from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the public key
// otherwise it will return an error
func (pk *MultiPublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return fmt.Errorf("multi public key must be %v bytes", PublicKeySize)
	}
	p1 := new(PublicKey)
	err := p1.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	pk.value = p1.value
	return nil
}

// Check a multisignature is valid for a multipublickey and a message
func (pk MultiPublicKey) verify(message []byte, sig *MultiSignature, signDst string) (bool, error) {
	return sig.verify(&pk, message, signDst)
}

// PartialSignature represents threshold Gap Diffie-Hellman BLS signature
// that can be combined with other partials to yield a completed BLS signature
// See section 3.2 in <https://www.cc.gatech.edu/~aboldyre/papers/bold.pdf>
type PartialSignature struct {
	Identifier byte
	Signature  *bls12381.PointG2
}

// partialSign creates a partial signature that can be combined with other partial signatures
// to yield a complete signature
func (sks SecretKeyShare) partialSign(message []byte, signDst string) (*PartialSignature, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty or nil")
	}
	p2, err := blsEngine.G2.HashToCurve(sha256.New, message, []byte(signDst))
	if err != nil {
		return nil, err
	}
	result := blsEngine.G2.New()
	blsEngine.G2.MulScalar(result, p2, sks.value.Secret.BigInt())
	if !blsEngine.G2.InCorrectSubgroup(result) {
		return nil, fmt.Errorf("point is not on correct subgroup")
	}
	return &PartialSignature{Identifier: sks.value.Identifier, Signature: result}, nil
}

// combineSigs gathers partial signatures and yields a complete signature
func combineSigs(partials []*PartialSignature) (*Signature, error) {
	if len(partials) < 2 {
		return nil, fmt.Errorf("must have at least 2 partial signatures")
	}
	if len(partials) > 255 {
		return nil, fmt.Errorf("unsupported to combine more than 255 signatures")
	}

	field := finitefield.New(blsEngine.G2.Q())
	xVars, yVars, err := splitXY(field, partials)

	if err != nil {
		return nil, err
	}

	sTmp := blsEngine.G2.New()
	sig := blsEngine.G2.New()

	// Lagrange interpolation
	x := field.Zero()
	for i, xi := range xVars {
		basis := field.One()

		for j, xj := range xVars {
			if i == j {
				continue
			}

			num := x.Sub(xj)  // x - x_m
			den := xi.Sub(xj) // x_j - x_m
			if den.IsEqual(field.Zero()) {
				return nil, fmt.Errorf("signatures cannot be recombined")
			}
			basis = basis.Mul(num.Div(den))
		}
		blsEngine.G2.MulScalar(sTmp, yVars[i], basis.BigInt())
		blsEngine.G2.Add(sig, sig, sTmp)
	}
	if !blsEngine.G2.InCorrectSubgroup(sig) {
		return nil, fmt.Errorf("signature is not in the correct subgroup")
	}

	return &Signature{Value: *sig}, nil
}

// Ensure no duplicates x values and convert x values to field elements
func splitXY(field *finitefield.Field, partials []*PartialSignature) ([]*finitefield.Element, []*bls12381.PointG2, error) {
	x := make([]*finitefield.Element, len(partials))
	y := make([]*bls12381.PointG2, len(partials))

	dup := make(map[byte]bool)

	for i, sp := range partials {
		if sp == nil {
			return nil, nil, fmt.Errorf("partial signature cannot be nil")
		}
		if _, exists := dup[sp.Identifier]; exists {
			return nil, nil, fmt.Errorf("duplicate signature included")
		}
		if !blsEngine.G2.InCorrectSubgroup(sp.Signature) {
			return nil, nil, fmt.Errorf("signature is not in the correct subgroup")
		}
		dup[sp.Identifier] = true
		x[i] = field.ElementFromBytes([]byte{sp.Identifier})
		y[i] = sp.Signature
	}
	return x, y, nil
}
