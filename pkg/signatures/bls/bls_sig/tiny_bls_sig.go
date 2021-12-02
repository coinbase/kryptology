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
// this file implements signatures in G1 and public keys in G2.
// Public Keys and Signatures can be aggregated but the consumer
// must use proofs of possession to defend against rogue-key attacks.

const (
	// Public key size in G2
	PublicKeyVtSize = 96
	// Signature size in G1
	SignatureVtSize = 48
	// Proof of Possession in G1
	ProofOfPossessionVtSize = 48
)

// Represents a public key in G2
type PublicKeyVt struct {
	value bls12381.PointG2
}

// Serialize a public key to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pk *PublicKeyVt) MarshalBinary() ([]byte, error) {
	return blsEngine.G2.ToCompressed(&pk.value), nil
}

// Deserialize a public key from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the public key
// otherwise it will return an error
func (pk *PublicKeyVt) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeyVtSize {
		return fmt.Errorf("public key must be %d bytes", PublicKeySize)
	}
	p2, err := blsEngine.G2.FromCompressed(data)
	if err != nil {
		return err
	}
	if blsEngine.G2.IsZero(p2) {
		return fmt.Errorf("public keys cannot be zero")
	}
	pk.value = *p2
	return nil
}

// Represents a BLS signature in G1
type SignatureVt struct {
	value bls12381.PointG1
}

// Serialize a signature to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (sig *SignatureVt) MarshalBinary() ([]byte, error) {
	return blsEngine.G1.ToCompressed(&sig.value), nil
}

func (sig *SignatureVt) verify(pk *PublicKeyVt, message []byte, signDstVt string) (bool, error) {
	return pk.verifySignatureVt(message, sig, signDstVt)
}

// The AggregateVerify algorithm checks an aggregated signature over
// several (PK, message) pairs.
// The Signature is the output of aggregateSignaturesVt
// Each message must be different or this will return false.
// See section 3.1.1 from
// https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
func (sig *SignatureVt) aggregateVerify(pks []*PublicKeyVt, msgs [][]byte, signDstVt string) (bool, error) {
	return sig.coreAggregateVerify(pks, msgs, signDstVt)
}

func (sig *SignatureVt) coreAggregateVerify(pks []*PublicKeyVt, msgs [][]byte, signDstVt string) (bool, error) {
	if len(pks) < 1 {
		return false, fmt.Errorf("at least one key is required")
	}
	if len(msgs) < 1 {
		return false, fmt.Errorf("at least one message is required")
	}
	if len(pks) != len(msgs) {
		return false, fmt.Errorf("the number of public keys does not match the number of messages: %v != %v", len(pks), len(msgs))
	}
	if !blsEngine.G1.InCorrectSubgroup(&sig.value) {
		return false, fmt.Errorf("signature is not in the correct subgroup")
	}

	engine := bls12381.NewEngine()
	dst := []byte(signDstVt)
	// e(H(m_1), pk_1)*...*e(H(m_N), pk_N) == e(s, g2)
	// However, we use only one miller loop
	// by doing the equivalent of
	// e(H(m_1), pk_1)*...*e(H(m_N), pk_N) * e(s^-1, g2) == 1
	for i, pk := range pks {
		if pk == nil {
			return false, fmt.Errorf("public key at %d is nil", i)
		}
		if engine.G2.IsZero(&pk.value) || !engine.G2.InCorrectSubgroup(&pk.value) {
			return false, fmt.Errorf("public key at %d is not in the correct subgroup", i)
		}
		p1, err := engine.G1.HashToCurve(sha256.New, msgs[i], dst)
		if err != nil {
			return false, err
		}
		engine.AddPair(p1, &pk.value)
	}
	g2 := engine.G2.One()
	engine.G2.Neg(g2, g2)
	engine.AddPair(&sig.value, g2)
	return engine.Check()
}

// Deserialize a signature from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error
func (sig *SignatureVt) UnmarshalBinary(data []byte) error {
	if len(data) != SignatureVtSize {
		return fmt.Errorf("signature must be %d bytes", SignatureSize)
	}
	p1, err := blsEngine.G1.FromCompressed(data)
	if err != nil {
		return err
	}
	if blsEngine.G1.IsZero(p1) {
		return fmt.Errorf("signatures cannot be zero")
	}
	sig.value = *p1
	return nil
}

// Get the corresponding public key from a secret key
// Verifies the public key is in the correct subgroup
func (sk *SecretKey) GetPublicKeyVt() (*PublicKeyVt, error) {
	result := blsEngine.G2.New()
	blsEngine.G2.MulScalar(result, blsEngine.G2.One(), &sk.value)
	if !blsEngine.G2.InCorrectSubgroup(result) || blsEngine.G2.IsZero(result) {
		return nil, fmt.Errorf("point is not in correct subgroup")
	}
	return &PublicKeyVt{value: *result}, nil
}

// Compute a signature from a secret key and message
// This signature is deterministic which protects against
// attacks arising from signing with bad randomness like
// the nonce reuse attack on ECDSA. `message` is
// hashed to a point in G1 as described in to
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1
// See Section 2.6 in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
// nil message is not permitted but empty slice is allowed
func (sk *SecretKey) createSignatureVt(message []byte, dstVt string) (*SignatureVt, error) {
	if message == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}
	if sk.value.Cmp(big.NewInt(0)) == 0 {
		return nil, fmt.Errorf("invalid secret key")
	}
	p1, err := blsEngine.G1.HashToCurve(sha256.New, message, []byte(dstVt))
	if err != nil {
		return nil, err
	}
	result := blsEngine.G1.New()
	blsEngine.G1.MulScalar(result, p1, &sk.value)
	if !blsEngine.G1.InCorrectSubgroup(result) {
		return nil, fmt.Errorf("point is not in correct subgroup")
	}
	return &SignatureVt{value: *result}, nil
}

// Verify a signature is valid for the message under this public key.
// See Section 2.7 in https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-03
func (pk PublicKeyVt) verifySignatureVt(message []byte, signature *SignatureVt, dstVt string) (bool, error) {
	if signature == nil || message == nil || blsEngine.G2.IsZero(&pk.value) {
		return false, fmt.Errorf("signature and message and public key cannot be nil or zero")
	}
	if blsEngine.G1.IsZero(&signature.value) || !blsEngine.G1.InCorrectSubgroup(&signature.value) {
		return false, fmt.Errorf("signature is not in the correct subgroup")
	}
	engine := bls12381.NewEngine()

	p1, err := engine.G1.HashToCurve(sha256.New, message, []byte(dstVt))
	if err != nil {
		return false, err
	}
	// e(H(m), pk) == e(s, g2)
	// However, we can reduce the number of miller loops
	// by doing the equivalent of
	// e(H(m)^-1, pk) * e(s, g2) == 1
	engine.AddPairInv(p1, &pk.value)
	engine.AddPair(&signature.value, engine.G2.One())
	return engine.Check()
}

// Combine public keys into one aggregated key
func aggregatePublicKeysVt(pks ...*PublicKeyVt) (*PublicKeyVt, error) {
	if len(pks) < 1 {
		return nil, fmt.Errorf("at least one public key is required")
	}
	result := blsEngine.G2.New()
	for i, k := range pks {
		if k == nil {
			return nil, fmt.Errorf("key at %d is nil, keys cannot be nil", i)
		}
		if !blsEngine.G2.InCorrectSubgroup(&k.value) {
			return nil, fmt.Errorf("key at %d is not in the correct subgroup", i)
		}
		blsEngine.G2.Add(result, result, &k.value)
	}
	return &PublicKeyVt{value: *result}, nil
}

// Combine signatures into one aggregated signature
func aggregateSignaturesVt(sigs ...*SignatureVt) (*SignatureVt, error) {
	if len(sigs) < 1 {
		return nil, fmt.Errorf("at least one signature is required")
	}
	result := blsEngine.G1.New()
	for i, s := range sigs {
		if s == nil {
			return nil, fmt.Errorf("signature at %d is nil, signature cannot be nil", i)
		}
		if !blsEngine.G1.InCorrectSubgroup(&s.value) {
			return nil, fmt.Errorf("signature at %d is not in the correct subgroup", i)
		}
		blsEngine.G1.Add(result, result, &s.value)
	}
	return &SignatureVt{value: *result}, nil
}

// A proof of possession scheme uses a separate public key validation
// step, called a proof of possession, to defend against rogue key
// attacks. This enables an optimization to aggregate signature
// verification for the case that all signatures are on the same
// message.
type ProofOfPossessionVt struct {
	value bls12381.PointG1
}

// Generates a proof-of-possession (PoP) for this secret key. The PoP signature should be verified before
// before accepting any aggregate signatures related to the corresponding pubkey.
func (sk *SecretKey) createProofOfPossessionVt(popDstVt string) (*ProofOfPossessionVt, error) {
	pk, err := sk.GetPublicKeyVt()
	if err != nil {
		return nil, err
	}
	msg, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sig, err := sk.createSignatureVt(msg, popDstVt)
	if err != nil {
		return nil, err
	}
	return &ProofOfPossessionVt{value: sig.value}, nil
}

// Serialize a proof of possession to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pop *ProofOfPossessionVt) MarshalBinary() ([]byte, error) {
	return blsEngine.G1.ToCompressed(&pop.value), nil
}

// Deserialize a proof of possession from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error
func (pop *ProofOfPossessionVt) UnmarshalBinary(data []byte) error {
	p1 := new(SignatureVt)
	err := p1.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	pop.value = p1.value
	return nil
}

// Verifies that PoP is valid for this pubkey. In order to prevent rogue key attacks, a PoP must be validated
// for each pubkey in an aggregated signature.
func (pop *ProofOfPossessionVt) verify(pk *PublicKeyVt, popDstVt string) (bool, error) {
	if pk == nil {
		return false, fmt.Errorf("public key cannot be nil")
	}
	msg, err := pk.MarshalBinary()
	if err != nil {
		return false, err
	}
	return pk.verifySignatureVt(msg, &SignatureVt{value: pop.value}, popDstVt)
}

// Represents an MultiSignature in G1. A multisignature is used when multiple signatures
// are calculated over the same message vs an aggregate signature where each message signed
// is a unique.
type MultiSignatureVt struct {
	value bls12381.PointG1
}

// Serialize a multi-signature to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (sig *MultiSignatureVt) MarshalBinary() ([]byte, error) {
	return blsEngine.G1.ToCompressed(&sig.value), nil
}

// Check a multisignature is valid for a multipublickey and a message
func (sig *MultiSignatureVt) verify(pk *MultiPublicKeyVt, message []byte, signDstVt string) (bool, error) {
	if pk == nil {
		return false, fmt.Errorf("public key cannot be nil")
	}
	p := &PublicKeyVt{value: pk.value}
	return p.verifySignatureVt(message, &SignatureVt{value: sig.value}, signDstVt)
}

// Deserialize a signature from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the Signature
// otherwise it will return an error
func (sig *MultiSignatureVt) UnmarshalBinary(data []byte) error {
	if len(data) != SignatureVtSize {
		return fmt.Errorf("multi signature must be %v bytes", SignatureSize)
	}
	s1 := new(SignatureVt)
	err := s1.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	sig.value = s1.value
	return nil
}

// Represents accumulated multiple Public Keys in G2 for verifying a multisignature
type MultiPublicKeyVt struct {
	value bls12381.PointG2
}

// Serialize a public key to a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
func (pk *MultiPublicKeyVt) MarshalBinary() ([]byte, error) {
	return blsEngine.G2.ToCompressed(&pk.value), nil
}

// Deserialize a public key from a byte array in compressed form.
// See
// https://github.com/zcash/librustzcash/blob/master/pairing/src/bls12_381/README.md#serialization
// https://docs.rs/bls12_381/0.1.1/bls12_381/notes/serialization/index.html
// If successful, it will assign the public key
// otherwise it will return an error
func (pk *MultiPublicKeyVt) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeyVtSize {
		return fmt.Errorf("multi public key must be %v bytes", PublicKeySize)
	}
	p2 := new(PublicKeyVt)
	err := p2.UnmarshalBinary(data)
	if err != nil {
		return err
	}
	pk.value = p2.value
	return nil
}

// Check a multisignature is valid for a multipublickey and a message
func (pk *MultiPublicKeyVt) verify(message []byte, sig *MultiSignatureVt, signDstVt string) (bool, error) {
	return sig.verify(pk, message, signDstVt)
}

// PartialSignatureVt represents threshold Gap Diffie-Hellman BLS signature
// that can be combined with other partials to yield a completed BLS signature
// See section 3.2 in <https://www.cc.gatech.edu/~aboldyre/papers/bold.pdf>
type PartialSignatureVt struct {
	identifier byte
	signature  bls12381.PointG1
}

// partialSignVt creates a partial signature that can be combined with other partial signatures
// to yield a complete signature
func (sks *SecretKeyShare) partialSignVt(message []byte, signDst string) (*PartialSignatureVt, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty or nil")
	}
	p1, err := blsEngine.G1.HashToCurve(sha256.New, message, []byte(signDst))
	if err != nil {
		return nil, err
	}
	result := blsEngine.G1.New()
	blsEngine.G1.MulScalar(result, p1, sks.value.Secret.BigInt())
	if !blsEngine.G1.InCorrectSubgroup(result) {
		return nil, fmt.Errorf("point is not on correct subgroup")
	}
	return &PartialSignatureVt{identifier: sks.value.Identifier, signature: *result}, nil
}

// combineSigsVt gathers partial signatures and yields a complete signature
func combineSigsVt(partials []*PartialSignatureVt) (*SignatureVt, error) {
	if len(partials) < 2 {
		return nil, fmt.Errorf("must have at least 2 partial signatures")
	}
	if len(partials) > 255 {
		return nil, fmt.Errorf("unsupported to combine more than 255 signatures")
	}
	field := finitefield.New(blsEngine.G1.Q())
	xVars, yVars, err := splitXYVt(field, partials)

	if err != nil {
		return nil, err
	}

	sTmp := blsEngine.G1.New()
	sig := blsEngine.G1.New()

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
		blsEngine.G1.MulScalar(sTmp, yVars[i], basis.BigInt())
		blsEngine.G1.Add(sig, sig, sTmp)
	}
	if !blsEngine.G1.InCorrectSubgroup(sig) {
		return nil, fmt.Errorf("signature is not in the correct subgroup")
	}

	return &SignatureVt{value: *sig}, nil
}

// Ensure no duplicates x values and convert x values to field elements
func splitXYVt(field *finitefield.Field, partials []*PartialSignatureVt) ([]*finitefield.Element, []*bls12381.PointG1, error) {
	x := make([]*finitefield.Element, len(partials))
	y := make([]*bls12381.PointG1, len(partials))

	dup := make(map[byte]bool)

	for i, sp := range partials {
		if sp == nil {
			return nil, nil, fmt.Errorf("partial signature cannot be nil")
		}
		if _, exists := dup[sp.identifier]; exists {
			return nil, nil, fmt.Errorf("duplicate signature included")
		}
		if !blsEngine.G1.InCorrectSubgroup(&sp.signature) {
			return nil, nil, fmt.Errorf("signature is not in the correct subgroup")
		}
		dup[sp.identifier] = true
		x[i] = field.ElementFromBytes([]byte{sp.identifier})
		y[i] = &sp.signature
	}
	return x, y, nil
}
