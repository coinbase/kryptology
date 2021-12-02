//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package paillier contains Paillier's cryptosystem (1999) [P99].
// Public-Key Cryptosystems Based on Composite Degree Residuosity Class.
// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf
// All routines here from pseudocode §2.5. Fig 1: The Paillier Cryptosystem.
//
// This module provides APIs for:
//
//  - generating a safe keypair,
//  - encryption and decryption,
//  - adding two encrypted values, Enc(a) and Enc(b), and obtaining Enc(a + b), and
//  - multiplying a plain value, a, and an encrypted value Enc(b), and obtaining Enc(a * b).
//
// The encrypted values are represented as big.Int and are serializable. This module also provides
// JSON serialization for the PublicKey and the SecretKey.
package paillier

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
)

// PaillierPrimeBits is the number of bits used to generate Paillier Safe Primes.
const PaillierPrimeBits = 1024

type (
	// PublicKey is a Paillier public key: N = P*Q; for safe primes P,Q.
	PublicKey struct {
		N  *big.Int // N = PQ
		N2 *big.Int // N² computed and cached to prevent re-computation.
	}

	// PublicKeyJson encapsulates the data that is serialized to JSON.
	// It is used internally and not for external use. Public so other pieces
	// can use for serialization.
	PublicKeyJson struct {
		N *big.Int
	}

	// SecretKey is a Paillier secret key.
	SecretKey struct {
		PublicKey
		Lambda  *big.Int // lcm(P - 1, Q - 1)
		Totient *big.Int // Euler's totient: (P - 1) * (Q - 1)
		U       *big.Int // L((N + 1)^λ(N) mod N²)−1 mod N
	}

	// SecretKeyJson encapsulates the data that is serialized to JSON.
	// It is used internally and not for external use. Public so other pieces
	// can use for serialization.
	SecretKeyJson struct {
		N, Lambda, Totient, U *big.Int
	}

	// Ciphertext in Pailler's cryptosystem: a value $c \in Z_{N²}$ .
	Ciphertext *big.Int
)

var (
	two = big.NewInt(2) // The odd prime
)

// NewKeys generates Paillier keys with `bits` sized safe primes.
func NewKeys() (*PublicKey, *SecretKey, error) {
	return keyGenerator(core.GenerateSafePrime, PaillierPrimeBits)
}

// keyGenerator generates Paillier keys with `bits` sized safe primes using function
// `genSafePrime` to generate the safe primes.
func keyGenerator(genSafePrime func(uint) (*big.Int, error), bits uint) (*PublicKey, *SecretKey, error) {
	values := make(chan *big.Int, 2)
	errors := make(chan error, 2)

	var p, q *big.Int

	for p == q {
		for range []int{1, 2} {
			go func() {
				value, err := genSafePrime(bits)
				values <- value
				errors <- err
			}()
		}

		for _, err := range []error{<-errors, <-errors} {
			if err != nil {
				return nil, nil, err
			}
		}

		p, q = <-values, <-values
	}

	// Assemble the secret/public key pair.
	sk, err := NewSecretKey(p, q)
	if err != nil {
		return nil, nil, err
	}
	return &sk.PublicKey, sk, nil
}

// NewSecretKey computes intermediate values based on safe primes p, q.
func NewSecretKey(p, q *big.Int) (*SecretKey, error) {
	if p == nil || q == nil {
		return nil, internal.ErrNilArguments
	}
	// Pre-compute necessary values.
	pm1 := new(big.Int).Sub(p, core.One) // P - 1
	qm1 := new(big.Int).Sub(q, core.One) // Q - 1
	n := new(big.Int).Mul(p, q)          // N = PQ
	nn := new(big.Int).Mul(n, n)         // N²
	lambda, err := lcm(pm1, qm1)         // λ(N) = lcm(P-1, Q-1)
	if err != nil {
		// Code coverage note: lcm returns error only if the inputs are nil, which can never happen here.
		return nil, err
	}
	totient := new(big.Int).Mul(pm1, qm1) // 𝝋(N) = (P-1)(Q-1)
	pk := PublicKey{
		N:  n,
		N2: nn,
	}

	// (N+1)^λ(N) mod N²
	t := new(big.Int).Add(n, core.One)
	t.Exp(t, lambda, nn)

	// L((N+1)^λ(N) mod N²)
	u, err := pk.l(t)
	if err != nil {
		return nil, err
	}
	// L((N+1)^λ(N) mod N²)^-1 mod N
	u.ModInverse(u, n)

	return &SecretKey{pk, lambda, totient, u}, nil
}

// MarshalJSON converts the public key into json format.
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	data := PublicKeyJson{pk.N}
	return json.Marshal(data)
}

// UnmarshalJSON converts the json data into this public key.
func (pk *PublicKey) UnmarshalJSON(bytes []byte) error {
	data := new(PublicKeyJson)
	if err := json.Unmarshal(bytes, data); err != nil {
		return err
	}
	if data.N == nil {
		return nil
	}
	pk.N = data.N
	pk.N2 = new(big.Int).Mul(data.N, data.N)
	return nil
}

// lcm calculates the least common multiple.
func lcm(x, y *big.Int) (*big.Int, error) {
	if x == nil || y == nil {
		return nil, internal.ErrNilArguments
	}
	gcd := new(big.Int).GCD(nil, nil, x, y)
	if core.ConstantTimeEq(gcd, core.Zero) {
		return core.Zero, nil
	}
	// Compute least common multiple: https://en.wikipedia.org/wiki/Least_common_multiple#Calculation .
	b := new(big.Int)
	return b.Abs(b.Mul(b.Div(x, gcd), y)), nil
}

// l computes a residuosity class of n^2: (x - 1) / n.
// Where it is the quotient x - 1 divided by n not modular multiplication of x - 1 times
// the modular multiplicative inverse of n. The function name comes from [P99].
func (pk *PublicKey) l(x *big.Int) (*big.Int, error) {
	if x == nil {
		return nil, internal.ErrNilArguments
	}

	if core.ConstantTimeEq(pk.N, core.Zero) {
		return nil, internal.ErrNCannotBeZero
	}

	// Ensure x = 1 mod N
	if !core.ConstantTimeEq(new(big.Int).Mod(x, pk.N), core.One) {
		return nil, internal.ErrResidueOne
	}

	// Ensure x ∈ Z_N²
	if err := core.In(x, pk.N2); err != nil {
		return nil, err
	}

	// (x - 1) / n
	b := new(big.Int).Sub(x, core.One)
	return b.Div(b, pk.N), nil
}

// NewPubkey initializes a Paillier public key with a given n.
func NewPubkey(n *big.Int) *PublicKey {
	// BUG(arash): TODO: It will segfault if n is nil. Refactor to check for it.
	return &PublicKey{
		N:  n,
		N2: new(big.Int).Mul(n, n), // Compute and cache N²
	}
}

// Add combines two Paillier ciphertexts.
func (pk *PublicKey) Add(c, d Ciphertext) (Ciphertext, error) {
	if c == nil || d == nil {
		return nil, internal.ErrNilArguments
	}
	// Ensure c,d ∈ Z_N²
	cErr := core.In(c, pk.N2)
	dErr := core.In(d, pk.N2)
	// Constant time error check
	var err error
	if cErr != nil {
		err = cErr
	}
	if dErr != nil {
		err = dErr
	}
	if err != nil {
		return nil, err
	}

	ctxt, err := core.Mul(c, d, pk.N2)
	if err != nil {
		// Code coverage note: core.Mul returns error only if the inputs are nil, which can never happen here.
		return nil, err
	}
	return ctxt, nil
}

// Mul is equivalent to adding two Paillier exponents.
func (pk *PublicKey) Mul(a *big.Int, c Ciphertext) (Ciphertext, error) {
	if a == nil || c == nil {
		return nil, internal.ErrNilArguments
	}

	// Ensure a ∈ Z_N
	aErr := core.In(a, pk.N)
	// Ensure c ∈ Z_N²
	cErr := core.In(c, pk.N2)

	var err error

	// Constant time error check
	if aErr != nil {
		err = aErr
	}
	if cErr != nil {
		err = cErr
	}
	if err != nil {
		return nil, err
	}
	return new(big.Int).Exp(c, a, pk.N2), nil
}

// Encrypt produces a ciphertext on input message.
func (pk *PublicKey) Encrypt(msg *big.Int) (Ciphertext, *big.Int, error) {
	// generate a nonce: r \in Z**_N
	r, err := core.Rand(pk.N)
	if err != nil {
		return nil, nil, err
	}

	// Generate and return the ciphertext
	ct, err := pk.encrypt(msg, r)
	return ct, r, err
}

// encrypt produces a ciphertext on input a message and nonce.
func (pk *PublicKey) encrypt(msg, r *big.Int) (Ciphertext, error) {
	if msg == nil || r == nil {
		return nil, internal.ErrNilArguments
	}

	// Ensure msg ∈ Z_N
	if err := core.In(msg, pk.N); err != nil {
		return nil, err
	}

	// Ensure r ∈ Z^*_N: we use the method proved in docs/[EL20]
	// ensure r ∈ Z^_N-{0}
	if err := core.In(r, pk.N); err != nil {
		return nil, err
	}
	if core.ConstantTimeEq(r, core.Zero) {
		return nil, fmt.Errorf("r cannot be 0")
	}

	// Compute the ciphertext components: ɑ, β
	// ɑ = (N+1)^m (mod N²)
	ɑ := new(big.Int).Add(pk.N, core.One)
	ɑ.Exp(ɑ, msg, pk.N2)
	β := new(big.Int).Exp(r, pk.N, pk.N2) // β = r^N (mod N²)

	// ciphertext = ɑ*β = (N+1)^m * r^N  (mod N²)
	c, err := core.Mul(ɑ, β, pk.N2)
	if err != nil {
		// Code coverage note: core.Mul returns error only if the inputs are nil, which can never happen here.
		return nil, err
	}
	return c, nil
}

// Decrypt is the reverse operation of Encrypt.
func (sk *SecretKey) Decrypt(c Ciphertext) (*big.Int, error) {
	if c == nil {
		return nil, internal.ErrNilArguments
	}

	// Ensure C ∈ Z_N²
	if err := core.In(c, sk.N2); err != nil {
		return nil, err
	}

	// Compute the msg in components
	// ɑ ≡ c^{λ(N)}		mod N²
	ɑ := new(big.Int).Exp(c, sk.Lambda, sk.N2)

	// l = L(ɑ, N)
	ell, err := sk.l(ɑ)
	if err != nil {
		return nil, err
	}

	// Compute the msg
	// m ≡ lu = L(ɑ)*u = L(c^{λ(N)})*u	mod N
	m, err := core.Mul(ell, sk.U, sk.N)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// MarshalJSON converts the secret key into json format.
func (sk SecretKey) MarshalJSON() ([]byte, error) {
	data := SecretKeyJson{
		sk.N,
		sk.Lambda,
		sk.Totient,
		sk.U,
	}
	return json.Marshal(data)
}

// UnmarshalJSON converts the json data into this secret key.
func (sk *SecretKey) UnmarshalJSON(bytes []byte) error {
	data := new(SecretKeyJson)
	if err := json.Unmarshal(bytes, data); err != nil {
		return err
	}
	if data.N != nil {
		sk.N = data.N
		sk.N2 = new(big.Int).Mul(data.N, data.N)
	}
	sk.U = data.U
	sk.Totient = data.Totient
	sk.Lambda = data.Lambda
	return nil
}
