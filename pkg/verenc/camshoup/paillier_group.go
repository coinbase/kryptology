//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

// Implements Camenisch-Shoup verifiable encryption based on the paper
// Practical Verifiable Encryption and Decryption of Discrete Logarithms
// see <https://www.shoup.net/papers/verenc.pdf> and
// <https://dominoweb.draco.res.ibm.com/reports/rz3730_revised.pdf>

import (
	"math/big"

	"git.sr.ht/~sircmpwn/go-bare"
	"github.com/coinbase/kryptology/internal"
	crypto "github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
)

// PaillierGroup holds public values for Verifiable Encryption
// g and h correspond to the symbols with the same name in the paper.
// n = p * q, where p = 2p' + 1, q = 2q' + 1, p, q, p', q' are all prime
// See section 3.1 and 3.2 in verenc.pdf.
// nd4 = n / 4 integer division
// n2 = n^2
// nd4 = n^2 / 4 integer division
type PaillierGroup struct {
	g, h, n, nd4, n2d2, n2d4, n2, twoInvTwo *big.Int
}

type paillierMarshal struct {
	N []byte `bare:"n"`
	G []byte `bare:"g"`
}

// NewPaillierGroup creates a new Paillier group for verifiable encryption
// and generates safe primes for p and q.
func NewPaillierGroup() (*PaillierGroup, error) {
	return groupGenerator(crypto.GenerateSafePrime, paillier.PaillierPrimeBits)
}

// NewPaillierGroupWithPrimes create a new Paillier group for verifiable encryption
// Order n^2 where n = p * q
func NewPaillierGroupWithPrimes(p, q *big.Int) (*PaillierGroup, error) {
	n := new(big.Int).Mul(p, q)
	n2 := new(big.Int).Mul(n, n)
	gTick, err := crypto.Rand(n2)
	if err != nil {
		return nil, err
	}
	twoInvTwo := new(big.Int).ModInverse(big.NewInt(2), n)
	// 2n^2
	twoN2 := new(big.Int).Lsh(n2, 1)
	return &PaillierGroup{
		g:         new(big.Int).Exp(gTick, twoN2, n2),
		h:         new(big.Int).Add(n, big.NewInt(1)),
		n:         n,
		nd4:       new(big.Int).Rsh(n, 1),
		n2:        n2,
		n2d2:      new(big.Int).Rsh(n2, 1),
		n2d4:      new(big.Int).Rsh(n2, 2),
		twoInvTwo: new(big.Int).Lsh(twoInvTwo, 1),
	}, nil
}

// create two safe primes and generate a new Paillier group
func groupGenerator(genSafePrime func(uint) (*big.Int, error), bits uint) (*PaillierGroup, error) {
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
				return nil, err
			}
		}

		p, q = <-values, <-values
	}
	return NewPaillierGroupWithPrimes(p, q)
}

// Abs computes a mod n^2 where 0 < a < n^2 or
// (n^2 - a) mod n^2 if a > n^2/2
// See section 3.2
func (pg PaillierGroup) Abs(a *big.Int) *big.Int {
	tv := new(big.Int).Mod(a, pg.n2)

	// if a > n^2 / 2 then n^2 - a else a
	if tv.Cmp(pg.n2d2) == 1 {
		return new(big.Int).Sub(pg.n2, tv)
	} else {
		return tv
	}
}

// Exp computes base^exp mod n^2
func (pg PaillierGroup) Exp(base, exp *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, pg.n2)
}

func (pg PaillierGroup) Mul(lhs, rhs *big.Int) *big.Int {
	r := new(big.Int).Mul(lhs, rhs)
	return r.Mod(r, pg.n2)
}

// Inv computes val^-1 mod n^2
func (pg PaillierGroup) Inv(val *big.Int) *big.Int {
	return new(big.Int).ModInverse(val, pg.n2)
}

// Gexp computes g^exp mod n^2
func (pg PaillierGroup) Gexp(exp *big.Int) *big.Int {
	return new(big.Int).Exp(pg.g, exp, pg.n2)
}

// Hexp computes h^exp mod n^2
func (pg PaillierGroup) Hexp(exp *big.Int) *big.Int {
	return new(big.Int).Exp(pg.h, exp, pg.n2)
}

// Rand returns a random v ∈ [1, n^2 / 4)
func (pg PaillierGroup) Rand() (*big.Int, error) {
	return crypto.Rand(pg.n2d4)
}

// RandForEncrypt returns a random v ∈ [1, n / 4)
func (pg PaillierGroup) RandForEncrypt() (*big.Int, error) {
	return crypto.Rand(pg.nd4)
}

// MarshalBinary serializes a paillier group to a byte sequence
func (pg PaillierGroup) MarshalBinary() ([]byte, error) {
	// Only serialize what's needed
	// all values except g can be derived from n
	// g is a random value
	tv := new(paillierMarshal)
	tv.N = pg.n.Bytes()
	tv.G = pg.g.Bytes()
	return bare.Marshal(tv)
}

// UnmarshalBinary deserializes a paillier group from a byte sequence
func (pg *PaillierGroup) UnmarshalBinary(data []byte) error {
	tv := new(paillierMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	pg.n = new(big.Int).SetBytes(tv.N)
	pg.g = new(big.Int).SetBytes(tv.G)
	twoInvTwo := new(big.Int).ModInverse(big.NewInt(2), pg.n)
	pg.h = new(big.Int).Add(pg.n, big.NewInt(1))
	pg.n2 = new(big.Int).Mul(pg.n, pg.n)
	pg.nd4 = new(big.Int).Rsh(pg.n, 1)
	pg.n2d2 = new(big.Int).Rsh(pg.n2, 1)
	pg.n2d4 = new(big.Int).Rsh(pg.n2, 2)
	pg.twoInvTwo = new(big.Int).Lsh(twoInvTwo, 1)
	return nil
}

// Hash computes h(u, e, L) for encryption/decryption
func (pg PaillierGroup) Hash(u *big.Int, e []*big.Int, data []byte) (*big.Int, error) {
	if u == nil || len(e) == 0 || crypto.AnyNil(e...) {
		return nil, internal.ErrNilArguments
	}
	toHash := make([][]byte, len(e)+2)
	toHash[0] = u.Bytes()
	for i, ee := range e {
		toHash[i+1] = ee.Bytes()
	}
	toHash[len(toHash)-1] = data
	h, err := internal.Hash([]byte("Coinbase Hash 1.0"), toHash...)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(h), nil
}
