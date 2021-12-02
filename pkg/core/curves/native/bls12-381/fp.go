//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls12381

import (
	"errors"
	"math/big"
)

func fromBytes(in []byte) (*fe, error) {
	fe := &fe{}
	if len(in) != 48 {
		return nil, errors.New("input string should be equal 48 bytes")
	}
	fe.setBytes(in)
	if !fe.isValid() {
		return nil, errors.New("must be less than modulus")
	}
	toMont(fe, fe)
	return fe, nil
}

func from64Bytes(in []byte) (*fe, error) {
	if len(in) != 64 {
		return nil, errors.New("input string should be equal 64 bytes")
	}
	a0 := make([]byte, 48)
	copy(a0[16:48], in[:32])
	a1 := make([]byte, 48)
	copy(a1[16:48], in[32:])
	e0, err := fromBytes(a0)
	if err != nil {
		return nil, err
	}
	e1, err := fromBytes(a1)
	if err != nil {
		return nil, err
	}
	// F = 2 ^ 256 * R
	F := fe{
		0x75b3cd7c5ce820f,
		0x3ec6ba621c3edb0b,
		0x168a13d82bff6bce,
		0x87663c4bf8c449d2,
		0x15f34c83ddc8d830,
		0xf9628b49caa2e85,
	}

	mul(e0, e0, &F)
	add(e1, e1, e0)
	return e1, nil
}

func fromBig(in *big.Int) (*fe, error) {
	fe := new(fe).setBig(in)
	if !fe.isValid() {
		return nil, errors.New("invalid input string")
	}
	toMont(fe, fe)
	return fe, nil
}

func fromString(in string) (*fe, error) {
	fe, err := new(fe).setString(in)
	if err != nil {
		return nil, err
	}
	if !fe.isValid() {
		return nil, errors.New("invalid input string")
	}
	toMont(fe, fe)
	return fe, nil
}

func toBytes(e *fe) []byte {
	e2 := new(fe)
	fromMont(e2, e)
	return e2.bytes()
}

func toBig(e *fe) *big.Int {
	e2 := new(fe)
	fromMont(e2, e)
	return e2.big()
}

func toString(e *fe) (s string) {
	e2 := new(fe)
	fromMont(e2, e)
	return e2.string()
}

func toMont(c, a *fe) {
	mul(c, a, r2)
}

func fromMont(c, a *fe) {
	mul(c, a, &fe{1})
}

func exp(c, a *fe, e *big.Int) {
	z := new(fe).set(r1)
	t := new(fe)
	for i := e.BitLen(); i >= 0; i-- {
		mul(z, z, z)
		mul(t, z, a)
		z.cmove(e.Bit(i), t)
	}
	c.set(z)
}

func inverse(inv, e *fe) {
	exp(inv, e, pMinus2)
}

func sqrt(c, a *fe) bool {
	u, v := new(fe).set(a), new(fe)
	exp(c, a, pPlus1Over4)
	square(v, c)
	return u.equal(v)
}

func isQuadraticNonResidue(elem *fe) bool {
	result := new(fe)
	exp(result, elem, pMinus1Over2)
	return !result.isOne()
}
