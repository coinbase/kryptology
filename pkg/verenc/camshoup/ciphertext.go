//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"math/big"

	"git.sr.ht/~sircmpwn/go-bare"
)

// CipherText represents verifiably encrypted ciphertext
// as described in section 3.2 in <https://shoup.net/papers/verenc.pdf>.
type CipherText struct {
	u, v *big.Int
	e    []*big.Int
}

type cipherTextMarshal struct {
	E [][]byte `bare:"e"`
	U []byte   `bare:"u"`
	V []byte   `bare:"v"`
}

func (c CipherText) MarshalBinary() ([]byte, error) {
	tv := new(cipherTextMarshal)
	tv.U = c.u.Bytes()
	tv.V = c.v.Bytes()
	tv.E = make([][]byte, len(c.e))
	for i, e := range c.e {
		tv.E[i] = e.Bytes()
	}

	return bare.Marshal(tv)
}

func (c *CipherText) UnmarshalBinary(data []byte) error {
	tv := new(cipherTextMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	c.u = new(big.Int).SetBytes(tv.U)
	c.v = new(big.Int).SetBytes(tv.V)
	c.e = make([]*big.Int, len(tv.E))
	for i, e := range tv.E {
		c.e[i] = new(big.Int).SetBytes(e)
	}
	return nil
}
