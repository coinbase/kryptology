//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"fmt"
	"math/big"

	"git.sr.ht/~sircmpwn/go-bare"
	mod "github.com/coinbase/kryptology/pkg/core"
)

type encryptionKeyMarshal struct {
	Y1    [][]byte `bare:"y1"`
	Y2    []byte   `bare:"y2"`
	Y3    []byte   `bare:"y3"`
	Group []byte   `bare:"group"`
}

// EncryptionKey encrypts a message to a ciphertext from which
// zero-knowledge proofs can be derived
// as described in section 3.2 in <https://shoup.net/papers/verenc.pdf>.
// n, g are stored in the `PaillierGroup` struct
type EncryptionKey struct {
	y1     []*big.Int
	y2, y3 *big.Int
	group  *PaillierGroup
}

func NewKeys(numMsgs uint, group *PaillierGroup) (*EncryptionKey, *DecryptionKey, error) {
	if numMsgs < 1 {
		return nil, nil, fmt.Errorf("number of messages should be greater than 0")
	}

	x1 := make([]*big.Int, numMsgs)
	y1 := make([]*big.Int, numMsgs)
	for i := range x1 {
		x, err := mod.Rand(group.n2d4)
		if err != nil {
			return nil, nil, err
		}
		x1[i] = x
		y1[i] = group.Gexp(x)
	}
	x2, err := mod.Rand(group.n2d4)
	if err != nil {
		return nil, nil, err
	}
	y2 := group.Gexp(x2)
	x3, err := mod.Rand(group.n2d4)
	if err != nil {
		return nil, nil, err
	}
	y3 := group.Gexp(x3)
	dk := &DecryptionKey{
		x1, x2, x3, group,
	}
	ek := &EncryptionKey{
		y1, y2, y3, group,
	}
	return ek, dk, nil
}

// MarshalBinary serializes a key to bytes
func (ek EncryptionKey) MarshalBinary() ([]byte, error) {
	tv := new(encryptionKeyMarshal)
	var err error
	tv.Group, err = ek.group.MarshalBinary()
	if err != nil {
		return nil, err
	}
	tv.Y3 = ek.y3.Bytes()
	tv.Y2 = ek.y2.Bytes()
	tv.Y1 = make([][]byte, len(ek.y1))
	for i, y := range ek.y1 {
		tv.Y1[i] = y.Bytes()
	}
	return bare.Marshal(tv)
}

// UnmarshalBinary deserializes a key from bytes
func (ek *EncryptionKey) UnmarshalBinary(data []byte) error {
	tv := new(encryptionKeyMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	ek.group = new(PaillierGroup)
	err = ek.group.UnmarshalBinary(tv.Group)
	if err != nil {
		return err
	}
	ek.y2 = new(big.Int).SetBytes(tv.Y2)
	ek.y3 = new(big.Int).SetBytes(tv.Y3)
	ek.y1 = make([]*big.Int, len(tv.Y1))
	for i, b := range tv.Y1 {
		ek.y1[i] = new(big.Int).SetBytes(b)
	}
	return nil
}

// Encrypt multiple messages as described in <https://shoup.net/papers/verenc.pdf>
// `domain` represents a domain separation tag or nonce
func (ek EncryptionKey) Encrypt(domain []byte, msgs []*big.Int) (*CipherText, error) {
	if len(msgs) > len(ek.y1) {
		return nil, fmt.Errorf("number of messages %d is more than supported by this key %d", len(msgs), len(ek.y1))
	}
	for i, m := range msgs {
		if m == nil || m.Cmp(ek.group.n) == 1 {
			return nil, fmt.Errorf("message %d is not valid", i)
		}
	}
	r, err := ek.group.RandForEncrypt()
	if err != nil {
		return nil, err
	}
	return ek.encryptWithR(domain, msgs, r)
}

func (ek EncryptionKey) encryptWithR(domain []byte, msgs []*big.Int, r *big.Int) (*CipherText, error) {
	u := ek.computeU(r)
	e := ek.computeE(msgs, r)

	hs, err := ek.group.Hash(u, e, domain)
	if err != nil {
		return nil, err
	}
	v := ek.computeV(r, hs, true)
	return &CipherText{u, v, e}, nil
}

func (ek EncryptionKey) computeE(msgs []*big.Int, r *big.Int) []*big.Int {
	e := make([]*big.Int, len(msgs))
	for i, m := range msgs {
		y := ek.group.Exp(ek.y1[i], r)
		hM := ek.group.Hexp(m)
		e[i] = ek.group.Mul(y, hM)
	}
	return e
}

func (ek EncryptionKey) computeU(r *big.Int) *big.Int {
	return ek.group.Gexp(r)
}

// computeV computes the `v` value during encryption
// abs is present for code reuse as during the proof of encryption
// in the commitment step absolute value is not taken.
func (ek EncryptionKey) computeV(r, hash *big.Int, abs bool) *big.Int {
	// y3 ^ h(u, e, L)
	y3hs := ek.group.Exp(ek.y3, hash)

	// y2 * (y3^h(u, e, L))
	y2y3hs := ek.group.Mul(ek.y2, y3hs)

	// (y2y3^h(u, e, L))^r
	y2y3hsr := ek.group.Exp(y2y3hs, r)
	if abs {
		return ek.group.Abs(y2y3hsr)
	} else {
		return y2y3hsr
	}
}
