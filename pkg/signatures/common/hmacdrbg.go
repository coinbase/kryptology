//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package common

import (
	"crypto/hmac"
	"hash"
)

// HmacDrbg is an HMAC deterministic random bit generator
// that can use any hash function. Handles reseeding
// automatically
type HmacDrbg struct {
	k, v   []byte
	count  int
	hasher func() hash.Hash
}

func NewHmacDrbg(entropy, nonce, pers []byte, hasher func() hash.Hash) *HmacDrbg {
	drbg := new(HmacDrbg)
	h := hasher()
	drbg.k = make([]byte, h.Size())
	drbg.v = make([]byte, h.Size())
	drbg.count = 0
	drbg.hasher = hasher

	for i := range drbg.v {
		drbg.v[i] = 1
	}

	drbg.update([][]byte{entropy, nonce, pers})
	drbg.count += 1
	return drbg
}

func (drbg *HmacDrbg) Read(dst []byte) (n int, err error) {
	toRead := len(dst)
	if toRead == 0 {
		return 0, nil
	}
	i := 0
	for i < toRead {
		vmac := drbg.getHmac()
		_, _ = vmac.Write(drbg.v)
		drbg.v = vmac.Sum(nil)

		for j, b := range drbg.v {
			dst[i+j] = b
		}
		i += len(drbg.v)
	}
	drbg.update(nil)
	drbg.count++
	return i, nil
}

func (drbg *HmacDrbg) Reseed(entropy []byte) {
	drbg.update([][]byte{entropy})
}

func (drbg *HmacDrbg) getHmac() hash.Hash {
	return hmac.New(drbg.hasher, drbg.k)
}

func (drbg *HmacDrbg) update(seeds [][]byte) {
	kmac := drbg.getHmac()
	_, _ = kmac.Write(drbg.v)
	_, _ = kmac.Write([]byte{0})
	if len(seeds) > 0 {
		for _, seed := range seeds {
			_, _ = kmac.Write(seed)
		}
	}
	drbg.k = kmac.Sum(nil)

	vmac := drbg.getHmac()
	_, _ = vmac.Write(drbg.v)
	drbg.v = vmac.Sum(nil)

	if len(seeds) == 0 {
		return
	}

	kmac = drbg.getHmac()
	_, _ = kmac.Write(drbg.v)
	_, _ = kmac.Write([]byte{1})
	for _, seed := range seeds {
		_, _ = kmac.Write(seed)
	}
	drbg.k = kmac.Sum(nil)

	vmac = drbg.getHmac()
	_, _ = vmac.Write(drbg.v)
	drbg.v = vmac.Sum(nil)
}
