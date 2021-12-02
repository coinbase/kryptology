//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bls12381

import (
	"hash"
)

func hashToFpXMD(f func() hash.Hash, msg []byte, domain []byte, count int) ([]*fe, error) {
	lenPerElm := 64
	lenInBytes := count * lenPerElm
	randBytes := expandMsgXMD(f, msg, domain, lenInBytes)
	els := make([]*fe, count)
	var err error
	for i := 0; i < count; i++ {
		els[i], err = from64Bytes(randBytes[i*64 : (i+1)*64])
		if err != nil {
			return nil, err
		}
	}
	return els, nil
}

func expandMsgXMD(f func() hash.Hash, msg []byte, domain []byte, outLen int) []byte {
	h := f()
	domainLen := uint8(len(domain))
	if len(domain) > 255 {
		// See https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/?include_text=1
		// Section 5.3.3
		_, _ = h.Write([]byte("H2C-OVERSIZE-DST-"))
		_, _ = h.Write(domain)
		domain = h.Sum(nil)
		h.Reset()
		domainLen = uint8(len(domain))
	}
	// DST_prime = DST || I2OSP(len(DST), 1)
	// b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
	_, _ = h.Write(make([]byte, h.BlockSize()))
	_, _ = h.Write(msg)
	_, _ = h.Write([]byte{uint8(outLen >> 8), uint8(outLen)})
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b0 := h.Sum(nil)

	// b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
	h.Reset()
	_, _ = h.Write(b0)
	_, _ = h.Write([]byte{1})
	_, _ = h.Write(domain)
	_, _ = h.Write([]byte{domainLen})
	b1 := h.Sum(nil)

	// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
	ell := (outLen + h.Size() - 1) / h.Size()
	bi := b1
	out := make([]byte, outLen)
	for i := 1; i < ell; i++ {
		h.Reset()
		// b_i = H(strxor(b_0, b_(i - 1)) || I2OSP(i, 1) || DST_prime)
		tmp := make([]byte, h.Size())
		for j := 0; j < h.Size(); j++ {
			tmp[j] = b0[j] ^ bi[j]
		}
		_, _ = h.Write(tmp)
		_, _ = h.Write([]byte{1 + uint8(i)})
		_, _ = h.Write(domain)
		_, _ = h.Write([]byte{domainLen})

		// b_1 || ... || b_(ell - 1)
		copy(out[(i-1)*h.Size():i*h.Size()], bi[:])
		bi = h.Sum(nil)
	}
	// b_ell
	copy(out[(ell-1)*h.Size():], bi[:])
	return out[:outLen]

}
