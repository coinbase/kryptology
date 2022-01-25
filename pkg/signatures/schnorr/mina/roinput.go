//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
)

// Handles the packing of bits and fields according to Mina spec
type roinput struct {
	fields []*fp.Fp
	bits   *BitVector
}

var conv = map[bool]int{
	true:  1,
	false: 0,
}

func (r *roinput) Init(fields int, bytes int) *roinput {
	r.fields = make([]*fp.Fp, 0, fields)
	r.bits = NewBitVector(make([]byte, bytes), 0)
	return r
}

func (r *roinput) Clone() *roinput {
	t := new(roinput)
	t.fields = make([]*fp.Fp, len(r.fields))
	for i, f := range r.fields {
		t.fields[i] = new(fp.Fp).Set(f)
	}
	buffer := r.bits.Bytes()
	data := make([]byte, len(buffer))
	copy(data, buffer)
	t.bits = NewBitVector(data, r.bits.Length())
	return t
}

func (r *roinput) AddFp(fp *fp.Fp) {
	r.fields = append(r.fields, fp)
}

func (r *roinput) AddFq(fq *fq.Fq) {
	scalar := fq.ToRaw()
	// Mina handles fields as 255 bit numbers
	// with each field we lose a bit
	for i := 0; i < 255; i++ {
		limb := i / 64
		idx := i % 64
		b := (scalar[limb] >> idx) & 1
		r.bits.Append(byte(b))
	}
}

func (r *roinput) AddBit(b bool) {
	r.bits.Append(byte(conv[b]))
}

func (r *roinput) AddBytes(input []byte) {
	for _, b := range input {
		for i := 0; i < 8; i++ {
			r.bits.Append(byte((b >> i) & 1))
		}
	}
}

func (r *roinput) AddUint32(x uint32) {
	for i := 0; i < 32; i++ {
		r.bits.Append(byte((x >> i) & 1))
	}
}

func (r *roinput) AddUint64(x uint64) {
	for i := 0; i < 64; i++ {
		r.bits.Append(byte((x >> i) & 1))
	}
}

func (r roinput) Bytes() []byte {
	out := make([]byte, (r.bits.Length()+7)/8+32*len(r.fields))
	res := NewBitVector(out, 0)
	// Mina handles fields as 255 bit numbers
	// with each field we lose a bit
	for _, f := range r.fields {
		buf := f.ToRaw()
		for i := 0; i < 255; i++ {
			limb := i / 64
			idx := i % 64
			b := (buf[limb] >> idx) & 1
			res.Append(byte(b))
		}
	}
	for i := 0; i < r.bits.Length(); i++ {
		res.Append(r.bits.Element(i))
	}
	return out
}

func (r roinput) Fields() []*fp.Fp {
	fields := make([]*fp.Fp, 0, len(r.fields)+r.bits.Length()/256)
	for _, f := range r.fields {
		fields = append(fields, new(fp.Fp).Set(f))
	}
	const maxChunkSize = 254
	bitsConsumed := 0
	bitIdx := 0

	for bitsConsumed < r.bits.Length() {
		var chunk [4]uint64

		remaining := r.bits.Length() - bitsConsumed
		var chunkSizeInBits int
		if remaining > maxChunkSize {
			chunkSizeInBits = maxChunkSize
		} else {
			chunkSizeInBits = remaining
		}

		for i := 0; i < chunkSizeInBits; i++ {
			limb := i >> 6
			idx := i & 0x3F
			b := r.bits.Element(bitIdx)
			chunk[limb] |= uint64(b) << idx
			bitIdx++
		}
		fields = append(fields, new(fp.Fp).SetRaw(&chunk))
		bitsConsumed += chunkSizeInBits
	}

	return fields
}
