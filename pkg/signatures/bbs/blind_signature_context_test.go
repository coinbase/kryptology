//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	crand "crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBlindSignatureContext(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	assert.NotNil(t, sk)

	generators := new(MessageGenerators).Init(pk, 4)
	nonce := curve.Scalar.Random(crand.Reader)
	msgs := make(map[int]curves.Scalar, 1)
	msgs[0] = curve.Scalar.Hash([]byte("identifier"))

	ctx, blinding, err := NewBlindSignatureContext(curve, msgs, generators, nonce, crand.Reader)
	assert.NoError(t, err)
	assert.NotNil(t, blinding)
	assert.False(t, blinding.IsZero())
	assert.NotNil(t, ctx)
	assert.False(t, ctx.commitment.IsIdentity())
	assert.False(t, ctx.challenge.IsZero())
	for _, p := range ctx.proofs {
		assert.False(t, p.IsZero())
	}

	delete(msgs, 0)
	msgs[1] = curve.Scalar.Hash([]byte("firstname"))
	msgs[2] = curve.Scalar.Hash([]byte("lastname"))
	msgs[3] = curve.Scalar.Hash([]byte("age"))
	blindSig, err := ctx.ToBlindSignature(msgs, sk, generators, nonce)
	assert.NoError(t, err)
	assert.NotNil(t, blindSig)
	assert.False(t, blindSig.a.IsIdentity())
	assert.False(t, blindSig.e.IsZero())
	assert.False(t, blindSig.s.IsZero())
	sig := blindSig.ToUnblinded(blinding)
	msgs[0] = curve.Scalar.Hash([]byte("identifier"))
	var sigMsgs [4]curves.Scalar
	for i := 0; i < 4; i++ {
		sigMsgs[i] = msgs[i]
	}
	err = pk.Verify(sig, generators, sigMsgs[:])
	assert.NoError(t, err)
}

func TestBlindSignatureContextMarshalBinary(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	assert.NoError(t, err)
	assert.NotNil(t, pk)
	assert.NotNil(t, sk)

	generators := new(MessageGenerators).Init(pk, 4)
	nonce := curve.Scalar.Random(crand.Reader)
	msgs := make(map[int]curves.Scalar, 1)
	msgs[0] = curve.Scalar.Hash([]byte("identifier"))

	ctx, blinding, err := NewBlindSignatureContext(curve, msgs, generators, nonce, crand.Reader)
	assert.NoError(t, err)
	assert.NotNil(t, blinding)
	assert.False(t, blinding.IsZero())
	assert.NotNil(t, ctx)
	assert.False(t, ctx.commitment.IsIdentity())
	assert.False(t, ctx.challenge.IsZero())
	for _, p := range ctx.proofs {
		assert.False(t, p.IsZero())
	}

	data, err := ctx.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, data)
	ctx2 := new(BlindSignatureContext).Init(curve)
	err = ctx2.UnmarshalBinary(data)
	assert.NoError(t, err)
	assert.Equal(t, ctx.challenge.Cmp(ctx2.challenge), 0)
	assert.True(t, ctx.commitment.Equal(ctx2.commitment))
	assert.Equal(t, len(ctx.proofs), len(ctx2.proofs))
	for i, p := range ctx.proofs {
		assert.Equal(t, p.Cmp(ctx2.proofs[i]), 0)
	}
}
