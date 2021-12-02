//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	crand "crypto/rand"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPokSignatureProofWorks(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	assert.NoError(t, err)
	assert.NotNil(t, sk)
	assert.NotNil(t, pk)
	assert.False(t, sk.value.IsZero())
	assert.False(t, pk.value.IsIdentity())
	_, ok := pk.value.(*curves.PointBls12381G2)
	assert.True(t, ok)
	generators := new(MessageGenerators).Init(pk, 4)
	msgs := []curves.Scalar{
		curve.Scalar.New(2),
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
	}

	sig, err := sk.Sign(generators, msgs)
	assert.NoError(t, err)
	assert.NotNil(t, sig)
	assert.False(t, sig.a.IsIdentity())
	assert.False(t, sig.e.IsZero())
	assert.False(t, sig.s.IsZero())

	proofMsgs := []common.ProofMessage{
		&common.ProofSpecificMessage{
			Message: msgs[0],
		},
		&common.ProofSpecificMessage{
			Message: msgs[1],
		},
		&common.RevealedMessage{
			Message: msgs[2],
		},
		&common.RevealedMessage{
			Message: msgs[3],
		},
	}

	pok, err := NewPokSignature(sig, generators, proofMsgs, crand.Reader)
	assert.NoError(t, err)
	assert.NotNil(t, pok)
	nonce := curve.Scalar.Random(crand.Reader)
	transcript := merlin.NewTranscript("TestPokSignatureProofWorks")
	pok.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	assert.NoError(t, err)

	pokSig, err := pok.GenerateProof(challenge)
	assert.NoError(t, err)
	assert.NotNil(t, pokSig)
	assert.True(t, pokSig.VerifySigPok(pk))

	revealedMsgs := map[int]curves.Scalar{
		2: msgs[2],
		3: msgs[3],
	}
	// Manual verify to show how when used in conjunction with other ZKPs
	transcript = merlin.NewTranscript("TestPokSignatureProofWorks")
	pokSig.GetChallengeContribution(generators, revealedMsgs, challenge, transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm = transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	vChallenge, err := curve.Scalar.SetBytesWide(okm)
	assert.NoError(t, err)
	assert.Equal(t, challenge.Cmp(vChallenge), 0)

	// Use the all-inclusive method
	transcript = merlin.NewTranscript("TestPokSignatureProofWorks")
	assert.True(t, pokSig.Verify(revealedMsgs, pk, generators, nonce, challenge, transcript))
}

func TestPokSignatureProofMarshalBinary(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	assert.NoError(t, err)
	assert.NotNil(t, sk)
	assert.NotNil(t, pk)
	assert.False(t, sk.value.IsZero())
	assert.False(t, pk.value.IsIdentity())
	_, ok := pk.value.(*curves.PointBls12381G2)
	assert.True(t, ok)
	generators := new(MessageGenerators).Init(pk, 4)
	msgs := []curves.Scalar{
		curve.Scalar.New(2),
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
	}

	sig, err := sk.Sign(generators, msgs)
	assert.NoError(t, err)
	assert.NotNil(t, sig)
	assert.False(t, sig.a.IsIdentity())
	assert.False(t, sig.e.IsZero())
	assert.False(t, sig.s.IsZero())

	proofMsgs := []common.ProofMessage{
		&common.ProofSpecificMessage{
			Message: msgs[0],
		},
		&common.ProofSpecificMessage{
			Message: msgs[1],
		},
		&common.RevealedMessage{
			Message: msgs[2],
		},
		&common.RevealedMessage{
			Message: msgs[3],
		},
	}

	pok, err := NewPokSignature(sig, generators, proofMsgs, crand.Reader)
	assert.NoError(t, err)
	assert.NotNil(t, pok)
	nonce := curve.Scalar.Random(crand.Reader)
	transcript := merlin.NewTranscript("TestPokSignatureProofMarshalBinary")
	pok.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	challenge, err := curve.Scalar.SetBytesWide(transcript.ExtractBytes([]byte("signature proof of knowledge"), 64))
	assert.NoError(t, err)

	pokSig, err := pok.GenerateProof(challenge)
	assert.NoError(t, err)
	assert.NotNil(t, pokSig)

	data, err := pokSig.MarshalBinary()
	assert.NoError(t, err)
	assert.NotNil(t, data)
	pokSig2 := new(PokSignatureProof).Init(curve)
	err = pokSig2.UnmarshalBinary(data)
	assert.NoError(t, err)
	assert.True(t, pokSig.aPrime.Equal(pokSig2.aPrime))
	assert.True(t, pokSig.aBar.Equal(pokSig2.aBar))
	assert.True(t, pokSig.d.Equal(pokSig2.d))
	assert.Equal(t, len(pokSig.proof1), len(pokSig2.proof1))
	assert.Equal(t, len(pokSig.proof2), len(pokSig2.proof2))
	for i, p := range pokSig.proof1 {
		assert.Equal(t, p.Cmp(pokSig2.proof1[i]), 0)
	}
	for i, p := range pokSig.proof2 {
		assert.Equal(t, p.Cmp(pokSig2.proof2[i]), 0)
	}
}
