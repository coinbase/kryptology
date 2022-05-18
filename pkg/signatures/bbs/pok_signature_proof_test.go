//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	crand "crypto/rand"
	"testing"

	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
)

func TestPokSignatureProofSomeMessagesRevealed(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)
	require.False(t, sk.value.IsZero())
	require.False(t, pk.value.IsIdentity())
	_, ok := pk.value.(*curves.PointBls12381G2)
	require.True(t, ok)
	generators, err := new(MessageGenerators).Init(pk, 4)
	require.NoError(t, err)
	msgs := []curves.Scalar{
		curve.Scalar.New(2),
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
	}

	sig, err := sk.Sign(generators, msgs)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.False(t, sig.a.IsIdentity())
	require.False(t, sig.e.IsZero())
	require.False(t, sig.s.IsZero())

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
	require.NoError(t, err)
	require.NotNil(t, pok)
	nonce := curve.Scalar.Random(crand.Reader)
	transcript := merlin.NewTranscript("TestPokSignatureProofWorks")
	pok.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	require.NoError(t, err)

	pokSig, err := pok.GenerateProof(challenge)
	require.NoError(t, err)
	require.NotNil(t, pokSig)
	require.True(t, pokSig.VerifySigPok(pk))

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
	require.NoError(t, err)
	require.Equal(t, challenge.Cmp(vChallenge), 0)

	// Use the all-inclusive method
	transcript = merlin.NewTranscript("TestPokSignatureProofWorks")
	require.True(t, pokSig.Verify(revealedMsgs, pk, generators, nonce, challenge, transcript))
}

func TestPokSignatureProofAllMessagesRevealed(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)
	require.False(t, sk.value.IsZero())
	require.False(t, pk.value.IsIdentity())
	_, ok := pk.value.(*curves.PointBls12381G2)
	require.True(t, ok)
	generators, err := new(MessageGenerators).Init(pk, 4)
	require.NoError(t, err)
	msgs := []curves.Scalar{
		curve.Scalar.New(2),
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
	}

	sig, err := sk.Sign(generators, msgs)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.False(t, sig.a.IsIdentity())
	require.False(t, sig.e.IsZero())
	require.False(t, sig.s.IsZero())

	proofMsgs := []common.ProofMessage{
		&common.RevealedMessage{
			Message: msgs[0],
		},
		&common.RevealedMessage{
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
	require.NoError(t, err)
	require.NotNil(t, pok)
	nonce := curve.Scalar.Random(crand.Reader)
	transcript := merlin.NewTranscript("TestPokSignatureProofWorks")
	pok.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	require.NoError(t, err)

	pokSig, err := pok.GenerateProof(challenge)
	require.NoError(t, err)
	require.NotNil(t, pokSig)
	require.True(t, pokSig.VerifySigPok(pk))

	revealedMsgs := map[int]curves.Scalar{
		0: msgs[0],
		1: msgs[1],
		2: msgs[2],
		3: msgs[3],
	}
	// Manual verify to show how when used in conjunction with other ZKPs
	transcript = merlin.NewTranscript("TestPokSignatureProofWorks")
	pokSig.GetChallengeContribution(generators, revealedMsgs, challenge, transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm = transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	vChallenge, err := curve.Scalar.SetBytesWide(okm)
	require.NoError(t, err)
	require.Equal(t, challenge.Cmp(vChallenge), 0)

	// Use the all-inclusive method
	transcript = merlin.NewTranscript("TestPokSignatureProofWorks")
	require.True(t, pokSig.Verify(revealedMsgs, pk, generators, nonce, challenge, transcript))
}

func TestPokSignatureProofAllMessagesHidden(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)
	require.False(t, sk.value.IsZero())
	require.False(t, pk.value.IsIdentity())
	_, ok := pk.value.(*curves.PointBls12381G2)
	require.True(t, ok)
	generators, err := new(MessageGenerators).Init(pk, 4)
	require.NoError(t, err)
	msgs := []curves.Scalar{
		curve.Scalar.New(2),
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
	}

	sig, err := sk.Sign(generators, msgs)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.False(t, sig.a.IsIdentity())
	require.False(t, sig.e.IsZero())
	require.False(t, sig.s.IsZero())

	proofMsgs := []common.ProofMessage{
		&common.ProofSpecificMessage{
			Message: msgs[0],
		},
		&common.ProofSpecificMessage{
			Message: msgs[1],
		},
		&common.ProofSpecificMessage{
			Message: msgs[2],
		},
		&common.ProofSpecificMessage{
			Message: msgs[3],
		},
	}

	pok, err := NewPokSignature(sig, generators, proofMsgs, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, pok)
	nonce := curve.Scalar.Random(crand.Reader)
	transcript := merlin.NewTranscript("TestPokSignatureProofWorks")
	pok.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	require.NoError(t, err)

	pokSig, err := pok.GenerateProof(challenge)
	require.NoError(t, err)
	require.NotNil(t, pokSig)
	require.True(t, pokSig.VerifySigPok(pk))

	revealedMsgs := map[int]curves.Scalar{}

	// Manual verify to show how when used in conjunction with other ZKPs
	transcript = merlin.NewTranscript("TestPokSignatureProofWorks")
	pokSig.GetChallengeContribution(generators, revealedMsgs, challenge, transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm = transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	vChallenge, err := curve.Scalar.SetBytesWide(okm)
	require.NoError(t, err)
	require.Equal(t, challenge.Cmp(vChallenge), 0)

	// Use the all-inclusive method
	transcript = merlin.NewTranscript("TestPokSignatureProofWorks")
	require.True(t, pokSig.Verify(revealedMsgs, pk, generators, nonce, challenge, transcript))
}

func TestPokSignatureProofMarshalBinary(t *testing.T) {
	curve := curves.BLS12381(&curves.PointBls12381G2{})
	pk, sk, err := NewKeys(curve)
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)
	require.False(t, sk.value.IsZero())
	require.False(t, pk.value.IsIdentity())
	_, ok := pk.value.(*curves.PointBls12381G2)
	require.True(t, ok)
	generators, err := new(MessageGenerators).Init(pk, 4)
	require.NoError(t, err)
	msgs := []curves.Scalar{
		curve.Scalar.New(2),
		curve.Scalar.New(3),
		curve.Scalar.New(4),
		curve.Scalar.New(5),
	}

	sig, err := sk.Sign(generators, msgs)
	require.NoError(t, err)
	require.NotNil(t, sig)
	require.False(t, sig.a.IsIdentity())
	require.False(t, sig.e.IsZero())
	require.False(t, sig.s.IsZero())

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
	require.NoError(t, err)
	require.NotNil(t, pok)
	nonce := curve.Scalar.Random(crand.Reader)
	transcript := merlin.NewTranscript("TestPokSignatureProofMarshalBinary")
	pok.GetChallengeContribution(transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	challenge, err := curve.Scalar.SetBytesWide(transcript.ExtractBytes([]byte("signature proof of knowledge"), 64))
	require.NoError(t, err)

	pokSig, err := pok.GenerateProof(challenge)
	require.NoError(t, err)
	require.NotNil(t, pokSig)

	data, err := pokSig.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, data)
	pokSig2 := new(PokSignatureProof).Init(curve)
	err = pokSig2.UnmarshalBinary(data)
	require.NoError(t, err)
	require.True(t, pokSig.aPrime.Equal(pokSig2.aPrime))
	require.True(t, pokSig.aBar.Equal(pokSig2.aBar))
	require.True(t, pokSig.d.Equal(pokSig2.d))
	require.Equal(t, len(pokSig.proof1), len(pokSig2.proof1))
	require.Equal(t, len(pokSig.proof2), len(pokSig2.proof2))
	for i, p := range pokSig.proof1 {
		require.Equal(t, p.Cmp(pokSig2.proof1[i]), 0)
	}
	for i, p := range pokSig.proof2 {
		require.Equal(t, p.Cmp(pokSig2.proof2[i]), 0)
	}
}
