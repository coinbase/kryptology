//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
	"github.com/gtank/merlin"
)

// PokSignatureProof is the actual proof sent from a prover
// to a verifier that contains a proof of knowledge of a signature
// and the selective disclosure proof
type PokSignatureProof struct {
	aPrime, aBar, d curves.PairingPoint
	proof1, proof2  []curves.Scalar
}

// Init creates an empty proof to a specific curve
// which should be followed by UnmarshalBinary
func (pok *PokSignatureProof) Init(curve *curves.PairingCurve) *PokSignatureProof {
	pok.aPrime = curve.Scalar.Point().(curves.PairingPoint).OtherGroup()
	pok.aBar = pok.aPrime
	pok.d = pok.aPrime
	pok.proof1 = []curves.Scalar{
		curve.Scalar.Zero(),
		curve.Scalar.Zero(),
	}
	pok.proof2 = make([]curves.Scalar, 0)
	return pok
}

func (pok *PokSignatureProof) MarshalBinary() ([]byte, error) {
	data := append(pok.aPrime.ToAffineCompressed(), pok.aBar.ToAffineCompressed()...)
	data = append(data, pok.d.ToAffineCompressed()...)
	for _, p := range pok.proof1 {
		data = append(data, p.Bytes()...)
	}
	for _, p := range pok.proof2 {
		data = append(data, p.Bytes()...)
	}
	return data, nil
}

func (pok *PokSignatureProof) UnmarshalBinary(in []byte) error {
	scSize := len(pok.proof1[0].Bytes())
	ptSize := len(pok.aPrime.ToAffineCompressed())
	minSize := scSize*4 + ptSize*3
	inSize := len(in)
	if inSize < minSize {
		return fmt.Errorf("invalid byte sequence")
	}
	if (inSize-ptSize)%scSize != 0 {
		return fmt.Errorf("invalid byte sequence")
	}
	secretCnt := ((inSize - ptSize*3) / scSize) - 2
	offset := 0
	end := ptSize

	aPrime, err := pok.aPrime.FromAffineCompressed(in[offset:end])
	if err != nil {
		return err
	}
	offset = end
	end += ptSize
	aBar, err := pok.aBar.FromAffineCompressed(in[offset:end])
	if err != nil {
		return err
	}
	offset = end
	end += ptSize
	d, err := pok.d.FromAffineCompressed(in[offset:end])
	if err != nil {
		return err
	}
	offset = end
	end += scSize
	proof1i0, err := pok.proof1[0].SetBytes(in[offset:end])
	if err != nil {
		return err
	}
	offset = end
	end += scSize
	proof1i1, err := pok.proof1[1].SetBytes(in[offset:end])
	if err != nil {
		return err
	}
	proof2 := make([]curves.Scalar, secretCnt)
	for i := 0; i < secretCnt; i++ {
		offset = end
		end += scSize
		proof2[i], err = pok.proof1[0].SetBytes(in[offset:end])
		if err != nil {
			return err
		}
	}

	pok.aPrime = aPrime.(curves.PairingPoint)
	pok.aBar = aBar.(curves.PairingPoint)
	pok.d = d.(curves.PairingPoint)
	pok.proof1[0] = proof1i0
	pok.proof1[1] = proof1i1
	pok.proof2 = proof2
	return nil
}

// GetChallengeContribution converts the committed values to bytes
// for the Fiat-Shamir challenge
func (pok PokSignatureProof) GetChallengeContribution(
	generators *MessageGenerators,
	revealedMessages map[int]curves.Scalar,
	challenge common.Challenge,
	transcript *merlin.Transcript,
) {
	transcript.AppendMessage([]byte("A'"), pok.aPrime.ToAffineCompressed())
	transcript.AppendMessage([]byte("Abar"), pok.aBar.ToAffineCompressed())
	transcript.AppendMessage([]byte("D"), pok.d.ToAffineCompressed())

	proof1Points := []curves.Point{pok.aBar.Sub(pok.d), pok.aPrime, generators.h0}
	proof1Scalars := []curves.Scalar{challenge, pok.proof1[0], pok.proof1[1]}
	commitmentProof1 := pok.aPrime.SumOfProducts(proof1Points, proof1Scalars)
	transcript.AppendMessage([]byte("Proof1"), commitmentProof1.ToAffineCompressed())

	rPoints := make([]curves.Point, 1, len(revealedMessages)+1)
	rScalars := make([]curves.Scalar, 1, len(revealedMessages)+1)

	rPoints[0] = pok.aPrime.Generator()
	rScalars[0] = pok.proof1[0].One()

	for idx, msg := range revealedMessages {
		rPoints = append(rPoints, generators.Get(idx+1))
		rScalars = append(rScalars, msg)
	}

	r := pok.aPrime.SumOfProducts(rPoints, rScalars)

	pts := 3 + generators.length - len(revealedMessages)
	proof2Points := make([]curves.Point, 3, pts)
	proof2Scalars := make([]curves.Scalar, 3, pts)

	// R * c
	proof2Points[0] = r
	proof2Scalars[0] = challenge

	// D * -r3Hat
	proof2Points[1] = pok.d.Neg()
	proof2Scalars[1] = pok.proof2[0]

	// H0 * s'Hat
	proof2Points[2] = generators.h0
	proof2Scalars[2] = pok.proof2[1]

	j := 2
	for i := 0; i < generators.length; i++ {
		if _, contains := revealedMessages[i]; contains {
			continue
		}
		proof2Points = append(proof2Points, generators.Get(i+1))
		proof2Scalars = append(proof2Scalars, pok.proof2[j])
		j++
	}
	commitmentProof2 := r.SumOfProducts(proof2Points, proof2Scalars)

	transcript.AppendMessage([]byte("Proof2"), commitmentProof2.ToAffineCompressed())
}

// VerifySigPok only validates the signature proof,
// the selective disclosure proof is checked by
// verifying
// pok.challenge == computedChallenge
func (pok PokSignatureProof) VerifySigPok(pk *PublicKey) bool {
	return !pk.value.IsIdentity() &&
		!pok.aPrime.IsIdentity() &&
		!pok.aBar.IsIdentity() &&
		pok.aPrime.MultiPairing(pok.aPrime, pk.value, pok.aBar, pk.value.Generator().Neg().(curves.PairingPoint)).IsOne()
}

// Verify checks a signature proof of knowledge and selective disclosure proof
func (pok PokSignatureProof) Verify(
	revealedMsgs map[int]curves.Scalar,
	pk *PublicKey,
	generators *MessageGenerators,
	nonce common.Nonce,
	challenge common.Challenge,
	transcript *merlin.Transcript,
) bool {
	pok.GetChallengeContribution(generators, revealedMsgs, challenge, transcript)
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("signature proof of knowledge"), 64)
	vChallenge, err := pok.proof1[0].SetBytesWide(okm)
	if err != nil {
		return false
	}
	return pok.VerifySigPok(pk) && challenge.Cmp(vChallenge) == 0
}
