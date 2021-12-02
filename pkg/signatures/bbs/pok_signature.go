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
	"io"
)

// PokSignature a.k.a. Proof of Knowledge of a Signature
// is used by the prover to convince a verifier
// that they possess a valid signature and
// can selectively disclose a set of signed messages
type PokSignature struct {
	// These values correspond to values with the same name
	// as section 4.5 in <https://eprint.iacr.org/2016/663.pdf>
	aPrime, aBar, d curves.PairingPoint
	// proof1 for proving signature
	// proof2 for selective disclosure
	proof1, proof2 *common.ProofCommittedBuilder
	// secrets1 for proving signature
	// secrets2 for proving relation
	// g1 * h1^m1 * h2^m2.... for all disclosed messages
	// m_i == d^r3 * h_0^{-s_prime} * h1^-m1 * h2^-m2.... for all undisclosed messages m_i
	secrets1, secrets2 []curves.Scalar
}

// NewPokSignature creates the initial proof data before a Fiat-Shamir calculation
func NewPokSignature(sig *Signature,
	generators *MessageGenerators,
	msgs []common.ProofMessage,
	reader io.Reader) (*PokSignature, error) {

	if len(msgs) != generators.length {
		return nil, fmt.Errorf("mismatch messages and generators")
	}

	r1 := getNonZeroScalar(sig.s, reader)
	r2 := getNonZeroScalar(sig.s, reader)
	r3, err := r1.Invert()
	if err != nil {
		return nil, err
	}

	sigMsgs := make([]curves.Scalar, len(msgs))
	for i, m := range msgs {
		sigMsgs[i] = m.GetMessage()
	}

	b := computeB(sig.s, sigMsgs, generators)

	aPrime, ok := sig.a.Mul(r1).(curves.PairingPoint)
	if !ok {
		return nil, fmt.Errorf("invalid point")
	}
	aBar, ok := b.Mul(r1).Sub(aPrime.Mul(sig.e)).(curves.PairingPoint)
	if !ok {
		return nil, fmt.Errorf("invalid point")
	}
	// d = b * r1 + h0 * r2
	d, ok := aPrime.SumOfProducts([]curves.Point{b, generators.h0}, []curves.Scalar{r1, r2}).(curves.PairingPoint)
	if !ok {
		return nil, fmt.Errorf("invalid point")
	}

	// s' = s + r2r3
	sPrime := sig.s.Add(r2.Mul(r3))

	// For proving relation aBar - d = aPrime * -e + h0 * r2
	curve := curves.Curve{
		Scalar: sig.s.Zero(),
		Point:  sig.a.Identity(),
	}
	proof1 := common.NewProofCommittedBuilder(&curve)
	// For aPrime * -e
	err = proof1.CommitRandom(aPrime, reader)
	if err != nil {
		return nil, err
	}
	err = proof1.CommitRandom(generators.h0, reader)
	if err != nil {
		return nil, err
	}
	secrets1 := []curves.Scalar{sig.e, r2}

	// For selective disclosure
	proof2 := common.NewProofCommittedBuilder(&curve)
	// For d * -r3
	err = proof2.CommitRandom(d.Neg(), reader)
	if err != nil {
		return nil, err
	}
	// For h0 * s'
	err = proof2.CommitRandom(generators.h0, reader)
	if err != nil {
		return nil, err
	}
	secrets2 := make([]curves.Scalar, 0, len(msgs)+2)
	secrets2 = append(secrets2, r3)
	secrets2 = append(secrets2, sPrime)

	for i, m := range msgs {
		if m.IsHidden() {
			err = proof2.Commit(generators.Get(i+1), m.GetBlinding(reader))
			if err != nil {
				return nil, err
			}
			secrets2 = append(secrets2, m.GetMessage())
		}
	}

	return &PokSignature{
		aPrime,
		aBar,
		d,
		proof1,
		proof2,
		secrets1,
		secrets2,
	}, nil
}

// GetChallengeContribution returns the bytes that should be added to
// a sigma protocol transcript for generating the challenge
func (pok *PokSignature) GetChallengeContribution(transcript *merlin.Transcript) {
	transcript.AppendMessage([]byte("A'"), pok.aPrime.ToAffineCompressed())
	transcript.AppendMessage([]byte("Abar"), pok.aBar.ToAffineCompressed())
	transcript.AppendMessage([]byte("D"), pok.d.ToAffineCompressed())
	transcript.AppendMessage([]byte("Proof1"), pok.proof1.GetChallengeContribution())
	transcript.AppendMessage([]byte("Proof2"), pok.proof2.GetChallengeContribution())
}

// GenerateProof converts the blinding factors and secrets into Schnorr proofs
func (pok *PokSignature) GenerateProof(challenge curves.Scalar) (*PokSignatureProof, error) {
	proof1, err := pok.proof1.GenerateProof(challenge, pok.secrets1)
	if err != nil {
		return nil, err
	}
	proof2, err := pok.proof2.GenerateProof(challenge, pok.secrets2)
	if err != nil {
		return nil, err
	}
	return &PokSignatureProof{
		aPrime: pok.aPrime,
		aBar:   pok.aBar,
		d:      pok.d,
		proof1: proof1,
		proof2: proof2,
	}, nil
}
