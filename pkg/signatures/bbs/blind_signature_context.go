//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package bbs

import (
	"fmt"
	"io"
	"sort"

	"github.com/gtank/merlin"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/signatures/common"
)

// BlindSignatureContext contains the data used for computing
// a blind signature and verifying proof of hidden messages from
// a future signature holder. A potential holder commits to messages
// that the signer will not know during the signing process
// rendering them hidden, but requires the holder to
// prove knowledge of those messages so a malicious party
// doesn't add just random data from anywhere.
type BlindSignatureContext struct {
	// The blinded signature commitment
	commitment common.Commitment
	// The challenge hash for the Fiat-Shamir heuristic
	challenge curves.Scalar
	// The proofs of hidden messages.
	proofs []curves.Scalar
}

// NewBlindSignatureContext creates the data needed to
// send to a signer to complete a blinded signature
// `msgs` is an index to message map where the index
// corresponds to the index in `generators`
// msgs are hidden from the signer but can also be empty
// if no messages are hidden but a blind signature is still desired
// because the signer should have no knowledge of the signature
func NewBlindSignatureContext(curve *curves.PairingCurve, msgs map[int]curves.Scalar, generators *MessageGenerators, nonce common.Nonce, reader io.Reader) (*BlindSignatureContext, common.SignatureBlinding, error) {
	if curve == nil || generators == nil || nonce == nil || reader == nil {
		return nil, nil, internal.ErrNilArguments
	}
	points := make([]curves.Point, 0)
	secrets := make([]curves.Scalar, 0)

	committing := common.NewProofCommittedBuilder(&curves.Curve{
		Scalar: curve.Scalar,
		Point:  curve.Scalar.Point().(curves.PairingPoint).OtherGroup(),
		Name:   curve.Name,
	})

	// C = h0^blinding_factor*h_i^m_i.....
	for i, m := range msgs {
		if i > generators.length || i < 0 {
			return nil, nil, fmt.Errorf("invalid index")
		}
		secrets = append(secrets, m)
		pt := generators.Get(i + 1)
		points = append(points, pt)
		err := committing.CommitRandom(pt, reader)
		if err != nil {
			return nil, nil, err
		}
	}
	blinding, ok := curve.Scalar.Random(reader).(common.SignatureBlinding)
	if !ok {
		return nil, nil, fmt.Errorf("unable to create signature blinding")
	}
	secrets = append(secrets, blinding)

	h0 := generators.Get(0)
	points = append(points, h0)
	err := committing.CommitRandom(h0, reader)
	if err != nil {
		return nil, nil, err
	}

	// Create a random commitment, compute challenges and response.
	// The proof of knowledge consists of a commitment and responses
	// Holder and signer engage in a proof of knowledge for `commitment`
	commitment := curve.Scalar.Point().(curves.PairingPoint).OtherGroup().SumOfProducts(points, secrets)
	transcript := merlin.NewTranscript("new blind signature")
	transcript.AppendMessage([]byte("random commitment"), committing.GetChallengeContribution())
	transcript.AppendMessage([]byte("blind commitment"), commitment.ToAffineCompressed())
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("blind signature context challenge"), 64)
	challenge, err := curve.Scalar.SetBytesWide(okm)
	if err != nil {
		return nil, nil, err
	}
	proofs, err := committing.GenerateProof(challenge, secrets)
	if err != nil {
		return nil, nil, err
	}
	return &BlindSignatureContext{
		commitment: commitment,
		challenge:  challenge,
		proofs:     proofs,
	}, blinding, nil
}

func (bsc *BlindSignatureContext) Init(curve *curves.PairingCurve) *BlindSignatureContext {
	bsc.challenge = curve.NewScalar()
	bsc.commitment = curve.Scalar.Point().(curves.PairingPoint).OtherGroup()
	bsc.proofs = make([]curves.Scalar, 0)
	return bsc
}

// MarshalBinary store the generators as a sequence of bytes
// where each point is compressed.
// Needs (N + 1) * ScalarSize + PointSize
func (bsc BlindSignatureContext) MarshalBinary() ([]byte, error) {
	buffer := append(bsc.commitment.ToAffineCompressed(), bsc.challenge.Bytes()...)
	for _, p := range bsc.proofs {
		buffer = append(buffer, p.Bytes()...)
	}
	return buffer, nil
}

func (bsc *BlindSignatureContext) UnmarshalBinary(in []byte) error {
	scSize := len(bsc.challenge.Bytes())
	ptSize := len(bsc.commitment.ToAffineCompressed())
	if len(in) < scSize*2+ptSize {
		return fmt.Errorf("insufficient number of bytes")
	}

	if (len(in)-ptSize)%scSize != 0 {
		return fmt.Errorf("invalid byte sequence")
	}
	commitment, err := bsc.commitment.FromAffineCompressed(in[:ptSize])
	if err != nil {
		return err
	}
	challenge, err := bsc.challenge.SetBytes(in[ptSize:(ptSize + scSize)])
	if err != nil {
		return err
	}

	nProofs := ((len(in) - ptSize) / scSize) - 1
	proofs := make([]curves.Scalar, nProofs)
	for i := 0; i < nProofs; i++ {
		proofs[i], err = bsc.challenge.SetBytes(in[(ptSize + (i+1)*scSize):(ptSize + (i+2)*scSize)])
		if err != nil {
			return err
		}
	}
	bsc.commitment = commitment
	bsc.challenge = challenge
	bsc.proofs = proofs
	return nil
}

// Verify validates a proof of hidden messages
func (bsc BlindSignatureContext) Verify(knownMsgs []int, generators *MessageGenerators, nonce common.Nonce) error {
	known := make(map[int]bool, len(knownMsgs))
	for _, i := range knownMsgs {
		if i > generators.length {
			return fmt.Errorf("invalid message index")
		}
		known[i] = true
	}

	points := make([]curves.Point, 0)
	for i := 0; i < generators.length; i++ {
		if _, contains := known[i]; !contains {
			points = append(points, generators.Get(i+1))
		}
	}
	points = append(points, generators.Get(0), bsc.commitment)
	scalars := append(bsc.proofs, bsc.challenge.Neg())

	commitment := points[0].SumOfProducts(points, scalars)
	transcript := merlin.NewTranscript("new blind signature")
	transcript.AppendMessage([]byte("random commitment"), commitment.ToAffineCompressed())
	transcript.AppendMessage([]byte("blind commitment"), bsc.commitment.ToAffineCompressed())
	transcript.AppendMessage([]byte("nonce"), nonce.Bytes())
	okm := transcript.ExtractBytes([]byte("blind signature context challenge"), 64)
	challenge, err := bsc.challenge.SetBytesWide(okm)
	if err != nil {
		return err
	}

	if challenge.Cmp(bsc.challenge) != 0 {
		return fmt.Errorf("invalid proof")
	}
	return nil
}

// ToBlindSignature converts a blind signature where
// msgs are known to the signer
// `msgs` is an index to message map where the index
// corresponds to the index in `generators`
func (bsc BlindSignatureContext) ToBlindSignature(msgs map[int]curves.Scalar, sk *SecretKey, generators *MessageGenerators, nonce common.Nonce) (*BlindSignature, error) {
	if sk == nil || generators == nil || nonce == nil {
		return nil, internal.ErrNilArguments
	}
	if sk.value.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}
	tv1 := make([]int, 0, len(msgs))
	for i := range msgs {
		if i > generators.length {
			return nil, fmt.Errorf("not enough message generators")
		}
		tv1 = append(tv1, i)
	}
	sort.Ints(tv1)
	signingMsgs := make([]curves.Scalar, len(msgs))
	for i, index := range tv1 {
		signingMsgs[i] = msgs[index]
	}
	err := bsc.Verify(tv1, generators, nonce)
	if err != nil {
		return nil, err
	}

	drbg := sha3.NewShake256()
	_, _ = drbg.Write(sk.value.Bytes())
	addDeterministicNonceData(generators, signingMsgs, drbg)
	// Should yield non-zero values for `e` and `s`, very small likelihood of being zero
	e := getNonZeroScalar(sk.value, drbg)
	s := getNonZeroScalar(sk.value, drbg)

	exp, err := e.Add(sk.value).Invert()
	if err != nil {
		return nil, err
	}
	// B = g1+h_0^s+h_1^m_1...
	points := make([]curves.Point, len(msgs)+3)
	scalars := make([]curves.Scalar, len(msgs)+3)
	points[0] = bsc.commitment
	points[1] = bsc.commitment.Generator()
	points[2] = generators.Get(0)
	scalars[0] = sk.value.One()
	scalars[1] = sk.value.One()
	scalars[2] = s
	i := 3
	for idx, m := range msgs {
		points[i] = generators.Get(idx + 1)
		scalars[i] = m
		i++
	}
	b := bsc.commitment.SumOfProducts(points, scalars)
	return &BlindSignature{
		a: b.Mul(exp).(curves.PairingPoint),
		e: e,
		s: s,
	}, nil
}
