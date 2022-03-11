//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package dkg implements the Distributed Key Generation (DKG) protocol of [DKLs18](https://eprint.iacr.org/2018/499.pdf).
// The DKG protocol is defined in "Protocol 2" page 7, of the paper. The Zero Knowledge Proof ideal functionalities are
// realized using schnorr proofs. Moreover, the seed OT is realized using the Verified Simplest OT protocol.
package dkg

import (
	"crypto/rand"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

// AliceOutput is the result of running DKG for Alice. It contains both the public and secret values that are needed
// for signing.
type AliceOutput struct {
	// PublicKey is the joint public key of Alice and Bob.
	// This value is public.
	PublicKey curves.Point

	// SecretKeyShare is Alice's secret key for the joint public key.
	// This output must be kept secret. If it is lost, the users will lose access and cannot create signatures.
	SecretKeyShare curves.Scalar

	// SeedOtResult are the outputs that the receiver will obtain as a result of running the "random" OT protocol.
	// This output must be kept secret. Although, if it is lost the users can run another OT protocol and obtain
	// new values to replace it.
	SeedOtResult *simplest.ReceiverOutput
}

// BobOutput is the result of running DKG for Bob. It contains both the public and secret values that are needed
// for signing.
type BobOutput struct {
	// PublicKey is the joint public key of Alice and Bob.
	// This value is public.
	PublicKey curves.Point

	// SecretKeyShare is Bob's secret key for the joint public key.
	// This output must be kept secret. If it is lost, the users will lose access and cannot create signatures.
	SecretKeyShare curves.Scalar

	// SeedOtResult are the outputs that the sender will obtain as a result of running the "random" OT protocol.
	// This output must be kept secret. Although, if it is lost the users can run another OT protocol and obtain
	// new values to replace it.
	SeedOtResult *simplest.SenderOutput
}

// Alice struct encoding Alice's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Alice will NOT obtain the signature.
type Alice struct {
	// prover is a schnorr prover for Alice's portion of public key.
	prover *schnorr.Prover

	// proof is alice's proof to her portion of the public key. It is stored as an intermediate value, during commitment phase.
	proof *schnorr.Proof

	// receiver is the base OT receiver.
	receiver *simplest.Receiver

	// secretKeyShare is Alice's secret key for the joint public key.
	secretKeyShare curves.Scalar

	// publicKey is the joint public key of Alice and Bob.
	publicKey curves.Point

	curve *curves.Curve

	transcript *merlin.Transcript
}

// Bob struct encoding Bob's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Bob will obtain the signature.
type Bob struct {
	// prover is a schnorr prover for Bob's portion of public key.
	prover *schnorr.Prover // this is a "schnorr statement" for pkB.

	// sender is the base OT sender.
	sender *simplest.Sender

	// secretKeyShare is Bob's secret key for the joint public key.
	secretKeyShare curves.Scalar

	// publicKey is the joint public key of Alice and Bob.
	publicKey curves.Point

	// schnorr proof commitment to Alice's schnorr proof.
	aliceCommitment schnorr.Commitment
	// 32-byte transcript salt which will be used for Alice's schnorr proof
	aliceSalt [simplest.DigestSize]byte

	curve *curves.Curve

	transcript *merlin.Transcript
}

// Round2Output contains the output of the 2nd round of DKG.
type Round2Output struct {
	// Seed is the random value used to derive the joint unique session id.
	Seed [simplest.DigestSize]byte

	// Commitment is the commitment to the ZKP to Alice's secret key share.
	Commitment schnorr.Commitment
}

// NewAlice creates a party that can participate in 2-of-2 DKG and threshold signature.
func NewAlice(curve *curves.Curve) *Alice {
	return &Alice{
		curve:      curve,
		transcript: merlin.NewTranscript("Coinbase_DKLs_DKG"),
	}
}

// NewBob creates a party that can participate in 2-of-2 DKG and threshold signature. This party
// is the receiver of the signature at the end.
func NewBob(curve *curves.Curve) *Bob {
	return &Bob{
		curve:      curve,
		transcript: merlin.NewTranscript("Coinbase_DKLs_DKG"),
	}
}

// Round1GenerateRandomSeed Bob flips random coins, and sends these to Alice
// in this round, Bob flips 32 random bytes and sends them to Alice.
// note that this is not _explicitly_ given as part of the protocol in https://eprint.iacr.org/2018/499.pdf, Protocol 1).
// rather, it is part of our generation of a unique session identifier, for use in subsequent schnorr proofs / seed OT / etc.
// we do it by having each party sample 32 bytes, then by appending _both_ as salts. secure if either party is honest
func (bob *Bob) Round1GenerateRandomSeed() ([simplest.DigestSize]byte, error) {
	bobSeed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(bobSeed[:]); err != nil {
		return [simplest.DigestSize]byte{}, errors.Wrap(err, "generating random bytes in bob DKG round 1 generate")
	}
	bob.transcript.AppendMessage([]byte("session_id_bob"), bobSeed[:]) // note: bob appends first here
	return bobSeed, nil
}

// Round2CommitToProof steps 1) and 2) of protocol 2 on page 7.
func (alice *Alice) Round2CommitToProof(bobSeed [simplest.DigestSize]byte) (*Round2Output, error) {
	aliceSeed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(aliceSeed[:]); err != nil {
		return nil, errors.Wrap(err, "generating random bytes in bob DKG round 1 generate")
	}
	alice.transcript.AppendMessage([]byte("session_id_bob"), bobSeed[:])
	alice.transcript.AppendMessage([]byte("session_id_alice"), aliceSeed[:])

	var err error
	uniqueSessionId := [simplest.DigestSize]byte{} // note: will use and re-use this below for sub-session IDs.
	copy(uniqueSessionId[:], alice.transcript.ExtractBytes([]byte("salt for simplest OT"), simplest.DigestSize))
	alice.receiver, err = simplest.NewReceiver(alice.curve, kos.Kappa, uniqueSessionId)
	if err != nil {
		return nil, errors.Wrap(err, "alice constructing new seed OT receiver in Alice DKG round 1")
	}

	alice.secretKeyShare = alice.curve.Scalar.Random(rand.Reader)
	copy(uniqueSessionId[:], alice.transcript.ExtractBytes([]byte("salt for alice schnorr"), simplest.DigestSize))
	alice.prover = schnorr.NewProver(alice.curve, nil, uniqueSessionId[:])
	var commitment schnorr.Commitment
	alice.proof, commitment, err = alice.prover.ProveCommit(alice.secretKeyShare) // will mutate `pkA`
	if err != nil {
		return nil, errors.Wrap(err, "prove + commit in alice DKG Commit round 1")
	}
	return &Round2Output{
		Commitment: commitment,
		Seed:       aliceSeed,
	}, nil
}

// Round3SchnorrProve receives Bob's Commitment and returns schnorr statment + proof.
// Steps 1 and 3 of protocol 2 on page 7.
func (bob *Bob) Round3SchnorrProve(round2Output *Round2Output) (*schnorr.Proof, error) {
	bob.transcript.AppendMessage([]byte("session_id_alice"), round2Output.Seed[:])

	bob.aliceCommitment = round2Output.Commitment // store it, so that we can check when alice decommits

	var err error
	uniqueSessionId := [simplest.DigestSize]byte{} // note: will use and re-use this below for sub-session IDs.
	copy(uniqueSessionId[:], bob.transcript.ExtractBytes([]byte("salt for simplest OT"), simplest.DigestSize))
	bob.sender, err = simplest.NewSender(bob.curve, kos.Kappa, uniqueSessionId)
	if err != nil {
		return nil, errors.Wrap(err, "bob constructing new OT sender in DKG round 2")
	}
	// extract alice's salt in the right order; we won't use this until she reveals her proof and we verify it below
	copy(bob.aliceSalt[:], bob.transcript.ExtractBytes([]byte("salt for alice schnorr"), simplest.DigestSize))
	bob.secretKeyShare = bob.curve.Scalar.Random(rand.Reader)
	copy(uniqueSessionId[:], bob.transcript.ExtractBytes([]byte("salt for bob schnorr"), simplest.DigestSize))
	bob.prover = schnorr.NewProver(bob.curve, nil, uniqueSessionId[:])
	proof, err := bob.prover.Prove(bob.secretKeyShare)
	if err != nil {
		return nil, errors.Wrap(err, "bob schnorr proving in DKG round 2")
	}
	return proof, err
}

// Round4VerifyAndReveal step 4 of protocol 2 on page 7.
func (alice *Alice) Round4VerifyAndReveal(proof *schnorr.Proof) (*schnorr.Proof, error) {
	var err error
	uniqueSessionId := [simplest.DigestSize]byte{}
	copy(uniqueSessionId[:], alice.transcript.ExtractBytes([]byte("salt for bob schnorr"), simplest.DigestSize))
	if err = schnorr.Verify(proof, alice.curve, nil, uniqueSessionId[:]); err != nil {
		return nil, errors.Wrap(err, "alice's verification of Bob's schnorr proof failed in DKG round 3")
	}
	alice.publicKey = proof.Statement.Mul(alice.secretKeyShare)
	return alice.proof, nil
}

// Round5DecommitmentAndStartOt step 5 of protocol 2 on page 7.
func (bob *Bob) Round5DecommitmentAndStartOt(proof *schnorr.Proof) (*schnorr.Proof, error) {
	var err error
	if err = schnorr.DecommitVerify(proof, bob.aliceCommitment, bob.curve, nil, bob.aliceSalt[:]); err != nil {
		return nil, errors.Wrap(err, "decommit + verify failed in bob's DKG round 4")
	}
	bob.publicKey = proof.Statement.Mul(bob.secretKeyShare)
	seedOTRound1Output, err := bob.sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "bob computing round 1 of seed  OT within DKG round 4")
	}
	return seedOTRound1Output, nil
}

// Round6DkgRound2Ot is a thin wrapper around the 2nd round of seed OT protocol.
func (alice *Alice) Round6DkgRound2Ot(proof *schnorr.Proof) ([]simplest.ReceiversMaskedChoices, error) {
	return alice.receiver.Round2VerifySchnorrAndPadTransfer(proof)
}

// Round7DkgRound3Ot is a thin wrapper around the 3rd round of seed OT protocol.
func (bob *Bob) Round7DkgRound3Ot(compressedReceiversMaskedChoice []simplest.ReceiversMaskedChoices) ([]simplest.OtChallenge, error) {
	return bob.sender.Round3PadTransfer(compressedReceiversMaskedChoice)
}

// Round8DkgRound4Ot is a thin wrapper around the 4th round of seed OT protocol.
func (alice *Alice) Round8DkgRound4Ot(challenge []simplest.OtChallenge) ([]simplest.OtChallengeResponse, error) {
	return alice.receiver.Round4RespondToChallenge(challenge)
}

// Round9DkgRound5Ot is a thin wrapper around the 5th round of seed OT protocol.
func (bob *Bob) Round9DkgRound5Ot(challengeResponses []simplest.OtChallengeResponse) ([]simplest.ChallengeOpening, error) {
	return bob.sender.Round5Verify(challengeResponses)
}

// Round10DkgRound6Ot is a thin wrapper around the 6th round of seed OT protocol.
func (alice *Alice) Round10DkgRound6Ot(challengeOpenings []simplest.ChallengeOpening) error {
	return alice.receiver.Round6Verify(challengeOpenings)
}

// Output returns the output of the DKG operation. Must be called after step 9. Calling it before that step
// has undefined behaviour.
func (alice *Alice) Output() *AliceOutput {
	return &AliceOutput{
		PublicKey:      alice.publicKey,
		SecretKeyShare: alice.secretKeyShare,
		SeedOtResult:   alice.receiver.Output,
	}
}

// Output returns the output of the DKG operation. Must be called after step 9. Calling it before that step
// has undefined behaviour.
func (bob *Bob) Output() *BobOutput {
	return &BobOutput{
		PublicKey:      bob.publicKey,
		SecretKeyShare: bob.secretKeyShare,
		SeedOtResult:   bob.sender.Output,
	}
}
