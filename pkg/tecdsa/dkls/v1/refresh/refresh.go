//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// This file implements the key refresh protocol of [DKLs18](https://eprint.iacr.org/2018/499.pdf).
// The key refresh protocol is defined as follows:
// 1. Key Share:
//   1.1. alice generates k_A <-- F_q; writes it to merlin transcript. sends it to bob.
//   1.2. bob receives k_A and writes it to merlin transcript. generates k_B <-- F_q and writes it to merlin transcript. reads k out of merlin transcript. overwrites sk_B *= k. sends k_B to Alice.
//   1.3. alice writes k_B to merlin transcript. reads k from it. overwrites sk_A *= k^{-1}.
// 2. OT: Redo OT (as it is done in the DKG)
package refresh

import (
	"crypto/rand"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

// Alice struct encoding Alice's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Alice will NOT obtain the signature.
type Alice struct {
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
	// sender is the base OT sender.
	sender *simplest.Sender

	// secretKeyShare is Bob's secret key for the joint public key.
	secretKeyShare curves.Scalar

	// publicKey is the joint public key of Alice and Bob.
	publicKey curves.Point

	curve *curves.Curve

	transcript *merlin.Transcript
}

type RefreshRound2Output struct {
	SeedOTRound1Output *schnorr.Proof
	BobMultiplier      curves.Scalar
}

// NewAliceRefresh creates a party that can participate in 2-of-2 key refresh.
func NewAlice(curve *curves.Curve, dkgOutput *dkg.AliceOutput) *Alice {
	return &Alice{
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("Coinbase_DKLs_Refresh"),
	}
}

// NewBobRefresh creates a party that can participate in 2-of-2 key refresh.
func NewBob(curve *curves.Curve, dkgOutput *dkg.BobOutput) *Bob {
	return &Bob{
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("Coinbase_DKLs_Refresh"),
	}
}

func (alice *Alice) Round1RefreshGenerateSeed() curves.Scalar {
	refreshSeed := alice.curve.Scalar.Random(rand.Reader)
	alice.transcript.AppendMessage([]byte("alice refresh seed"), refreshSeed.Bytes())
	return refreshSeed
}

func (bob *Bob) Round2RefreshProduceSeedAndMultiplyAndStartOT(aliceSeed curves.Scalar) (*RefreshRound2Output, error) {
	bob.transcript.AppendMessage([]byte("alice refresh seed"), aliceSeed.Bytes())
	bobSeed := bob.curve.Scalar.Random(rand.Reader)
	bob.transcript.AppendMessage([]byte("bob refresh seed"), bobSeed.Bytes())
	k, err := bob.curve.NewScalar().SetBytes(
		bob.transcript.ExtractBytes([]byte("secret key share multiplier"), simplest.DigestSize),
	)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't produce bob's secret key share multiplier")
	}
	bob.secretKeyShare = bob.secretKeyShare.Mul(k)

	uniqueSessionId := [simplest.DigestSize]byte{} // note: will use and re-use this below for sub-session IDs.
	copy(uniqueSessionId[:], bob.transcript.ExtractBytes([]byte("salt for simplest OT"), simplest.DigestSize))
	bob.sender, err = simplest.NewSender(bob.curve, kos.Kappa, uniqueSessionId)
	if err != nil {
		return nil, errors.Wrap(err, "bob constructing new OT sender in refresh round 2")
	}
	seedOTRound1Output, err := bob.sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "bob computing round 1 of seed OT within refresh round 2")
	}

	return &RefreshRound2Output{
		SeedOTRound1Output: seedOTRound1Output,
		BobMultiplier:      bobSeed,
	}, nil
}

func (alice *Alice) Round3RefreshMultiplyRound2Ot(input *RefreshRound2Output) ([]simplest.ReceiversMaskedChoices, error) {
	alice.transcript.AppendMessage([]byte("bob refresh seed"), input.BobMultiplier.Bytes())
	k, err := alice.curve.NewScalar().SetBytes(
		alice.transcript.ExtractBytes([]byte("secret key share multiplier"), simplest.DigestSize),
	)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't produce bob's secret key share multiplier")
	}
	kInverse, err := k.Invert()
	if err != nil {
		return nil, errors.Wrap(err, "couldn't produce k inverse (alice's secret key share)")
	}
	alice.secretKeyShare = alice.secretKeyShare.Mul(kInverse)

	uniqueSessionId := [simplest.DigestSize]byte{} // note: will use and re-use this below for sub-session IDs.
	copy(uniqueSessionId[:], alice.transcript.ExtractBytes([]byte("salt for simplest OT"), simplest.DigestSize))
	alice.receiver, err = simplest.NewReceiver(alice.curve, kos.Kappa, uniqueSessionId)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't construct OT receiver")
	}

	return alice.receiver.Round2VerifySchnorrAndPadTransfer(input.SeedOTRound1Output)
}

func (bob *Bob) Round4RefreshRound3Ot(compressedReceiversMaskedChoice []simplest.ReceiversMaskedChoices) ([]simplest.OtChallenge, error) {
	return bob.sender.Round3PadTransfer(compressedReceiversMaskedChoice)
}

func (alice *Alice) Round5RefreshRound4Ot(challenge []simplest.OtChallenge) ([]simplest.OtChallengeResponse, error) {
	return alice.receiver.Round4RespondToChallenge(challenge)
}

func (bob *Bob) Round6RefreshRound5Ot(challengeResponses []simplest.OtChallengeResponse) ([]simplest.ChallengeOpening, error) {
	return bob.sender.Round5Verify(challengeResponses)
}

func (alice *Alice) Round7DkgRound6Ot(challengeOpenings []simplest.ChallengeOpening) error {
	return alice.receiver.Round6Verify(challengeOpenings)
}

func (alice *Alice) Output() *dkg.AliceOutput {
	return &dkg.AliceOutput{
		PublicKey:      alice.publicKey,
		SecretKeyShare: alice.secretKeyShare,
		SeedOtResult:   alice.receiver.Output,
	}
}

func (bob *Bob) Output() *dkg.BobOutput {
	return &dkg.BobOutput{
		PublicKey:      bob.publicKey,
		SecretKeyShare: bob.secretKeyShare,
		SeedOtResult:   bob.sender.Output,
	}
}
