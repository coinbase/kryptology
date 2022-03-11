//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package dealer implements key generation via a trusted dealer for the protocol [DKLs18](https://eprint.iacr.org/2018/499.pdf).
// The trusted dealer produces the same output as the corresponding DKG protocol and can be used for signing without
// additional modifications.
// Note that running actual DKG is ALWAYS recommended over a trusted dealer.
package dealer

import (
	"crypto/rand"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
)

// GenerationAndDeal produces private key material for alice and bob which they can later use in signing.
// Running actual DKG is ALWAYS recommended over using this function, as this function breaks the security guarantees of DKG.
// only use this function if you have a very good reason to.
func GenerateAndDeal(curve *curves.Curve) (*dkg.AliceOutput, *dkg.BobOutput, error) {
	aliceSecretShare, bobSecretShare, publicKey := produceKeyShares(curve)
	aliceOTOutput, bobOTOutput, err := produceOTResults(curve)
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't produce OT results")
	}
	alice := &dkg.AliceOutput{
		PublicKey:      publicKey,
		SecretKeyShare: aliceSecretShare,
		SeedOtResult:   aliceOTOutput,
	}
	bob := &dkg.BobOutput{
		PublicKey:      publicKey,
		SecretKeyShare: bobSecretShare,
		SeedOtResult:   bobOTOutput,
	}
	return alice, bob, nil
}

func produceKeyShares(curve *curves.Curve) (aliceSecretShare curves.Scalar, bobSecretShare curves.Scalar, publicKey curves.Point) {
	aliceSecretShare = curve.Scalar.Random(rand.Reader)
	bobSecretShare = curve.Scalar.Random(rand.Reader)
	publicKey = curve.ScalarBaseMult(aliceSecretShare.Mul(bobSecretShare))
	return aliceSecretShare, bobSecretShare, publicKey
}

func produceOTResults(curve *curves.Curve) (*simplest.ReceiverOutput, *simplest.SenderOutput, error) {
	oneTimePadEncryptionKeys := make([]simplest.OneTimePadEncryptionKeys, kos.Kappa)
	oneTimePadDecryptionKey := make([]simplest.OneTimePadDecryptionKey, kos.Kappa)

	// we'll need a receiver because in its constructor random bits will be selected.
	receiver, err := simplest.NewReceiver(curve, kos.Kappa, [simplest.DigestSize]byte{})
	if err != nil {
		return nil, nil, errors.Wrap(err, "couldn't initialize a receiver")
	}
	packedRandomChoiceBits, randomChoiceBits := receiver.Output.PackedRandomChoiceBits, receiver.Output.RandomChoiceBits

	for i := 0; i < kos.Kappa; i++ {
		if _, err := rand.Read(oneTimePadEncryptionKeys[i][0][:]); err != nil {
			return nil, nil, errors.WithStack(err)
		}
		if _, err := rand.Read(oneTimePadEncryptionKeys[i][1][:]); err != nil {
			return nil, nil, errors.WithStack(err)
		}
		oneTimePadDecryptionKey[i] = oneTimePadEncryptionKeys[i][randomChoiceBits[i]]
	}

	senderOutput := &simplest.SenderOutput{
		OneTimePadEncryptionKeys: oneTimePadEncryptionKeys,
	}
	receiverOutput := &simplest.ReceiverOutput{
		PackedRandomChoiceBits:  packedRandomChoiceBits,
		RandomChoiceBits:        randomChoiceBits,
		OneTimePadDecryptionKey: oneTimePadDecryptionKey,
	}
	return receiverOutput, senderOutput, nil
}
