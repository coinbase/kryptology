// Package ottest contains some utilities to test ot functions. The main goal is to reduce the code duplication in
// various other packages that need to run an OT in their test setup stage.
package ottest

import (
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
)

// RunSimplestOT is a utility function used _only_ during various tests.
// essentially, it encapsulates the entire process of running a base OT, so that other tests can use it / bootstrap themselves.
// it handles the creation of the base OT sender and receiver, as well as orchestrates the rounds on them;
// it returns their outsputs, so that others can use them.
func RunSimplestOT(curve *curves.Curve, batchSize int, uniqueSessionId [simplest.DigestSize]byte) (*simplest.SenderOutput, *simplest.ReceiverOutput, error) {
	receiver, err := simplest.NewReceiver(curve, batchSize, uniqueSessionId)
	if err != nil {
		return nil, nil, errors.Wrap(err, "constructing OT receiver in run simplest OT")
	}
	sender, err := simplest.NewSender(curve, batchSize, uniqueSessionId)
	if err != nil {
		return nil, nil, errors.Wrap(err, "constructing OT sender in run simplest OT")
	}
	proof, err := sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "sender round 1 in run simplest OT")
	}
	receiversMaskedChoice, err := receiver.Round2VerifySchnorrAndPadTransfer(proof)
	if err != nil {
		return nil, nil, errors.Wrap(err, "receiver round 2 in run simplest OT")
	}
	challenge, err := sender.Round3PadTransfer(receiversMaskedChoice)
	if err != nil {
		return nil, nil, errors.Wrap(err, "sender round 3 in run simplest OT")
	}
	challengeResponse, err := receiver.Round4RespondToChallenge(challenge)
	if err != nil {
		return nil, nil, errors.Wrap(err, "receiver round 4 in run simplest OT")
	}
	challengeOpenings, err := sender.Round5Verify(challengeResponse)
	if err != nil {
		return nil, nil, errors.Wrap(err, "sender round 5 in run simplest OT")
	}
	err = receiver.Round6Verify(challengeOpenings)
	if err != nil {
		return nil, nil, errors.Wrap(err, "receiver round 6 in run simplest OT")
	}
	return sender.Output, receiver.Output, nil
}
