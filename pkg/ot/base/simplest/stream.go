package simplest

import (
	"encoding/gob"
	"io"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

// ReceiverStreamOTRun exposes the entire seed OT process for the receiver in "stream mode" to the user.
// what this means is that instead of calling the component methods in the process manually, and manually handling
// the encoding and decoding of the resulting output and input structs, the user needs _only_ to pass a ReadWriter
// (in practice this will be something like a websocket object), and this method will handle the entire process.
// this serves the dual (though related) purpose of conveniently bundling up the entire seed OT process,
// for use in tests, both in this package, as well as in the other packages which use this one (like cOT and mult).
func ReceiverStreamOTRun(receiver *Receiver, rw io.ReadWriter) error {
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	gob.Register(&curves.ScalarK256{})
	gob.Register(&curves.PointK256{})

	proof := &schnorr.Proof{}

	if err := dec.Decode(proof); err != nil {
		return errors.Wrap(err, "failed to decode proof in receiver stream OT")
	}

	receiversMaskedChoice, err := receiver.Round2VerifySchnorrAndPadTransfer(proof)
	if err != nil {
		return errors.Wrap(err, "error in round 2 in receiver stream OT")
	}
	if err = enc.Encode(receiversMaskedChoice); err != nil {
		return errors.Wrap(err, "error encoding result of round 1 in receiver stream OT")
	}
	var challenge []OtChallenge
	err = dec.Decode(&challenge)
	if err != nil {
		return errors.Wrap(err, "error decoding challenge in receiver stream OT")
	}
	challengeResponse, err := receiver.Round4RespondToChallenge(challenge)
	if err != nil {
		return errors.Wrap(err, "error computing round 2 challenge response in receiver stream OT")
	}
	if err = enc.Encode(challengeResponse); err != nil {
		return errors.Wrap(err, "error encoding challenge response in receiver stream OT")
	}
	var openings []ChallengeOpening
	err = dec.Decode(&openings)
	if err != nil {
		return errors.Wrap(err, "error decoding challenge openings in receiver stream OT")
	}
	return receiver.Round6Verify(openings)
}

// SenderStreamOTRun exposes the entire seed OT process for the sender in "stream mode" to the user.
// similarly to the above, this means that the user needs only to pass a `ReadWriter` representing the comm channel;
// this method will handle all encoding and decoding + writing and reading to the channel.
func SenderStreamOTRun(sender *Sender, rw io.ReadWriter) error {
	// again a high-level helper method showing the overall flow, this time for the sender.
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	gob.Register(&curves.ScalarK256{})
	gob.Register(&curves.PointK256{})

	proof, err := sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return err
	}
	if err = enc.Encode(proof); err != nil {
		return err
	}

	var receiversMaskedChoice []ReceiversMaskedChoices
	err = dec.Decode(&receiversMaskedChoice)
	if err != nil {
		return errors.Wrap(err, "error decoding receiver's masked choice in sender stream OT")
	}

	challenge, err := sender.Round3PadTransfer(receiversMaskedChoice)
	if err != nil {
		return errors.Wrap(err, "error during round 2 pad transfer in sender stream OT")
	}
	err = enc.Encode(challenge)
	if err != nil {
		return errors.Wrap(err, "error encoding challenge in sender stream OT")
	}
	var challengeResponses []OtChallengeResponse
	err = dec.Decode(&challengeResponses)
	if err != nil {
		return errors.Wrap(err, "error decoding challenges responses in sender stream OT")
	}
	opening, err := sender.Round5Verify(challengeResponses)
	if err != nil {
		return errors.Wrap(err, "error in round 3 verify in sender stream OT")
	}
	return enc.Encode(opening)
}
