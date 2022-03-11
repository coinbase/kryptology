package kos

import (
	"encoding/gob"
	"io"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
)

// ReceiverStreamCOtRun exposes an end-to-end "streaming" version of the cOT process for the receiver.
// this is similar to what we're also doing in the base OT side. the user only passes an arbitrary `ReadWriter` here,
// together with the relevant inputs (namely a choice vector); this method handles all parts of the process,
// including both encoding / decoding and writing to / reading from the stream.
func ReceiverStreamCOtRun(receiver *Receiver, hashKeySeed [simplest.DigestSize]byte, choice [COtBlockSizeBytes]byte, rw io.ReadWriter) error {
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)

	firstMessage, err := receiver.Round1Initialize(hashKeySeed, choice)
	if err != nil {
		return errors.Wrap(err, "computing first message in receiver stream cOT")
	}
	if err = enc.Encode(firstMessage); err != nil {
		return errors.Wrap(err, "encoding first message in receiver stream cOT")
	}
	responseTau := &Round2Output{}
	if err = dec.Decode(responseTau); err != nil {
		return errors.Wrap(err, "decoding responseTau in receiver stream OT")
	}
	if err = receiver.Round3Transfer(responseTau); err != nil {
		return errors.Wrap(err, "error during round 3 in receiver stream OT")
	}
	return nil
}

// SenderStreamCOtRun exposes the end-to-end "streaming" version of cOT for the sender.
// the sender should pass an arbitrary ReadWriter together with their input; this will handle the whole process,
// including all component methods, plus reading to and writing from the network.
func SenderStreamCOtRun(sender *Sender, hashKeySeed [simplest.DigestSize]byte, input [L][OtWidth]curves.Scalar, rw io.ReadWriter) error {
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)

	firstMessage := &Round1Output{}
	if err := dec.Decode(firstMessage); err != nil {
		return errors.Wrap(err, "decoding first message in sender stream cOT")
	}
	responseTau, err := sender.Round2Transfer(hashKeySeed, input, firstMessage)
	if err != nil {
		return errors.Wrap(err, "error in round 2 in sender stream cOT")
	}
	if err = enc.Encode(responseTau); err != nil {
		return errors.Wrap(err, "encoding responseTau in sender stream cOT")
	}
	return nil
}
