package v1

import (
	"bytes"
	"encoding/gob"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/protocol"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/refresh"
)

func newRefreshProtocolMessage(payload []byte, round string, version uint) *protocol.Message {
	return &protocol.Message{
		Protocol: protocol.Dkls18Refresh,
		Version:  version,
		Payloads: map[string][]byte{payloadKey: payload},
		Metadata: map[string]string{"round": round},
	}
}

func versionIsSupported(messageVersion uint) error {
	if messageVersion < uint(protocol.Version1) {
		return errors.New("only version 1 is supported.")
	}
	return nil
}

func encodeRefreshRound1Output(seed curves.Scalar, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	registerTypes()
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(&seed); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "1", version), nil
}

func decodeRefreshRound2Input(m *protocol.Message) (curves.Scalar, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(curves.Scalar)
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return *decoded, nil
}

func encodeRefreshRound2Output(output *refresh.RefreshRound2Output, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(output); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "2", version), nil
}

func decodeRefreshRound3Input(m *protocol.Message) (*refresh.RefreshRound2Output, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(refresh.RefreshRound2Output)
	if err := dec.Decode(decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeRefreshRound3Output(choices []simplest.ReceiversMaskedChoices, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(choices); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "3", version), nil
}

func decodeRefreshRound4Input(m *protocol.Message) ([]simplest.ReceiversMaskedChoices, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.ReceiversMaskedChoices{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeRefreshRound4Output(challenge []simplest.OtChallenge, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(challenge); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "4", version), nil
}

func decodeRefreshRound5Input(m *protocol.Message) ([]simplest.OtChallenge, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.OtChallenge{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeRefreshRound5Output(responses []simplest.OtChallengeResponse, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(responses); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "5", version), nil
}

func decodeRefreshRound6Input(m *protocol.Message) ([]simplest.OtChallengeResponse, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.OtChallengeResponse{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeRefreshRound6Output(opening []simplest.ChallengeOpening, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(opening); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "6", version), nil
}

func decodeRefreshRound7Input(m *protocol.Message) ([]simplest.ChallengeOpening, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.ChallengeOpening{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

// EncodeAliceRefreshOutput serializes Alice Refresh output based on the protocol version.
func EncodeAliceRefreshOutput(result *dkg.AliceOutput, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	registerTypes()
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(result); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "alice-output", version), nil
}

// DecodeAliceRefreshResult deserializes Alice refresh output.
func DecodeAliceRefreshResult(m *protocol.Message) (*dkg.AliceOutput, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	registerTypes()
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(dkg.AliceOutput)
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

// EncodeBobRefreshOutput serializes Bob refresh output based on the protocol version.
func EncodeBobRefreshOutput(result *dkg.BobOutput, version uint) (*protocol.Message, error) {
	if err := versionIsSupported(version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	registerTypes()
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(result); err != nil {
		return nil, errors.WithStack(err)
	}
	return newRefreshProtocolMessage(buf.Bytes(), "bob-output", version), nil
}

// DecodeBobRefreshResult deserializes Bob refhresh output.
func DecodeBobRefreshResult(m *protocol.Message) (*dkg.BobOutput, error) {
	if err := versionIsSupported(m.Version); err != nil {
		return nil, errors.Wrap(err, "version error")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(dkg.BobOutput)
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}
