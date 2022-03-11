package v1

import (
	"bytes"
	"encoding/gob"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/protocol"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/sign"
)

func newSignProtocolMessage(payload []byte, round string, version uint) *protocol.Message {
	return &protocol.Message{
		Protocol: protocol.Dkls18Sign,
		Version:  version,
		Payloads: map[string][]byte{payloadKey: payload},
		Metadata: map[string]string{"round": round},
	}
}

func encodeSignRound1Output(commitment [32]byte, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(&commitment); err != nil {
		return nil, errors.WithStack(err)
	}
	return newSignProtocolMessage(buf.Bytes(), "1", version), nil
}

func decodeSignRound2Input(m *protocol.Message) ([32]byte, error) {
	if m.Version != protocol.Version1 {
		return [32]byte{}, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := [32]byte{}
	if err := dec.Decode(&decoded); err != nil {
		return [32]byte{}, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeSignRound2Output(output *sign.SignRound2Output, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(output); err != nil {
		return nil, errors.WithStack(err)
	}
	return newSignProtocolMessage(buf.Bytes(), "2", version), nil
}

func decodeSignRound3Input(m *protocol.Message) (*sign.SignRound2Output, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := &sign.SignRound2Output{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeSignRound3Output(output *sign.SignRound3Output, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(output); err != nil {
		return nil, errors.WithStack(err)
	}
	return newSignProtocolMessage(buf.Bytes(), "3", version), nil
}

func decodeSignRound4Input(m *protocol.Message) (*sign.SignRound3Output, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := &sign.SignRound3Output{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeSignature(signature *curves.EcdsaSignature, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(signature); err != nil {
		return nil, errors.WithStack(err)
	}
	return newSignProtocolMessage(buf.Bytes(), "signature", version), nil
}

// DecodeSignature serializes the signature.
func DecodeSignature(m *protocol.Message) (*curves.EcdsaSignature, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := &curves.EcdsaSignature{}
	if err := dec.Decode(decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}
