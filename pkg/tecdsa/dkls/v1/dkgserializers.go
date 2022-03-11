package v1

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/protocol"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	v0 "github.com/coinbase/kryptology/pkg/tecdsa/dkls/v0"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const payloadKey = "direct"

func newDkgProtocolMessage(payload []byte, round string, version uint) *protocol.Message {
	return &protocol.Message{
		Protocol: protocol.Dkls18Dkg,
		Version:  version,
		Payloads: map[string][]byte{payloadKey: payload},
		Metadata: map[string]string{"round": round},
	}
}

func registerTypes() {
	gob.Register(&curves.ScalarK256{})
	gob.Register(&curves.PointK256{})
	gob.Register(&curves.ScalarP256{})
	gob.Register(&curves.PointP256{})
}

func encodeDkgRound1Output(commitment [32]byte, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	registerTypes()
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(&commitment); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "1", version), nil
}

func decodeDkgRound2Input(m *protocol.Message) ([32]byte, error) {
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

func encodeDkgRound2Output(output *dkg.Round2Output, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(output); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "2", version), nil
}

func decodeDkgRound3Input(m *protocol.Message) (*dkg.Round2Output, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(dkg.Round2Output)
	if err := dec.Decode(decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeDkgRound3Output(proof *schnorr.Proof, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(proof); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "3", version), nil
}

func decodeDkgRound4Input(m *protocol.Message) (*schnorr.Proof, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(schnorr.Proof)
	if err := dec.Decode(decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeDkgRound4Output(proof *schnorr.Proof, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(proof); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "4", version), nil
}

func decodeDkgRound5Input(m *protocol.Message) (*schnorr.Proof, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(schnorr.Proof)
	if err := dec.Decode(decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeDkgRound5Output(proof *schnorr.Proof, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(proof); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "5", version), nil
}

func decodeDkgRound6Input(m *protocol.Message) (*schnorr.Proof, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(schnorr.Proof)
	if err := dec.Decode(decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeDkgRound6Output(choices []simplest.ReceiversMaskedChoices, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(choices); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "6", version), nil
}

func decodeDkgRound7Input(m *protocol.Message) ([]simplest.ReceiversMaskedChoices, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.ReceiversMaskedChoices{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeDkgRound7Output(challenge []simplest.OtChallenge, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(challenge); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "7", version), nil
}

func decodeDkgRound8Input(m *protocol.Message) ([]simplest.OtChallenge, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.OtChallenge{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeDkgRound8Output(responses []simplest.OtChallengeResponse, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(responses); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "8", version), nil
}

func decodeDkgRound9Input(m *protocol.Message) ([]simplest.OtChallengeResponse, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.OtChallengeResponse{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

func encodeDkgRound9Output(opening []simplest.ChallengeOpening, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(opening); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "9", version), nil
}

func decodeDkgRound10Input(m *protocol.Message) ([]simplest.ChallengeOpening, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := []simplest.ChallengeOpening{}
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

// EncodeAliceDkgOutput serializes Alice DKG output based on the protocol version.
func EncodeAliceDkgOutput(result *dkg.AliceOutput, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	registerTypes()
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(result); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "alice-output", version), nil
}

// DecodeAliceDkgResult deserializes Alice DKG output.
func DecodeAliceDkgResult(m *protocol.Message) (*dkg.AliceOutput, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
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

// EncodeBobDkgOutput serializes Bob DKG output based on the protocol version.
func EncodeBobDkgOutput(result *dkg.BobOutput, version uint) (*protocol.Message, error) {
	if version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	registerTypes()
	buf := bytes.NewBuffer([]byte{})
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(result); err != nil {
		return nil, errors.WithStack(err)
	}
	return newDkgProtocolMessage(buf.Bytes(), "bob-output", version), nil
}

// DecodeBobDkgResult deserializes Bob DKG output.
func DecodeBobDkgResult(m *protocol.Message) (*dkg.BobOutput, error) {
	if m.Version != protocol.Version1 {
		return nil, errors.New("only version 1 is supported")
	}
	buf := bytes.NewBuffer(m.Payloads[payloadKey])
	dec := gob.NewDecoder(buf)
	decoded := new(dkg.BobOutput)
	if err := dec.Decode(&decoded); err != nil {
		return nil, errors.WithStack(err)
	}
	return decoded, nil
}

// ConvertAliceDkgOutputToV1 converts the V0 output to V1 output.
// The V0 version of DKls `gob` encoded entire `Alice` object and returned it as DKG state and returned this state and
// the public key to the caller as the serialized version of DKG.
// In contrast, the V1 version of DKLs `gob` encodes only what is need for signing algorithm. Therefore, this function
// first decodes the V0 dkg result to Alice object and a public key. Then extracts the required data out of the Alice
// object and creates V1 Dkg output object.
// Note that in addition to extracting the required data, this function also performs type conversions on curve Scalar
// and Points. The reason is that between V0 and V1, the interface and data types for curve computation has changed.
//
// Furthermore, the new encoded value is represented as a `protocol.Message` which contains versioning and other
// metadata about the serialized values. This serialized value will be the input to the sign function.
//
// In summary, the following data mapping and conversion is performed.
//   - v0.alice.Pk              -> Converted to v1.PublicKey (a curve Point)
//   - v0.alice.SkA             -> Converted to v1.SecretKeyShare (a scalar value)
//   - v0.alice.Receiver.Packed -> Converted to v1.SeedOtResult.PackedRandomChoiceBits (the random choice bits in OT)
//   - v0.alice.Receiver.Packed -> Converted to v1.SeedOtResult.RandomChoiceBits (the random choice bits in OT in unpacked form)
//   - v0.alice.Receiver.Rho    -> Converted to v1.SeedOtResult.OneTimePadDecryptionKey (the Rho value in the paper)
func ConvertAliceDkgOutputToV1(params *v0.Params, dkgResult []byte) (*protocol.Message, error) {
	alice, err := v0.DecodeAlice(params, dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var curve *curves.Curve
	if params.Curve.Params().Name == curves.K256Name {
		curve = curves.K256()
	} else if params.Curve.Params().Name == curves.P256Name {
		curve = curves.P256()
	} else {
		return nil, fmt.Errorf("unsupported curve %s", params.Curve.Params().Name)
	}

	publicKey, err := curve.Point.Set(alice.Pk.X, alice.Pk.Y)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	secretKey, err := curve.Scalar.SetBigInt(alice.SkA)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	packedChoiceBits := make([]byte, len(alice.Receiver.Packed))
	copy(packedChoiceBits, alice.Receiver.Packed[:])

	randomChoiceBits := make([]int, kos.Kappa)
	for i := 0; i < len(randomChoiceBits); i++ {
		randomChoiceBits[i] = int(simplest.ExtractBitFromByteVector(packedChoiceBits, i))
	}

	decryptionPads := make([]simplest.OneTimePadDecryptionKey, kos.Kappa)
	for i := 0; i < kos.Kappa; i++ {
		for j := 0; j < simplest.DigestSize; j++ {
			decryptionPads[i][j] = alice.Receiver.Rho[i][j]
		}
	}

	dkgConvertedResult := &dkg.AliceOutput{
		PublicKey:      publicKey,
		SecretKeyShare: secretKey,
		SeedOtResult: &simplest.ReceiverOutput{
			PackedRandomChoiceBits:  packedChoiceBits,
			RandomChoiceBits:        randomChoiceBits,
			OneTimePadDecryptionKey: decryptionPads,
		},
	}

	return EncodeAliceDkgOutput(dkgConvertedResult, protocol.Version1)
}

// ConvertBobDkgOutputToV1 converts the V0 output to V1 output.
// The V0 version of DKls `gob` encoded entire `Bob` object and returned it as DKG state and returned this state and
// the public key to the caller as the serialized version of DKG.
// In contrast, the V1 version of DKLs `gob` encodes only what is need for signing algorithm. Therefore, this function
// first decodes the V0 dkg result to Bob object and a public key. Then extracts the required data out of the Bob
// object and creates V1 Dkg output object.
// Note that in addition to extracting the required data, this function also performs type conversions on curve Scalar
// and Points. The reason is that between V0 and V1, the interface and data types for curve computation has changed.
//
// Furthermore, the new encoded value is represented as a `protocol.Message` which contains versioning and other
// metadata about the serialized values. This serialized value will be the input to the sign function.
//
// In summary, the following data mapping and conversion is performed.
//   - v0.bob.Pk         -> Converted to v1.PublicKey (a curve Point)
//   - v0.bob.SkA        -> Converted to v1.SecretKeyShare (a scalar value)
//   - v0.bob.Sender.Rho -> Converted to v1.SeedOtResult.OneTimePadEncryptionKeys (the Rho value in the paper)
func ConvertBobDkgOutputToV1(params *v0.Params, dkgResult []byte) (*protocol.Message, error) {
	bob, err := v0.DecodeBob(params, dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var curve *curves.Curve
	if params.Curve.Params().Name == curves.K256Name {
		curve = curves.K256()
	} else if params.Curve.Params().Name == curves.P256Name {
		curve = curves.P256()
	} else {
		return nil, fmt.Errorf("unsupported curve %s", params.Curve.Params().Name)
	}

	publicKey, err := curve.Point.Set(bob.Pk.X, bob.Pk.Y)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	secretKey, err := curve.Scalar.SetBigInt(bob.SkB)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	encryptionPads := make([]simplest.OneTimePadEncryptionKeys, kos.Kappa)
	for i := 0; i < kos.Kappa; i++ {
		for k := 0; k < 2; k++ { // simplest.keyCount
			for j := 0; j < simplest.DigestSize; j++ {
				encryptionPads[i][k][j] = bob.Sender.Rho[i][k][j]
			}
		}
	}

	dkgConvertedResult := &dkg.BobOutput{
		PublicKey:      publicKey,
		SecretKeyShare: secretKey,
		SeedOtResult: &simplest.SenderOutput{
			OneTimePadEncryptionKeys: encryptionPads,
		},
	}

	return EncodeBobDkgOutput(dkgConvertedResult, protocol.Version1)
}
