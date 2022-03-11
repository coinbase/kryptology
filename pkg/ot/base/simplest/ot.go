//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package simplest implements the "Verified Simplest OT", as defined in "protocol 7" of [DKLs18](https://eprint.iacr.org/2018/499.pdf).
// The original "Simplest OT" protocol is presented in [CC15](https://eprint.iacr.org/2015/267.pdf).
// In our implementation, we run OTs for multiple choice bits in parallel. Furthermore, as described in the DKLs paper,
// we implement this as Random OT protocol. We also add encryption and decryption steps as defined in the protocol, but
// emphasise that these steps are optional. Specifically, in the setting where this OT is used as the seed OT in an
// OT Extension protocol, the encryption and decryption steps are not needed.
//
// Limitation: currently we only support batch OTs that are multiples of 8.
//
// Ideal functionalities:
//  - We have used ZKP Schnorr for the F^{R_{DL}}_{ZK}
//  - We have used HMAC for realizing the Random Oracle Hash function, the key for HMAC is received as input to the protocol.
package simplest

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const (
	// keyCount is the number of encryption keys created. Since this is a 1-out-of-2 OT, the key count is set to 2.
	keyCount = 2

	// DigestSize is the length of hash. Similarly, when it comes to encrypting and decryption, it is the size of the
	// plaintext and ciphertext.
	DigestSize = 32
)

type (
	// OneTimePadDecryptionKey is the type of Rho^w, Rho^0, and RHo^1 in the paper.
	OneTimePadDecryptionKey = [DigestSize]byte

	// OneTimePadEncryptionKeys is the type of Rho^0, and RHo^1 in the paper.
	OneTimePadEncryptionKeys = [keyCount][DigestSize]byte

	// OtChallenge is the type of xi in the paper.
	OtChallenge = [DigestSize]byte

	// OtChallengeResponse is the type of Rho' in the paper.
	OtChallengeResponse = [DigestSize]byte

	// ChallengeOpening is the type of hashed Rho^0 and Rho^1
	ChallengeOpening = [keyCount][DigestSize]byte

	// ReceiversMaskedChoices corresponds to the "A" value in the paper in compressed format.
	ReceiversMaskedChoices = []byte
)

// SenderOutput are the outputs that the sender will obtain as a result of running the "random" OT protocol.
type SenderOutput struct {
	// OneTimePadEncryptionKeys are  Rho^0 and Rho^1, the output of the random OT.
	// These can be used to encrypt and send two messages to the receiver.
	// Therefore, for readability they are called OneTimePadEncryptionKeys  in the code.
	OneTimePadEncryptionKeys []OneTimePadEncryptionKeys
}

// ReceiverOutput are the outputs that the receiver will obtain as a result of running the "random" OT protocol.
type ReceiverOutput struct {
	// PackedRandomChoiceBits is a packed version of the choice vector, the packing is done for performance reasons.
	PackedRandomChoiceBits []byte

	// RandomChoiceBits is the choice vector represented as unpacked int array. Initialed from PackedRandomChoiceBits.
	RandomChoiceBits []int

	// OneTimePadDecryptionKey is Rho^w, the output of the random OT. For the receiver, there is just 1 output per execution.
	// This value will be used to decrypt one of the messages sent by the sender.
	// Therefore, for readability this is called OneTimePadDecryptionKey in the code.
	OneTimePadDecryptionKey []OneTimePadDecryptionKey
}

// Sender stores state for the "sender" role in OT. see Protocol 7 in Appendix A of DKLs18.
type Sender struct {
	// Output is the output that is produced as a result of running random OT protocol.
	Output *SenderOutput

	curve *curves.Curve

	// secretKey is the value `b` in the paper, which is the discrete log of B, which will be (re)used in _all_ executions of the OT.
	secretKey curves.Scalar

	// publicKey is the public key of the secretKey.
	publicKey curves.Point

	// batchSize is the number of parallel OTs.
	batchSize int

	transcript *merlin.Transcript
}

// Receiver stores state for the "receiver" role in OT. Protocol 7, Appendix A, of DKLs.
type Receiver struct {
	// Output is the output that is produced as a result of running random OT protocol.
	Output *ReceiverOutput

	curve *curves.Curve

	// senderPublicKey corresponds to "B" in the paper.
	senderPublicKey curves.Point

	// senderChallenge is "xi" in the protocol.
	senderChallenge []OtChallenge

	// batchSize is the number of parallel OTs.
	batchSize int

	transcript *merlin.Transcript
}

// NewSender creates a new "sender" object, ready to participate in a _random_ verified simplest OT in the role of the sender.
// no messages are specified by the sender, because random ones will be sent (hence the random OT).
// ultimately, the `Sender`'s `Output` field will be appropriately populated.
// you can use it directly, or alternatively bootstrap it into an _actual_ (non-random) OT using `Round7Encrypt` below
func NewSender(curve *curves.Curve, batchSize int, uniqueSessionId [DigestSize]byte) (*Sender, error) {
	if batchSize&0x07 != 0 { // This is the same as `batchSize % 8 != 0`, but is constant time
		return nil, errors.New("batch size should be a multiple of 8")
	}
	transcript := merlin.NewTranscript("Coinbase_DKLs_SeedOT")
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])
	return &Sender{
		Output:     &SenderOutput{},
		curve:      curve,
		batchSize:  batchSize,
		transcript: transcript,
	}, nil
}

// NewReceiver is a Random OT receiver. Therefore, the choice bits are created randomly.
// The choice bits are stored in a packed format (e.g., each choice is a single bit in a byte array).
func NewReceiver(curve *curves.Curve, batchSize int, uniqueSessionId [DigestSize]byte) (*Receiver, error) {
	// This is the same as `batchSize % 8 != 0`, but is constant time
	if batchSize&0x07 != 0 {
		return nil, errors.New("batch size should be a multiple of 8")
	}

	transcript := merlin.NewTranscript("Coinbase_DKLs_SeedOT")
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])

	receiver := &Receiver{
		Output:     &ReceiverOutput{},
		curve:      curve,
		batchSize:  batchSize,
		transcript: transcript,
	}
	batchSizeBytes := batchSize >> 3 // divide by 8
	receiver.Output.PackedRandomChoiceBits = make([]byte, batchSizeBytes)
	if _, err := rand.Read(receiver.Output.PackedRandomChoiceBits[:]); err != nil {
		return nil, errors.Wrap(err, "choosing random choice bits")
	}
	// Unpack into Choice bits
	receiver.initChoice()
	return receiver, nil
}

// Round1ComputeAndZkpToPublicKey is the first phase of the protocol.
// computes and stores public key and returns the schnorr proof. serialized / packed.
// This implements step 1 of Protocol 7 of DKLs18, page 16.
func (sender *Sender) Round1ComputeAndZkpToPublicKey() (*schnorr.Proof, error) {
	var err error
	// Sample the secret key and compute the public key.
	sender.secretKey = sender.curve.Scalar.Random(rand.Reader)
	sender.publicKey = sender.curve.ScalarBaseMult(sender.secretKey)

	// Generate the ZKP proof.
	uniqueSessionId := [DigestSize]byte{}
	copy(uniqueSessionId[:], sender.transcript.ExtractBytes([]byte("sender schnorr proof"), DigestSize))
	prover := schnorr.NewProver(sender.curve, nil, uniqueSessionId[:])
	proof, err := prover.Prove(sender.secretKey)
	if err != nil {
		return nil, errors.Wrap(err, "creating zkp proof for secret key in seed OT sender round 1")
	}
	return proof, nil
}

// Round2VerifySchnorrAndPadTransfer verifies the schnorr proof of the public key sent by the sender, i.e., step 2),
// and then does receiver's "Pad Transfer" phase in OT, i.e., step 3), of Protocol 7 (page 16) of the paper.
func (receiver *Receiver) Round2VerifySchnorrAndPadTransfer(proof *schnorr.Proof) ([]ReceiversMaskedChoices, error) {
	receiver.senderPublicKey = proof.Statement
	uniqueSessionId := [DigestSize]byte{}
	copy(uniqueSessionId[:], receiver.transcript.ExtractBytes([]byte("sender schnorr proof"), DigestSize))
	if err := schnorr.Verify(proof, receiver.curve, nil, uniqueSessionId[:]); err != nil {
		return nil, errors.Wrap(err, "verifying schnorr proof in seed OT receiver round 2")
	}

	result := make([]ReceiversMaskedChoices, receiver.batchSize)
	receiver.Output.OneTimePadDecryptionKey = make([]OneTimePadDecryptionKey, receiver.batchSize)
	copy(uniqueSessionId[:], receiver.transcript.ExtractBytes([]byte("random oracle salts"), DigestSize))
	for i := 0; i < receiver.batchSize; i++ {
		a := receiver.curve.Scalar.Random(rand.Reader)
		// Computing `A := a . G + w . B` in constant time, by first computing option0 = a.G and option1 = a.G+B and then
		// constant time choosing one of them by first assuming that the output is option0, and overwrite it if the choice bit is 1.

		option0 := receiver.curve.ScalarBaseMult(a)
		option0Bytes := option0.ToAffineCompressed()
		option1 := option0.Add(receiver.senderPublicKey)
		option1Bytes := option1.ToAffineCompressed()

		result[i] = option0Bytes
		subtle.ConstantTimeCopy(receiver.Output.RandomChoiceBits[i], result[i], option1Bytes)
		// compute the internal rho
		rho := receiver.senderPublicKey.Mul(a)
		hash := sha3.New256()
		if _, err := hash.Write(uniqueSessionId[:]); err != nil {
			return nil, errors.Wrap(err, "writing seed to hash in round 2 pad transfer")
		}
		if _, err := hash.Write([]byte{byte(i)}); err != nil {
			return nil, errors.Wrap(err, "writing i to hash in round 2 pad transfer")
		}
		if _, err := hash.Write(rho.ToAffineCompressed()); err != nil {
			return nil, errors.Wrap(err, "writing point to hash in round 2 pad transfer")
		}
		copy(receiver.Output.OneTimePadDecryptionKey[i][:], hash.Sum(nil))
	}
	return result, nil
}

// Round3PadTransfer is the sender's "Pad Transfer" phase in OT; see steps 4 and 5 of page 16 of the paper.
// Returns the challenges xi
func (sender *Sender) Round3PadTransfer(compressedReceiversMaskedChoice []ReceiversMaskedChoices) ([]OtChallenge, error) {
	var err error
	challenge := make([]OtChallenge, sender.batchSize)
	sender.Output.OneTimePadEncryptionKeys = make([]OneTimePadEncryptionKeys, sender.batchSize)
	negSenderPublicKey := sender.publicKey.Neg()

	receiversMaskedChoice := make([]curves.Point, len(compressedReceiversMaskedChoice))
	for i := 0; i < len(compressedReceiversMaskedChoice); i++ {

		if receiversMaskedChoice[i], err = sender.curve.Point.FromAffineCompressed(compressedReceiversMaskedChoice[i]); err != nil {
			return nil, errors.Wrap(err, "uncompress the point")
		}
	}

	baseEncryptionKeyMaterial := make([]curves.Point, keyCount)
	var hashedKey [keyCount][DigestSize]byte
	uniqueSessionId := [DigestSize]byte{}
	copy(uniqueSessionId[:], sender.transcript.ExtractBytes([]byte("random oracle salts"), DigestSize))

	for i := 0; i < sender.batchSize; i++ {
		// Sender creates two options that will eventually be used as her encryption keys.
		// `baseEncryptionKeyMaterial[0]` and `baseEncryptionKeyMaterial[0]` correspond to rho_0 and rho_1 in the paper, respectively.
		baseEncryptionKeyMaterial[0] = receiversMaskedChoice[i].Mul(sender.secretKey)

		receiverChoiceMinusSenderPublicKey := receiversMaskedChoice[i].Add(negSenderPublicKey)
		baseEncryptionKeyMaterial[1] = receiverChoiceMinusSenderPublicKey.Mul(sender.secretKey)

		for k := 0; k < keyCount; k++ {
			hash := sha3.New256()
			if _, err = hash.Write(uniqueSessionId[:]); err != nil {
				return nil, errors.Wrap(err, "writing seed to hash in round 3 pad transfer")
			}
			if _, err = hash.Write([]byte{byte(i)}); err != nil {
				return nil, errors.Wrap(err, "writing i to hash in round 3 pad transfer")
			}
			if _, err = hash.Write(baseEncryptionKeyMaterial[k].ToAffineCompressed()); err != nil {
				return nil, errors.Wrap(err, "writing point to hash in round 3 pad transfer")
			}
			copy(sender.Output.OneTimePadEncryptionKeys[i][k][:], hash.Sum(nil))
			if err != nil {
				return nil, errors.Wrap(err, "compute the encryption keys")
			}

			// Compute a challenge by XORing the hash of the hash of the key. Not a typo ;)
			hashedKey[k] = sha3.Sum256(sender.Output.OneTimePadEncryptionKeys[i][k][:])
			hashedKey[k] = sha3.Sum256(hashedKey[k][:])
		}

		challenge[i] = xorBytes(hashedKey[0], hashedKey[1])
	}
	return challenge, nil
}

// Round4RespondToChallenge corresponds to initial round of the receiver's "Verify" phase; see step 6 of page 16 of the paper.
// this is just the start of Verification. In this round, the receiver outputs "rho'", which the sender will check.
func (receiver *Receiver) Round4RespondToChallenge(challenge []OtChallenge) ([]OtChallengeResponse, error) {
	// store to be used in future steps
	receiver.senderChallenge = challenge
	// challengeResponses is Rho' in the paper.
	challengeResponses := make([]OtChallengeResponse, receiver.batchSize)
	for i := 0; i < receiver.batchSize; i++ {
		// Constant-time xor of the hashed key and the challenge, based on the choice bit.
		hashedKey := sha3.Sum256(receiver.Output.OneTimePadDecryptionKey[i][:])
		hashedKey = sha3.Sum256(hashedKey[:])
		challengeResponses[i] = hashedKey
		alternativeChallengeResponse := xorBytes(receiver.senderChallenge[i], hashedKey)
		subtle.ConstantTimeCopy(receiver.Output.RandomChoiceBits[i], challengeResponses[i][:], alternativeChallengeResponse[:])
	}
	return challengeResponses, nil
}

// Round5Verify verifies the challenge response. If the verification passes, sender opens his challenges to the receiver.
// See step 7 of page 16 of the paper.
// Abort if Rho' != H(H(Rho^0)) in other words, if challengeResponse != H(H(encryption key 0)).
// opening is H(encryption key)
func (sender *Sender) Round5Verify(challengeResponses []OtChallengeResponse) ([]ChallengeOpening, error) {
	opening := make([]ChallengeOpening, sender.batchSize)
	for i := 0; i < sender.batchSize; i++ {
		for k := 0; k < keyCount; k++ {
			opening[i][k] = sha3.Sum256(sender.Output.OneTimePadEncryptionKeys[i][k][:])
		}

		// Verify
		hashedKey0 := sha3.Sum256(opening[i][0][:])
		if subtle.ConstantTimeCompare(hashedKey0[:], challengeResponses[i][:]) != 1 {
			return nil, errors.New("receiver's challenge response didn't match H(H(rho^0))")
		}
	}
	return opening, nil
}

// Round6Verify is the _last_ part of the "Verification" phase of OT; see p. 16 of https://eprint.iacr.org/2018/499.pdf.
// See step 8 of page 16 of the paper.
// Abort if H(Rho^w) != the one it calculated itself or
//       if Xi != H(H(Rho^0)) XOR H(H(Rho^1))
// In other words,
//       if opening_w != H(decryption key)  or
//       if challenge != H(opening 0) XOR H(opening 0)
func (receiver *Receiver) Round6Verify(challengeOpenings []ChallengeOpening) error {
	for i := 0; i < receiver.batchSize; i++ {
		hashedDecryptionKey := sha3.Sum256(receiver.Output.OneTimePadDecryptionKey[i][:])
		w := receiver.Output.RandomChoiceBits[i]
		if subtle.ConstantTimeCompare(hashedDecryptionKey[:], challengeOpenings[i][w][:]) != 1 {
			return fmt.Errorf("sender's supposed H(rho^omega) doesn't match our own")
		}
		hashedKey0 := sha3.Sum256(challengeOpenings[i][0][:])
		hashedKey1 := sha3.Sum256(challengeOpenings[i][1][:])
		reconstructedChallenge := xorBytes(hashedKey0, hashedKey1)
		if subtle.ConstantTimeCompare(reconstructedChallenge[:], receiver.senderChallenge[i][:]) != 1 {
			return fmt.Errorf("sender's openings H(rho^0) and H(rho^1) didn't decommit to its prior message")
		}
	}
	return nil
}

// Round7Encrypt wraps an `Encrypt` operation on the Sender's underlying output from the random OT; see `Encrypt` below.
// this is optional; it will be used only in circumstances when you want to run "actual" (i.e., non-random) OT
func (sender *Sender) Round7Encrypt(messages [][keyCount][DigestSize]byte) ([][keyCount][DigestSize]byte, error) {
	return sender.Output.Encrypt(messages)
}

// Round8Decrypt wraps a `Decrypt` operation on the Receiver's underlying output from the random OT; see `Decrypt` below
// this is optional; it will be used only in circumstances when you want to run "actual" (i.e., non-random) OT
func (receiver *Receiver) Round8Decrypt(ciphertext [][keyCount][DigestSize]byte) ([][DigestSize]byte, error) {
	return receiver.Output.Decrypt(ciphertext)
}

// Encrypt runs step 9) of the seed OT Protocol 7) of https://eprint.iacr.org/2018/499.pdf,
// in which the seed OT sender "encrypts" both messages under the "one-time keys" output by the random OT.
func (s *SenderOutput) Encrypt(plaintexts [][keyCount][DigestSize]byte) ([][keyCount][DigestSize]byte, error) {
	batchSize := len(s.OneTimePadEncryptionKeys)
	if len(plaintexts) != batchSize {
		return nil, errors.New("message size should be same as batch size")
	}
	ciphertexts := make([][keyCount][DigestSize]byte, batchSize)

	for i := 0; i < len(plaintexts); i++ {
		for k := 0; k < keyCount; k++ {
			ciphertexts[i][k] = xorBytes(s.OneTimePadEncryptionKeys[i][k], plaintexts[i][k])
		}
	}
	return ciphertexts, nil
}

// Decrypt is step 10) of the seed OT Protocol 7) of https://eprint.iacr.org/2018/499.pdf,
// where the seed OT receiver "decrypts" the message it's receiving using the "key" it received in the random OT.
func (r *ReceiverOutput) Decrypt(ciphertexts [][keyCount][DigestSize]byte) ([][DigestSize]byte, error) {
	batchSize := len(r.OneTimePadDecryptionKey)
	if len(ciphertexts) != batchSize {
		return nil, errors.New("number of ciphertexts should be same as batch size")
	}
	plaintexts := make([][DigestSize]byte, batchSize)

	for i := 0; i < len(ciphertexts); i++ {
		choice := r.RandomChoiceBits[i]
		plaintexts[i] = xorBytes(r.OneTimePadDecryptionKey[i], ciphertexts[i][choice])
	}
	return plaintexts, nil
}
