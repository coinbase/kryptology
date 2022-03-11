//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package sign implements the 2-2 threshold signature protocol of [DKLs18](https://eprint.iacr.org/2018/499.pdf).
// The signing protocol is defined in "Protocol 4" page 9, of the paper. The Zero Knowledge Proof ideal functionalities are
// realized using schnorr proofs.
package sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/coinbase/kryptology/pkg/zkp/schnorr"
)

const multiplicationCount = 2

// Alice struct encoding Alice's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Alice will not possess the signature.
type Alice struct {
	hash           hash.Hash // which hash function should we use to compute message (i.e, teh digest)
	seedOtResults  *simplest.ReceiverOutput
	secretKeyShare curves.Scalar // the witness
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// Bob struct encoding Bob's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Bob will obtain the signature.
type Bob struct {
	// Signature is the resulting digital signature and is the output of this protocol.
	Signature *curves.EcdsaSignature

	hash           hash.Hash // which hash function should we use to compute message
	seedOtResults  *simplest.SenderOutput
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	transcript     *merlin.Transcript
	// multiplyReceivers are 2 receivers that are used to perform the two multiplications needed:
	// 1. (phi + 1/kA) * (1/kB)
	// 2. skA/KA * skB/kB
	multiplyReceivers [multiplicationCount]*MultiplyReceiver
	kB                curves.Scalar
	dB                curves.Point
	curve             *curves.Curve
}

// NewAlice creates a party that can participate in protocol runs of DKLs sign, in the role of Alice.
func NewAlice(curve *curves.Curve, hash hash.Hash, dkgOutput *dkg.AliceOutput) *Alice {
	return &Alice{
		hash:           hash,
		seedOtResults:  dkgOutput.SeedOtResult,
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("Coinbase_DKLs_Sign"),
	}
}

// NewBob creates a party that can participate in protocol runs of DKLs sign, in the role of Bob.
// This party receives the signature at the end.
func NewBob(curve *curves.Curve, hash hash.Hash, dkgOutput *dkg.BobOutput) *Bob {
	return &Bob{
		hash:           hash,
		seedOtResults:  dkgOutput.SeedOtResult,
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("Coinbase_DKLs_Sign"),
	}
}

// SignRound2Output is the output of the 3rd round of the protocol.
type SignRound2Output struct {
	// KosRound1Outputs is the output of the first round of OT Extension, stored for future rounds.
	KosRound1Outputs [multiplicationCount]*kos.Round1Output

	// DB is D_{B} = k_{B} . G from the paper.
	DB curves.Point

	// Seed is the random value used to derive the joint unique session id.
	Seed [simplest.DigestSize]byte
}

// SignRound3Output is the output of the 3rd round of the protocol.
type SignRound3Output struct {
	// MultiplyRound2Outputs is the output of the second round of multiply sub-protocol. Stored to use in future rounds.
	MultiplyRound2Outputs [multiplicationCount]*MultiplyRound2Output

	// RSchnorrProof is ZKP for the value R = k_{A} . D_{B} from the paper.
	RSchnorrProof *schnorr.Proof

	// RPrime is R' = k'_{A} . D_{B} from the paper.
	RPrime curves.Point

	// EtaPhi is the Eta_{Phi} from the paper.
	EtaPhi curves.Scalar

	// EtaSig is the Eta_{Sig} from the paper.
	EtaSig curves.Scalar
}

// Round1GenerateRandomSeed first step of the generation of the shared random salt `idExt`
// in this round, Alice flips 32 random bytes and sends them to Bob.
// Note that this is not _explicitly_ given as part of the protocol in https://eprint.iacr.org/2018/499.pdf, Protocol 1).
// Rather, it is part of our generation of `idExt`, the shared random salt which both parties must use in cOT.
// This value introduced in Protocol 9), very top of page 16. it is not indicated how it should be derived.
// We do it by having each party sample 32 bytes, then by appending _both_ as salts. Secure if either party is honest
func (alice *Alice) Round1GenerateRandomSeed() ([simplest.DigestSize]byte, error) {
	aliceSeed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(aliceSeed[:]); err != nil {
		return [simplest.DigestSize]byte{}, errors.Wrap(err, "generating random bytes in alice round 1 generate")
	}
	alice.transcript.AppendMessage([]byte("session_id_alice"), aliceSeed[:])
	return aliceSeed, nil
}

// Round2Initialize Bob's initial message, which kicks off the signature process. Protocol 1, Bob's steps 1) - 3).
// Bob's work here entails beginning the Diffie–Hellman-like construction of the instance key / nonce,
// as well as preparing the inputs which he will feed into the multiplication protocol,
// and moreover actually initiating the (first respective messages of) the multiplication protocol using these inputs.
// This latter step in turn amounts to sending the initial message in a new cOT extension.
// All the resulting data gets packaged and sent to Alice.
func (bob *Bob) Round2Initialize(aliceSeed [simplest.DigestSize]byte) (*SignRound2Output, error) {
	bobSeed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(bobSeed[:]); err != nil {
		return nil, errors.Wrap(err, "flipping random coins in bob round 2 initialize")
	}
	bob.transcript.AppendMessage([]byte("session_id_alice"), aliceSeed[:])
	bob.transcript.AppendMessage([]byte("session_id_bob"), bobSeed[:])

	var err error
	uniqueSessionId := [simplest.DigestSize]byte{} // will use and _re-use_ this throughout, for sub-session IDs
	copy(uniqueSessionId[:], bob.transcript.ExtractBytes([]byte("multiply receiver id 0"), simplest.DigestSize))
	bob.multiplyReceivers[0], err = NewMultiplyReceiver(bob.seedOtResults, bob.curve, uniqueSessionId)
	if err != nil {
		return nil, errors.Wrap(err, "error creating multiply receiver 0 in Bob sign round 3")
	}
	copy(uniqueSessionId[:], bob.transcript.ExtractBytes([]byte("multiply receiver id 1"), simplest.DigestSize))
	bob.multiplyReceivers[1], err = NewMultiplyReceiver(bob.seedOtResults, bob.curve, uniqueSessionId)
	if err != nil {
		return nil, errors.Wrap(err, "error creating multiply receiver 1 in Bob sign round 3")
	}
	round2Output := &SignRound2Output{
		Seed: bobSeed,
	}
	bob.kB = bob.curve.Scalar.Random(rand.Reader)
	bob.dB = bob.curve.ScalarBaseMult(bob.kB)
	round2Output.DB = bob.dB
	kBInv := bob.curve.Scalar.One().Div(bob.kB)

	round2Output.KosRound1Outputs[0], err = bob.multiplyReceivers[0].Round1Initialize(kBInv)
	if err != nil {
		return nil, errors.Wrap(err, "error in multiply round 1 initialize 0 within Bob sign round 3 initialize")
	}
	round2Output.KosRound1Outputs[1], err = bob.multiplyReceivers[1].Round1Initialize(bob.secretKeyShare.Mul(kBInv))
	if err != nil {
		return nil, errors.Wrap(err, "error in multiply round 1 initialize 1 within Bob sign round 3 initialize")
	}
	return round2Output, nil
}

// Round3Sign Alice's first message. Alice is the _responder_; she is responding to Bob's initial message.
// This is Protocol 1 (p. 6), and contains Alice's steps 3) -- 8). these can all be combined into one message.
// Alice's job here is to finish computing the shared instance key / nonce, as well as multiplication input values;
// then to invoke the multiplication on these two input values (stashing the outputs in her running result struct),
// then to use the _output_ of the multiplication (which she already possesses as of the end of her computation),
// and use that to compute some final values which will help Bob compute the final signature.
func (alice *Alice) Round3Sign(message []byte, round2Output *SignRound2Output) (*SignRound3Output, error) {
	alice.transcript.AppendMessage([]byte("session_id_bob"), round2Output.Seed[:])

	multiplySenders := [multiplicationCount]*MultiplySender{}
	var err error
	uniqueSessionId := [simplest.DigestSize]byte{} // will use and _re-use_ this throughout, for sub-session IDs
	copy(uniqueSessionId[:], alice.transcript.ExtractBytes([]byte("multiply receiver id 0"), simplest.DigestSize))
	if multiplySenders[0], err = NewMultiplySender(alice.seedOtResults, alice.curve, uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "creating multiply sender 0 in Alice round 4 sign")
	}
	copy(uniqueSessionId[:], alice.transcript.ExtractBytes([]byte("multiply receiver id 1"), simplest.DigestSize))
	if multiplySenders[1], err = NewMultiplySender(alice.seedOtResults, alice.curve, uniqueSessionId); err != nil {
		return nil, errors.Wrap(err, "creating multiply sender 1 in Alice round 4 sign")
	}
	round3Output := &SignRound3Output{}
	kPrimeA := alice.curve.Scalar.Random(rand.Reader)
	round3Output.RPrime = round2Output.DB.Mul(kPrimeA)
	hashRPrimeBytes := sha3.Sum256(round3Output.RPrime.ToAffineCompressed())
	hashRPrime, err := alice.curve.Scalar.SetBytes(hashRPrimeBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "setting hashRPrime scalar from bytes")
	}
	kA := hashRPrime.Add(kPrimeA)
	copy(uniqueSessionId[:], alice.transcript.ExtractBytes([]byte("schnorr proof for R"), simplest.DigestSize))
	rSchnorrProver := schnorr.NewProver(alice.curve, round2Output.DB, uniqueSessionId[:])
	round3Output.RSchnorrProof, err = rSchnorrProver.Prove(kA)
	if err != nil {
		return nil, errors.Wrap(err, "generating schnorr proof for R = kA * DB in alice round 4 sign")
	}
	// reassign / stash the below value here just for notational clarity.
	// this is _the_ key public point R in the ECDSA signature. we'll use its coordinate X in various places.
	r := round3Output.RSchnorrProof.Statement
	phi := alice.curve.Scalar.Random(rand.Reader)
	kAInv := alice.curve.Scalar.One().Div(kA)

	if round3Output.MultiplyRound2Outputs[0], err = multiplySenders[0].Round2Multiply(phi.Add(kAInv), round2Output.KosRound1Outputs[0]); err != nil {
		return nil, errors.Wrap(err, "error in round 2 multiply 0 within alice round 4 sign")
	}
	if round3Output.MultiplyRound2Outputs[1], err = multiplySenders[1].Round2Multiply(alice.secretKeyShare.Mul(kAInv), round2Output.KosRound1Outputs[1]); err != nil {
		return nil, errors.Wrap(err, "error in round 2 multiply 1 within alice round 4 sign")
	}

	one := alice.curve.Scalar.One()
	gamma1 := alice.curve.ScalarBaseMult(kA.Mul(phi).Add(one))
	other := r.Mul(multiplySenders[0].outputAdditiveShare.Neg())
	gamma1 = gamma1.Add(other)
	hashGamma1Bytes := sha3.Sum256(gamma1.ToAffineCompressed())
	hashGamma1, err := alice.curve.Scalar.SetBytes(hashGamma1Bytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "setting hashGamma1 scalar from bytes")
	}
	round3Output.EtaPhi = hashGamma1.Add(phi)
	if _, err = alice.hash.Write(message); err != nil {
		return nil, errors.Wrap(err, "writing message to hash in alice round 4 sign")
	}
	digest := alice.hash.Sum(nil)
	hOfMAsInteger, err := alice.curve.Scalar.SetBytes(digest)
	if err != nil {
		return nil, errors.Wrap(err, "setting hOfMAsInteger scalar from bytes")
	}
	affineCompressedForm := r.ToAffineCompressed()
	if len(affineCompressedForm) != 33 {
		return nil, errors.New("the compressed form must be exactly 33 bytes")
	}
	// Discard the leading byte and parse the rest as the X coordinate.
	rX, err := alice.curve.Scalar.SetBytes(affineCompressedForm[1:])
	if err != nil {
		return nil, errors.Wrap(err, "setting rX scalar from bytes")
	}

	sigA := hOfMAsInteger.Mul(multiplySenders[0].outputAdditiveShare).Add(rX.Mul(multiplySenders[1].outputAdditiveShare))
	gamma2 := alice.publicKey.Mul(multiplySenders[0].outputAdditiveShare)
	other = alice.curve.ScalarBaseMult(multiplySenders[1].outputAdditiveShare.Neg())
	gamma2 = gamma2.Add(other)
	hashGamma2Bytes := sha3.Sum256(gamma2.ToAffineCompressed())
	hashGamma2, err := alice.curve.Scalar.SetBytes(hashGamma2Bytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "setting hashGamma2 scalar from bytes")
	}
	round3Output.EtaSig = hashGamma2.Add(sigA)
	return round3Output, nil
}

// Round4Final this is Bob's last portion of the signature computation, and ultimately results in the complete signature
// corresponds to Protocol 1, Bob's steps 3) -- 10).
// Bob begins by _finishing_ the OT-based multiplication, using Alice's one and only message to him re: the mult.
// Bob then move's onto the remainder of Alice's message, which contains extraneous data used to finish the signature.
// Using this data, Bob completes the signature, which gets stored in `Bob.Sig`. Bob also verifies it.
func (bob *Bob) Round4Final(message []byte, round3Output *SignRound3Output) error {
	if err := bob.multiplyReceivers[0].Round3Multiply(round3Output.MultiplyRound2Outputs[0]); err != nil {
		return errors.Wrap(err, "error in round 3 multiply 0 within sign round 5")
	}
	if err := bob.multiplyReceivers[1].Round3Multiply(round3Output.MultiplyRound2Outputs[1]); err != nil {
		return errors.Wrap(err, "error in round 3 multiply 1 within sign round 5")
	}
	rPrimeHashedBytes := sha3.Sum256(round3Output.RPrime.ToAffineCompressed())
	rPrimeHashed, err := bob.curve.Scalar.SetBytes(rPrimeHashedBytes[:])
	if err != nil {
		return errors.Wrap(err, "setting rPrimeHashed scalar from bytes")
	}
	r := bob.dB.Mul(rPrimeHashed)
	r = r.Add(round3Output.RPrime)
	// To ensure that the correct public statement is used, we use the public statement that we have calculated
	// instead of the open Alice sent us.
	round3Output.RSchnorrProof.Statement = r
	uniqueSessionId := [simplest.DigestSize]byte{}
	copy(uniqueSessionId[:], bob.transcript.ExtractBytes([]byte("schnorr proof for R"), simplest.DigestSize))
	if err = schnorr.Verify(round3Output.RSchnorrProof, bob.curve, bob.dB, uniqueSessionId[:]); err != nil {
		return errors.Wrap(err, "bob's verification of alice's schnorr proof re: r failed")
	}
	zero := bob.curve.Scalar.Zero()
	affineCompressedForm := r.ToAffineCompressed()
	if len(affineCompressedForm) != 33 {
		return errors.New("the compressed form must be exactly 33 bytes")
	}
	rY := affineCompressedForm[0] & 0x1 // this is bit(0) of Y coordinate
	rX, err := bob.curve.Scalar.SetBytes(affineCompressedForm[1:])
	if err != nil {
		return errors.Wrap(err, "setting rX scalar from bytes")
	}
	bob.Signature = &curves.EcdsaSignature{
		R: rX.Add(zero).BigInt(), // slight trick here; add it to 0 just to mod it by q (now it's mod p!)
		V: int(rY),
	}
	gamma1 := r.Mul(bob.multiplyReceivers[0].outputAdditiveShare)
	gamma1HashedBytes := sha3.Sum256(gamma1.ToAffineCompressed())
	gamma1Hashed, err := bob.curve.Scalar.SetBytes(gamma1HashedBytes[:])
	if err != nil {
		return errors.Wrap(err, "setting gamma1Hashed scalar from bytes")
	}
	phi := round3Output.EtaPhi.Sub(gamma1Hashed)
	theta := bob.multiplyReceivers[0].outputAdditiveShare.Sub(phi.Div(bob.kB))
	if _, err = bob.hash.Write(message); err != nil {
		return errors.Wrap(err, "writing message to hash in Bob sign round 5 final")
	}
	digestBytes := bob.hash.Sum(nil)
	digest, err := bob.curve.Scalar.SetBytes(digestBytes)
	if err != nil {
		return errors.Wrap(err, "setting digest scalar from bytes")
	}
	capitalR, err := bob.curve.Scalar.SetBigInt(bob.Signature.R)
	if err != nil {
		return errors.Wrap(err, "setting capitalR scalar from big int")
	}
	sigB := digest.Mul(theta).Add(capitalR.Mul(bob.multiplyReceivers[1].outputAdditiveShare))
	gamma2 := bob.curve.ScalarBaseMult(bob.multiplyReceivers[1].outputAdditiveShare)
	other := bob.publicKey.Mul(theta.Neg())
	gamma2 = gamma2.Add(other)
	gamma2HashedBytes := sha3.Sum256(gamma2.ToAffineCompressed())
	gamma2Hashed, err := bob.curve.Scalar.SetBytes(gamma2HashedBytes[:])
	if err != nil {
		return errors.Wrap(err, "setting gamma2Hashed scalar from bytes")
	}
	scalarS := sigB.Add(round3Output.EtaSig.Sub(gamma2Hashed))
	bob.Signature.S = scalarS.BigInt()
	if bob.Signature.S.Bit(255) == 1 {
		bob.Signature.S = scalarS.Neg().BigInt()
		bob.Signature.V ^= 1
	}
	// now verify the signature
	unCompressedAffinePublicKey := bob.publicKey.ToAffineUncompressed()
	if len(unCompressedAffinePublicKey) != 65 {
		return errors.New("the uncompressed form must have exactly 65 bytes")
	}
	x := new(big.Int).SetBytes(unCompressedAffinePublicKey[1:33])
	y := new(big.Int).SetBytes(unCompressedAffinePublicKey[33:])
	ellipticCurve, err := bob.curve.ToEllipticCurve()
	if err != nil {
		return errors.Wrap(err, "invalid curve")
	}
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: ellipticCurve, X: x, Y: y}, digestBytes, bob.Signature.R, bob.Signature.S) {
		return fmt.Errorf("final signature failed to verify")
	}
	return nil
}
