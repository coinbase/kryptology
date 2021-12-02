//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

// Alice struct encoding Alice's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Alice will NOT obtain the signature.
type Alice struct {
	PkA      *Schnorr // this is a "schnorr statement" for pkA.
	Receiver *seedOTReceiver
	SkA      *big.Int // the witness
	Pk       *curves.EcPoint

	// Note: unexported fields are marshaled during Encode
	params *Params
}

// Bob struct encoding Bob's state during one execution of the overall signing algorithm.
// At the end of the joint computation, Bob will obtain the signature.
type Bob struct {
	// Exported fields
	PkB    *Schnorr // this is a "schnorr statement" for pkB.
	Sender *seedOTSender
	SkB    *big.Int
	Pk     *curves.EcPoint
	Sig    *curves.EcdsaSignature // The resulting digital signature

	// Intermediate values and those used only during sign or DKG are not exported

	// Commitment to Alice's schnorr proof.
	params *Params
	// Only used during DKG so it's not persisted during encoding
	com []byte
	tB  *MultiplyReceiver // the receiver for additive shares of the multiplication.
	kB  *big.Int
	dB  *curves.EcPoint
}

// NewAlice creates a party that can participate in 2-of-2 DKG and threshold signature.
func NewAlice(params *Params) *Alice {
	return &Alice{
		params:   params,
		Receiver: &seedOTReceiver{params: params},
		PkA:      &Schnorr{params: params},
	}
}

// NewBob creates a party that can participate in 2-of-2 DKG and threshold signature. This party
// is the receiver of the signature at the end.
func NewBob(params *Params) *Bob {
	return &Bob{
		params: params,
		Sender: &seedOTSender{params: params},
		PkB:    &Schnorr{params: params},
	}
}

type signInitStorage struct {
	Seed [32]byte // hash seed for idExt?
	DB   *curves.EcPoint
}

type signStorage struct {
	RPrime *curves.EcPoint
	EtaPhi *big.Int
	EtaSig *big.Int
}

// signInit Bob's initial message, which kicks off the signature process. Protocol 1, Bob's steps 1) - 3).
// Bob's work here entails beginning the Diffie–Hellman-like construction of the instance key / nonce,
// as well as preparing the inputs which he will feed into the multiplication protocol,
// and moreover actually initiating the (first message of) the multiplication protocol using these inputs.
// this latter step in turn amounts to sending the initial message in a new cOT extension.
// all the resulting data gets packaged and sent to Alice.
func (bob *Bob) signInit(w io.Writer) error {
	bob.tB = NewMultiplyReceiver(2, bob.Sender)
	// assumes that the seed OT has already been taken care of.
	// result is an instance seed _plus_ partial instance dB key plus _two_ concurrent first messages in the multiplication protocol!
	result := &signInitStorage{}
	enc := gob.NewEncoder(w)
	var err error
	if _, err = rand.Read(result.Seed[:]); err != nil {
		return err
	}
	idExt := sha256.Sum256(result.Seed[:])

	if bob.kB, err = bob.params.Scalar.Random(); err != nil {
		return err
	}
	if bob.dB, err = curves.NewScalarBaseMult(bob.params.Curve, bob.kB); err != nil {
		return err
	}
	result.DB = bob.dB // ?
	kBInv := bob.params.Scalar.Div(big.NewInt(1), bob.kB)
	if err = enc.Encode(result); err != nil {
		return err
	}
	return bob.tB.MultiplyInit(idExt, []*big.Int{kBInv, bob.params.Scalar.Mul(bob.SkB, kBInv)}, w)
}

// signInit Alice's first message. Alice is the _responder_; she is responding to Bob's initial message.
// this is Protocol 1 (p. 6), and contains Alice's steps 3) -- 8). these can all be combined into one message.
// Alice's job here is to finish computing the shared instance key / nonce, as well as multiplication input values;
// then to invoke the coalesced multiplication on these two input values (appending the result to her running message),
// then to use the _output_ of the multiplication (which she already possesses as of the end of her computation),
// and use that to compute some final values which will help Bob compute the final signature.
//
// Note: the protocol has been modified to receive the message digest instead of the message to make the protocol
// compatible with various blockchains as they each use a different hashing algorithm. For example,
// 2xSHA2 for Bitcoin and keccak-256 for Ethereum. We have investigated the security of receiving hash as input and
// the result is available at TODO: add the link to the document containing the analysis.
func (alice *Alice) signInit(digest []byte, rw io.ReadWriter) error {
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	input := &signInitStorage{}
	if err := dec.Decode(input); err != nil {
		return err
	}
	tA := NewMultiplySender(2, alice.Receiver)
	// digest is the hashed message to be signed. i use the name `message` throughout for crypto messages.
	// note: things could go badly if Bob doesn't pick a _new_ / random "seed". verify how to handle this.
	idExt := sha256.Sum256(input.Seed[:])

	result := &signStorage{} // make([]byte, tA.MultiplyOutputSize+192) // again pretty convoluted here.
	kPrimeA, err := alice.params.Scalar.Random()
	if err != nil {
		return err
	}
	if result.RPrime, err = input.DB.ScalarMult(kPrimeA); err != nil {
		return err
	}
	temp := sha256.Sum256(result.RPrime.Bytes())
	kA := alice.params.Scalar.Add(new(big.Int).SetBytes(temp[:]), kPrimeA)
	r, err := input.DB.ScalarMult(kA)
	if err != nil {
		return err
	}
	phi, err := alice.params.Scalar.Random()
	if err != nil {
		return err
	}
	kAInv := alice.params.Scalar.Div(big.NewInt(1), kA)

	// Alice's response here is _two_ (i.e., collated) responses to the multiplication protocol.
	// followed by Alice's R', followed by a schnorr proof for R (!). folllowed by \eta^{\phi} and \eta^{sig}.
	if err = tA.Multiply(idExt, []*big.Int{alice.params.Scalar.Add(phi, kAInv), alice.params.Scalar.Mul(alice.SkA, kAInv)}, rw); err != nil {
		return err
	}

	gamma1, err := curves.NewScalarBaseMult(alice.params.Curve, kA)
	if err != nil {
		return err
	}
	gamma1, err = gamma1.ScalarMult(phi)
	if err != nil {
		return err
	}
	other, err := r.ScalarMult(alice.params.Scalar.Neg(tA.TA[0]))
	if err != nil {
		return err
	}
	gamma1, err = gamma1.Add(other)
	if err != nil {
		return err
	}
	gamma1, err = gamma1.Add(alice.params.Generator)
	if err != nil {
		return err
	}
	temp = sha256.Sum256(gamma1.Bytes())
	result.EtaPhi = alice.params.Scalar.Add(new(big.Int).SetBytes(temp[:]), phi)
	sigA := alice.params.Scalar.Add(
		alice.params.Scalar.Mul(
			new(big.Int).SetBytes(digest),
			tA.TA[0],
		),
		alice.params.Scalar.Mul(
			r.X, tA.TA[1],
		),
	)
	gamma2, err := alice.Pk.ScalarMult(tA.TA[0])
	if err != nil {
		return err
	}
	other, err = curves.NewScalarBaseMult(alice.params.Curve, alice.params.Scalar.Neg(tA.TA[1]))
	if err != nil {
		return err
	}
	gamma2, err = gamma2.Add(other)
	if err != nil {
		return err
	}
	temp = sha256.Sum256(gamma2.Bytes())
	result.EtaSig = alice.params.Scalar.Add(new(big.Int).SetBytes(temp[:]), sigA)
	return enc.Encode(result)
}

// signFinal this is Bob's last portion of the signature computation, and ultimately results in the complete signature
// corresponds to Protocol 1, Bob's steps 3) -- 10).
// Bob begins by _finishing_ the OT-based multiplication, using Alice's one and only message to him re: the mult.
// Bob then move's onto the remainder of Alice's message, which contains extraneous data used to finish the signature.
// using this data, Bob completes the signature, which gets stored in `Bob.Sig`. Bob also verifies it.
//
// Note: the protocol has been modified to receive the message digest instead of the message to make the protocol
// compatible with various blockchains as they each use a different hashing algorithm. For example,
// 2xSHA2 for Bitcoin and keccak-256 for Ethereum. We have investigated the security of receiving hash as input and
// the result is available at TODO: add the link to the document containing the analysis.
func (bob *Bob) signFinal(digest []byte, r io.Reader) error {
	bob.Sig = &curves.EcdsaSignature{}
	if err := bob.tB.MultiplyTransfer(r); err != nil {
		return err
	}
	dec := gob.NewDecoder(r)
	input := &signStorage{}
	if err := dec.Decode(input); err != nil {
		return err
	}
	temp := sha256.Sum256(input.RPrime.Bytes())
	R, err := bob.dB.ScalarMult(new(big.Int).SetBytes(temp[:]))
	if err != nil {
		return err
	}
	R, err = R.Add(input.RPrime)
	if err != nil {
		return err
	}
	bob.Sig.R = R.X // NOT modding by q...?
	bob.Sig.V = int(R.Y.Bit(0))
	gamma1, err := R.ScalarMult(bob.tB.TB[0])
	if err != nil {
		return err
	}
	temp = sha256.Sum256(gamma1.Bytes())
	phi := bob.params.Scalar.Sub(input.EtaPhi, new(big.Int).SetBytes(temp[:]))
	theta := bob.params.Scalar.Sub(bob.tB.TB[0], bob.params.Scalar.Div(phi, bob.kB))
	sigB := bob.params.Scalar.Add(bob.params.Scalar.Mul(new(big.Int).SetBytes(digest), theta), bob.params.Scalar.Mul(bob.Sig.R, bob.tB.TB[1]))
	gamma2, err := curves.NewScalarBaseMult(bob.params.Curve, bob.tB.TB[1])
	if err != nil {
		return err
	}
	other, err := bob.Pk.ScalarMult(bob.params.Scalar.Neg(theta))
	if err != nil {
		return err
	}
	gamma2, err = gamma2.Add(other)
	if err != nil {
		return err
	}
	temp = sha256.Sum256(gamma2.Bytes())
	bob.Sig.S = bob.params.Scalar.Add(sigB, bob.params.Scalar.Sub(input.EtaSig, new(big.Int).SetBytes(temp[:])))
	// now verify the signature
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: bob.params.Curve, X: bob.Pk.X, Y: bob.Pk.Y}, digest, bob.Sig.R, bob.Sig.S) {
		return fmt.Errorf("final signature failed to verify")
	}
	return nil
}

// Sign this is an illustrative helper method which shows the overall flow for Alice.
// in practice this will be replaced by a method which actually sends messages back and forth.
func (alice *Alice) Sign(m []byte, rw io.ReadWriter) error {
	return alice.signInit(m, rw)
}

// Sign this is an illustrative helper method which shows the overall flow for Bob.
func (bob *Bob) Sign(m []byte, rw io.ReadWriter) error {
	if err := bob.signInit(rw); err != nil {
		return err
	}
	return bob.signFinal(m, rw)
}
