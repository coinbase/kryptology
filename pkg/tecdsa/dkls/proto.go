//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkls

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

type (
	// ProtocolIterator a generalized interface for multi-party protocols that follows the iterator pattern.
	ProtocolIterator interface {
		// Next runs the next round of the protocol.
		// Inputs are read from rw.Read(); outputs are written to rw.Write().
		// Returns io.EOF when protocol has completed.
		Next(rw io.ReadWriter) error

		// Result returns the final result, if any, of the completed protocol.
		// Reports an error if the protocol has not yet terminated
		// or if an error was encountered during protocol execution.
		Result() (interface{}, error)

		// SetDebug enables or disables (passing a nil value as input) debugging.
		// At the moment, we only print the final dkls dkg result as json value to this log, but if needed more debugging
		// can be added for various steps of the other protocols.
		SetDebug(log io.Writer)
	}

	// Basic protocol interface implementation that calls the next step func in a pre-defined list
	protoStepper struct {
		steps []func(rw io.ReadWriter) error
		step  uint
		log   io.Writer //nolint:structcheck // This is only used in some of the protocols.
	}

	// DKG protocols produce the following result on successful completion
	DkgResult struct {
		DkgState []byte
		Pubkey   *curves.EcPoint
	}
	// AliceDkg DKLS DKG implementation that satisfies the protocol iterator interface.
	AliceDkg struct {
		protoStepper
		alice *Alice
	}

	// BobDkg DKLS DKG implementation that satisfies the protocol iterator interface.
	BobDkg struct {
		protoStepper
		bob *Bob
	}

	// AliceSign DKLS sign implementation that satisfies the protocol iterator interface.
	AliceSign struct {
		protoStepper
		alice *Alice
	}

	// BobSign DKLS sign implementation that satisfies the protocol iterator interface.
	BobSign struct {
		protoStepper
		bob *Bob
	}
)

var (
	// Static type assertions
	_ ProtocolIterator = &AliceDkg{}
	_ ProtocolIterator = &BobDkg{}
	_ ProtocolIterator = &AliceSign{}
	_ ProtocolIterator = &BobSign{}

	errProtocolNotComplete = fmt.Errorf("protocol has not completed")
	errNotInitialized      = fmt.Errorf("object has not been initialized")
	errNoSig               = fmt.Errorf("dkls.Alice does not produce a signature")
)

// Reports true if the step index exceeds the number of steps
func (p *protoStepper) complete() bool { return int(p.step) >= len(p.steps) }

// Next runs the next step in the protocol and reports errors or increments the step index
func (p *protoStepper) Next(rw io.ReadWriter) error {
	// Signal EOF if the protocol has completed.
	if p.complete() {
		return io.EOF
	}

	// Run the current protocol step and report any errors
	if err := p.steps[p.step](rw); err != nil {
		return err
	}

	// Increment the step index and report success
	p.step++
	return nil
}

// NewAliceDkg creates a new protocol that can compute a DKG as Alice
func NewAliceDkg(params *Params) *AliceDkg {
	a := &AliceDkg{alice: NewAlice(params)}
	a.steps = []func(rw io.ReadWriter) error{
		func(rw io.ReadWriter) error { return a.alice.dkgCommit(rw) },
		a.alice.dkgVerify,
		func(rw io.ReadWriter) error {
			if err := a.alice.Receiver.pubKey(rw); err != nil {
				return err
			}
			return a.alice.Receiver.padTransfer(rw)
		},
		a.alice.Receiver.verification,
		func(rw io.ReadWriter) error { return a.alice.Receiver.final(rw) },
	}
	return a
}

// NewBobDkg Creates a new protocol that can compute a DKG as Bob
func NewBobDkg(params *Params) *BobDkg {
	b := &BobDkg{bob: NewBob(params)}
	b.steps = []func(rw io.ReadWriter) error{
		b.bob.dkgCommit,
		func(rw io.ReadWriter) error {
			if err := b.bob.dkgVerify(rw); err != nil {
				return err
			}
			return b.bob.Sender.pubKey(rw)
		},
		b.bob.Sender.padTransfer,
		b.bob.Sender.verification,
	}
	return b
}

func (a *AliceDkg) SetDebug(log io.Writer) {
	a.log = log
}

// Result Returns an encoded version of Alice as sequence of bytes that can be used to initialize an AliceSign protocol.
func (a *AliceDkg) Result() (interface{}, error) {
	// Sanity check
	if !a.complete() {
		return nil, errProtocolNotComplete
	}
	if a.alice == nil {
		return nil, errNotInitialized
	}

	// Encode DKG state of alice for future signing
	state, err := EncodeAlice(a.alice)
	if err != nil {
		return nil, err
	}

	result := &DkgResult{
		DkgState: state,
		Pubkey:   a.alice.Pk,
	}

	if a.log != nil {
		resultBytes, err := json.Marshal(result)
		if err != nil {
			_, _ = a.log.Write([]byte(fmt.Sprintf("Error while json marshaling the results: %v", err)))
		} else {
			_, _ = a.log.Write([]byte("Alice Dkg result:\n"))
			_, _ = a.log.Write(resultBytes)
		}
	}
	return result, nil
}

func (b *BobDkg) SetDebug(log io.Writer) {
	b.log = log
}

// Result returns an encoded version of Alice as sequence of bytes that can be used to
// initialize an AliceSign protocol.
func (b *BobDkg) Result() (interface{}, error) {
	// Sanity check
	if !b.complete() {
		return nil, errProtocolNotComplete
	}
	if b.bob == nil {
		return nil, errNotInitialized
	}
	// Encode DKG state of bob for future signing
	state, err := EncodeBob(b.bob)
	if err != nil {
		return nil, err
	}

	result := &DkgResult{
		DkgState: state,
		Pubkey:   b.bob.Pk,
	}
	if b.log != nil {
		resultBytes, err := json.Marshal(result)
		if err != nil {
			_, _ = b.log.Write([]byte(fmt.Sprintf("Error while json marshaling the results: %v", err)))
		} else {
			_, _ = b.log.Write([]byte("Alice Dkg result:\n"))
			_, _ = b.log.Write(resultBytes)
		}
	}
	return result, nil
}

// Creates a new protocol that can compute a signature as Alice.
// Requires dkg state that was produced at the end of DKG.Result().
func NewAliceSign(params *Params, msg []byte, dkgResult []byte) (*AliceSign, error) {
	// Reconstitute Alice
	alice, err := DecodeAlice(params, dkgResult)
	if err != nil {
		return nil, err
	}

	// Configure Alice with her 1 signing step
	a := &AliceSign{alice: alice}
	a.steps = []func(rw io.ReadWriter) error{
		func(rw io.ReadWriter) error { return alice.signInit(msg, rw) },
	}
	return a, nil
}

// NewBobSign creates a new protocol that can compute a signature as Bob.
// Requires dkg state that was produced at the end of DKG.Result().
func NewBobSign(params *Params, msg []byte, dkgResult []byte) (*BobSign, error) {
	// Reconstitute Bob
	bob, err := DecodeBob(params, dkgResult)
	if err != nil {
		return nil, err
	}

	// Configure Bob with 2 signing steps
	b := &BobSign{bob: bob}
	b.steps = []func(rw io.ReadWriter) error{
		func(rw io.ReadWriter) error { return bob.signInit(rw) },
		func(rw io.ReadWriter) error { return bob.signFinal(msg, rw) },
	}
	return b, nil
}

func (a *AliceSign) SetDebug(log io.Writer) {
	a.log = log
}

// Result always returns errNoSig.
// Alice does not compute a signature in the DKLS protocol; only Bob computes the signature.
func (a *AliceSign) Result() (interface{}, error) {
	return nil, errNoSig
}

func (b *BobSign) SetDebug(log io.Writer) {
	b.log = log
}

// If the signing protocol completed successfully, returns the signature that
// Bob computed as a *core.EcdsaSignature.
func (d *BobSign) Result() (interface{}, error) {
	// We can't produce a signature until the protocol completes
	if !d.complete() {
		return nil, errProtocolNotComplete
	}
	if d.bob == nil {
		// Object wasn't created with NewXSign()
		return nil, errNotInitialized

	}
	return d.bob.Sig, nil
}

// Encodes an alice object as a byte sequence after DKG has been completed.
func EncodeAlice(a *Alice) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(a)
	return buf.Bytes(), err
}

// Decodes an alice object that was encoded after DKG.
func DecodeAlice(params *Params, b []byte) (*Alice, error) {
	alice := NewAlice(params)
	err := gob.NewDecoder(bytes.NewBuffer(b)).Decode(alice)
	return alice, err
}

// Encodes a bob object as a byte sequence after DKG has been completed.
func EncodeBob(b *Bob) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(b)
	return buf.Bytes(), err
}

// Decodes an bob object that was encoded after DKG.
func DecodeBob(params *Params, b []byte) (*Bob, error) {
	bob := NewBob(params)
	err := gob.NewDecoder(bytes.NewBuffer(b)).Decode(bob)
	return bob, err
}
