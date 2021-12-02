//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkls

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/coinbase/kryptology/internal"
)

// this implements the _coalesced_ multiplication, in which Alice and Bob perform 2 "parallel" multiplication protocols
// they wind up with additive sharings of the respective two products.

type MultiplySender struct {
	sender *cOTSender
	TA     []*big.Int

	multiplicity int
}

type MultiplyReceiver struct {
	receiver *cOTReceiver
	TB       []*big.Int

	omega        []byte // stashing this here, though ironically the cOT doesn't need to stash it.
	multiplicity int
}

func NewMultiplySender(multiplicity int, receiver *seedOTReceiver) *MultiplySender {
	sender := newCOTSender(multiplicity, receiver)
	return &MultiplySender{
		sender:       sender,
		TA:           make([]*big.Int, multiplicity),
		multiplicity: multiplicity,
	}
}

func NewMultiplyReceiver(multiplicity int, sender *seedOTSender) *MultiplyReceiver {
	receiver := newCOTReceiver(multiplicity, sender)
	return &MultiplyReceiver{
		receiver:     receiver,
		TB:           make([]*big.Int, multiplicity),
		multiplicity: multiplicity,
	}
}

// Algorithm 5. in DKLs. this "encodes" Bob's secret input scalars `beta` in the right way, using the opts.
// the idea is that if Bob were to just put beta's as the choice vector, then Alice could learn a few of Bob's bits.
// using selective failure attacks. so you subtract random components of a public random vector. see paper for details.
// note that we're using the optimization now where both multiplications get "coalesced".
func (receiver *MultiplyReceiver) encode(beta []*big.Int) ([]byte, error) {
	// passing beta by value, so that we can mutate it locally. check that this does what i want.
	bytes := make([][]byte, receiver.multiplicity)
	params := receiver.receiver.sender.params
	result := make([]byte, receiver.receiver.l>>3)
	for i := 0; i < receiver.multiplicity; i++ {
		bytes[i] = params.Scalar.Bytes(beta[i])
		if _, err := rand.Read(result[(1+i*2)*kappa>>3 : (2+i*2)*kappa>>3]); err != nil {
			return nil, err
		}
	}
	if _, err := rand.Read(result[2*receiver.multiplicity*kappa>>3 : (2*receiver.multiplicity*kappa+s)>>3]); err != nil {
		return nil, err
	}
	for i := 0; i < receiver.multiplicity; i++ {
		for j := 0; j < kappa; j++ {
			bit := int(result[((1+2*i)*kappa+j)>>3]) >> (j & 0x07) & 0x01
			mask := params.Scalar.Bytes(params.Scalar.Sub(new(big.Int).SetBytes(bytes[i][:]), params.gadget[kappa+j]))
			subtle.ConstantTimeCopy(bit, bytes[i][:], mask)
		}
		// some converting from bytes and back. a bit cumbersome, but in practice this will be negligible
		// it'd be simpler to just keep running big ints, which we are subtracting from.
		// but we can only `ConstantTimeCopy` byte slices (as opposed to big ints). so keep them as bytes.
		for j := 0; j < 2*s; j++ {
			bit := int(result[(2*receiver.multiplicity*kappa+j)>>3]) >> (j & 0x07) & 0x01
			mask := params.Scalar.Bytes(params.Scalar.Sub(new(big.Int).SetBytes(bytes[i][:]), params.gadget[2*kappa+j]))
			subtle.ConstantTimeCopy(bit, bytes[i][:], mask)
		}
		copy(result[2*i*kappa>>3:(2*i+1)*kappa>>3], internal.ReverseScalarBytes(bytes[i][:]))
	}
	return result, nil
}

// MultiplyInit Protocol 5., Multiplication, 3). Bob (receiver) encodes beta and initiates the cOT extension!
func (receiver *MultiplyReceiver) MultiplyInit(idExt [32]byte, beta []*big.Int, w io.Writer) error {
	var err error
	if receiver.omega, err = receiver.encode(beta); err != nil {
		return err
	}
	return receiver.receiver.init(idExt, receiver.omega, w)
}

// Multiply Protocol 5., steps 3) 5), 7). Alice _responds_ to Bob's initial cOT message, using a vector of alphas as input.
// doesn't actually send that message yet, only stashes it, and moves onto the next steps of the multiplication protocol
// specifically, Alice can then do step 5) (compute the outputs of the multiplication protocol), also stashes this.
// finishes up by taking care of 7), after that, Alice is totally done with multiplication and has stashed the outputs.
func (sender *MultiplySender) Multiply(idExt [32]byte, alpha []*big.Int, rw io.ReadWriter) error {
	inputMain := make([]*big.Int, 2*sender.multiplicity*kappa)
	inputOT := [2 * s][]*big.Int{} // inputOT := [2 * s][2 * sender.multiplicity]*big.Int{}
	for i := range inputOT {
		inputOT[i] = make([]*big.Int, sender.multiplicity)
	}
	var err error
	params := sender.sender.receiver.params
	for i := 0; i < sender.multiplicity; i++ {
		for j := 0; j < 2*kappa; j++ {
			inputMain[kappa*2*i+j] = params.Scalar.Mul(params.gadget[j], alpha[i])
		}
		for j := 0; j < 2*s; j++ {
			inputOT[j][i] = params.Scalar.Mul(params.gadget[j+2*kappa], alpha[i])
		}
	}
	if err = sender.sender.transfer(idExt, inputMain, inputOT, rw); err != nil {
		return err
	}

	scalar := sender.sender.receiver.params.Scalar // stash this just to shorten the expressions
	for i := 0; i < sender.multiplicity; i++ {
		sender.TA[i] = new(big.Int)
		for j := 0; j < 2*kappa; j++ {
			sender.TA[i] = scalar.Add(sender.TA[i], sender.sender.tA[2*kappa*i+j])
		}
	}
	for i := 0; i < 2*s; i++ {
		for j := 0; j < sender.multiplicity; j++ {
			sender.TA[j] = scalar.Add(sender.TA[j], sender.sender.tAOT[i][j])
		}
	}
	return nil
}

// MultiplyTransfer Protocol 5., Multiplication, 3) and 6). Bob finalizes the cOT extension.
// using that and Alice's multiplication message, Bob completes the multiplication protocol, including checks.
// at the end, Bob's values tB_j are populated.
func (receiver *MultiplyReceiver) MultiplyTransfer(r io.Reader) error {
	if err := receiver.receiver.transfer(r); err != nil {
		return err
	}
	scalar := receiver.receiver.sender.params.Scalar
	for i := 0; i < receiver.multiplicity; i++ {
		receiver.TB[i] = new(big.Int)
		for j := 0; j < 2*kappa; j++ {
			receiver.TB[i] = scalar.Add(receiver.TB[i], receiver.receiver.tB[2*kappa*i+j])
		}
	}
	for i := 0; i < 2*s; i++ {
		for j := 0; j < receiver.multiplicity; j++ {
			receiver.TB[j] = scalar.Add(receiver.TB[j], receiver.receiver.tBOT[i][j])
		}
	}
	return nil
}

// illustrative helper method which goes through the whole flow for Bob, assuming a channel to pass messages through.
func (receiver *MultiplyReceiver) multiply(idExt [32]byte, beta []*big.Int, rw io.ReadWriter) error {
	if err := receiver.MultiplyInit(idExt, beta, rw); err != nil {
		return err
	}
	return receiver.MultiplyTransfer(rw)
}

// illustrative helper method which goes through the whole flow for Alice, assuming a channel.
func (sender *MultiplySender) multiply(idExt [32]byte, alpha []*big.Int, rw io.ReadWriter) error {
	return sender.Multiply(idExt, alpha, rw)
}
