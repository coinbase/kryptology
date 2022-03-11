//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sign

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
)

// This implements the Multiplication protocol of DKLs, protocol 5. https://eprint.iacr.org/2018/499.pdf
// two parties---the "sender" and "receiver", let's say---each input a scalar modulo q.
// the functionality multiplies their two scalars modulo q, and then randomly additively shares the product mod q.
// it then returns the two respective additive shares to the two parties.

// MultiplySender is the party that plays the role of Sender in the multiplication protocol (protocol 5 of the paper).
type MultiplySender struct {
	cOtSender           *kos.Sender   // underlying cOT sender struct, used by mult.
	outputAdditiveShare curves.Scalar // ultimate output share of mult.
	gadget              [kos.L]curves.Scalar
	curve               *curves.Curve
	transcript          *merlin.Transcript
	uniqueSessionId     [simplest.DigestSize]byte
}

// MultiplyReceiver is the party that plays the role of Sender in the multiplication protocol (protocol 5 of the paper).
type MultiplyReceiver struct {
	cOtReceiver         *kos.Receiver               // underlying cOT receiver struct, used by mult.
	outputAdditiveShare curves.Scalar               // ultimate output share of mult.
	omega               [kos.COtBlockSizeBytes]byte // this is used as an intermediate result during the course of mult.
	gadget              [kos.L]curves.Scalar
	curve               *curves.Curve
	transcript          *merlin.Transcript
	uniqueSessionId     [simplest.DigestSize]byte
}

func generateGadgetVector(curve *curves.Curve) ([kos.L]curves.Scalar, error) {
	var err error
	gadget := [kos.L]curves.Scalar{}
	for i := 0; i < kos.Kappa; i++ {
		gadget[i], err = curve.Scalar.SetBigInt(new(big.Int).Lsh(big.NewInt(1), uint(i)))
		if err != nil {
			return gadget, errors.Wrap(err, "creating gadget scalar from big int")
		}
	}
	shake := sha3.NewCShake256(nil, []byte("Coinbase DKLs gadget vector"))
	for i := kos.Kappa; i < kos.L; i++ {
		var err error
		bytes := [simplest.DigestSize]byte{}
		if _, err = shake.Read(bytes[:]); err != nil {
			return gadget, err
		}
		gadget[i], err = curve.Scalar.SetBytes(bytes[:])
		if err != nil {
			return gadget, errors.Wrap(err, "creating gadget scalar from bytes")
		}
	}
	return gadget, nil
}

// NewMultiplySender generates a `MultiplySender` instance, ready to take part in multiplication as the "sender".
// You must supply it the _output_ of a seed OT, from the receiver's point of view, as well as params and a unique ID.
// That is, the mult sender must run the base OT as the receiver; note the (apparent) reversal of roles.
func NewMultiplySender(seedOtResults *simplest.ReceiverOutput, curve *curves.Curve, uniqueSessionId [simplest.DigestSize]byte) (*MultiplySender, error) {
	sender := kos.NewCOtSender(seedOtResults, curve)
	gadget, err := generateGadgetVector(curve)
	if err != nil {
		return nil, errors.Wrap(err, "error generating gadget vector in new multiply sender")
	}

	transcript := merlin.NewTranscript("Coinbase_DKLs_Multiply")
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])
	return &MultiplySender{
		cOtSender:       sender,
		curve:           curve,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
		gadget:          gadget,
	}, nil
}

// NewMultiplyReceiver generates a `MultiplyReceiver` instance, ready to take part in multiplication as the "receiver".
// You must supply it the _output_ of a seed OT, from the sender's point of view, as well as params and a unique ID.
// That is, the mult sender must run the base OT as the sender; note the (apparent) reversal of roles.
func NewMultiplyReceiver(seedOtResults *simplest.SenderOutput, curve *curves.Curve, uniqueSessionId [simplest.DigestSize]byte) (*MultiplyReceiver, error) {
	receiver := kos.NewCOtReceiver(seedOtResults, curve)
	gadget, err := generateGadgetVector(curve)
	if err != nil {
		return nil, errors.Wrap(err, "error generating gadget vector in new multiply receiver")
	}
	transcript := merlin.NewTranscript("Coinbase_DKLs_Multiply")
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])
	return &MultiplyReceiver{
		cOtReceiver:     receiver,
		curve:           curve,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
		gadget:          gadget,
	}, nil
}

// MultiplyRound2Output is the output of the second round of the multiplication protocol.
type MultiplyRound2Output struct {
	COTRound2Output *kos.Round2Output
	R               [kos.L]curves.Scalar
	U               curves.Scalar
}

// Algorithm 5. in DKLs. "Encodes" Bob's secret input scalars `beta` in the right way, using the opts.
// The idea is that if Bob were to just put beta's as the choice vector, then Alice could learn a few of Bob's bits.
// using selective failure attacks. so you subtract random components of a public random vector. see paper for details.
func (receiver *MultiplyReceiver) encode(beta curves.Scalar) ([kos.COtBlockSizeBytes]byte, error) {
	// passing beta by value, so that we can mutate it locally. check that this does what i want.
	encoding := [kos.COtBlockSizeBytes]byte{}
	bytesOfBetaMinusDotProduct := beta.Bytes()
	if _, err := rand.Read(encoding[kos.KappaBytes:]); err != nil {
		return encoding, errors.Wrap(err, "sampling `gamma` random bytes in multiply receiver encode")
	}
	for j := kos.Kappa; j < kos.L; j++ {
		jthBitOfGamma := simplest.ExtractBitFromByteVector(encoding[:], j)
		// constant-time computation of the dot product beta - < gR, gamma >.
		// we can only `ConstantTimeCopy` byte slices (as opposed to big ints). so keep them as bytes.
		option0, err := receiver.curve.Scalar.SetBytes(bytesOfBetaMinusDotProduct[:])
		if err != nil {
			return encoding, errors.Wrap(err, "setting masking bits scalar from bytes")
		}
		option0Bytes := option0.Bytes()
		option1 := option0.Sub(receiver.gadget[j])
		option1Bytes := option1.Bytes()
		bytesOfBetaMinusDotProduct = option0Bytes
		subtle.ConstantTimeCopy(int(jthBitOfGamma), bytesOfBetaMinusDotProduct[:], option1Bytes)
	}
	copy(encoding[0:kos.KappaBytes], internal.ReverseScalarBytes(bytesOfBetaMinusDotProduct[:]))
	return encoding, nil
}

// Round1Initialize Protocol 5., Multiplication, 3). Bob (receiver) encodes beta and initiates the cOT extension
func (receiver *MultiplyReceiver) Round1Initialize(beta curves.Scalar) (*kos.Round1Output, error) {
	var err error
	if receiver.omega, err = receiver.encode(beta); err != nil {
		return nil, errors.Wrap(err, "encoding input beta in receiver round 1 initialize")
	}
	cOtRound1Output, err := receiver.cOtReceiver.Round1Initialize(receiver.uniqueSessionId, receiver.omega)
	if err != nil {
		return nil, errors.Wrap(err, "error in cOT round 1 initialize within multiply round 1 initialize")
	}
	// write the output of the first round to the transcript
	for i := 0; i < kos.Kappa; i++ {
		label := []byte(fmt.Sprintf("row %d of U", i))
		receiver.transcript.AppendMessage(label, cOtRound1Output.U[i][:])
	}
	receiver.transcript.AppendMessage([]byte("wPrime"), cOtRound1Output.WPrime[:])
	receiver.transcript.AppendMessage([]byte("vPrime"), cOtRound1Output.VPrime[:])
	return cOtRound1Output, nil
}

// Round2Multiply Protocol 5., steps 3) 5), 7). Alice _responds_ to Bob's initial cOT message, using alpha as input.
// Doesn't actually send the message yet, only stashes it and moves onto the next steps of the multiplication protocol
// specifically, Alice can then do step 5) (compute the outputs of the multiplication protocol), also stashes this.
// Finishes by taking care of 7), after that, Alice is totally done with multiplication and has stashed the outputs.
func (sender *MultiplySender) Round2Multiply(alpha curves.Scalar, round1Output *kos.Round1Output) (*MultiplyRound2Output, error) {
	var err error
	alphaHat := sender.curve.Scalar.Random(rand.Reader)
	input := [kos.L][2]curves.Scalar{} // sender's input, namely integer "sums" in case w_j == 1.
	for j := 0; j < kos.L; j++ {
		input[j][0] = alpha
		input[j][1] = alphaHat
	}
	round2Output := &MultiplyRound2Output{}
	round2Output.COTRound2Output, err = sender.cOtSender.Round2Transfer(sender.uniqueSessionId, input, round1Output)
	if err != nil {
		return nil, errors.Wrap(err, "error in cOT within round 2 multiply")
	}
	// write the output of the first round to the transcript
	for i := 0; i < kos.Kappa; i++ {
		label := []byte(fmt.Sprintf("row %d of U", i))
		sender.transcript.AppendMessage(label, round1Output.U[i][:])
	}
	sender.transcript.AppendMessage([]byte("wPrime"), round1Output.WPrime[:])
	sender.transcript.AppendMessage([]byte("vPrime"), round1Output.VPrime[:])
	// write our own output of the second round to the transcript
	chiWidth := 2
	for i := 0; i < kos.Kappa; i++ {
		for k := 0; k < chiWidth; k++ {
			label := []byte(fmt.Sprintf("row %d of Tau", i))
			sender.transcript.AppendMessage(label, round2Output.COTRound2Output.Tau[i][k].Bytes())
		}
	}
	chi := make([]curves.Scalar, chiWidth)
	for k := 0; k < 2; k++ {
		label := []byte(fmt.Sprintf("draw challenge chi %d", k))
		randomBytes := sender.transcript.ExtractBytes(label, kos.KappaBytes)
		chi[k], err = sender.curve.Scalar.SetBytes(randomBytes)
		if err != nil {
			return nil, errors.Wrap(err, "setting chi scalar from bytes")
		}
	}
	sender.outputAdditiveShare = sender.curve.Scalar.Zero()
	for j := 0; j < kos.L; j++ {
		round2Output.R[j] = sender.curve.Scalar.Zero()
		for k := 0; k < chiWidth; k++ {
			round2Output.R[j] = round2Output.R[j].Add(chi[k].Mul(sender.cOtSender.OutputAdditiveShares[j][k]))
		}
		sender.outputAdditiveShare = sender.outputAdditiveShare.Add(sender.gadget[j].Mul(sender.cOtSender.OutputAdditiveShares[j][0]))
	}
	round2Output.U = chi[0].Mul(alpha).Add(chi[1].Mul(alphaHat))
	return round2Output, nil
}

// Round3Multiply Protocol 5., Multiplication, 3) and 6). Bob finalizes the cOT extension.
// using that and Alice's multiplication message, Bob completes the multiplication protocol, including checks.
// At the end, Bob's values tB_j are populated.
func (receiver *MultiplyReceiver) Round3Multiply(round2Output *MultiplyRound2Output) error {
	chiWidth := 2
	// write the output of the second round to the transcript
	for i := 0; i < kos.Kappa; i++ {
		for k := 0; k < chiWidth; k++ {
			label := []byte(fmt.Sprintf("row %d of Tau", i))
			receiver.transcript.AppendMessage(label, round2Output.COTRound2Output.Tau[i][k].Bytes())
		}
	}
	if err := receiver.cOtReceiver.Round3Transfer(round2Output.COTRound2Output); err != nil {
		return errors.Wrap(err, "error within cOT round 3 transfer within round 3 multiply")
	}
	var err error
	chi := make([]curves.Scalar, chiWidth)
	for k := 0; k < chiWidth; k++ {
		label := []byte(fmt.Sprintf("draw challenge chi %d", k))
		randomBytes := receiver.transcript.ExtractBytes(label, kos.KappaBytes)
		chi[k], err = receiver.curve.Scalar.SetBytes(randomBytes)
		if err != nil {
			return errors.Wrap(err, "setting chi scalar from bytes")
		}
	}

	receiver.outputAdditiveShare = receiver.curve.Scalar.Zero()
	for j := 0; j < kos.L; j++ {
		// compute the LHS of bob's step 6) for j. note that we're "adding r_j" to both sides"; so this LHS includes r_j.
		// the reason to do this is so that the constant-time (i.e., independent of w_j) calculation of w_j * u can proceed more cleanly.
		leftHandSideOfCheck := round2Output.R[j]
		for k := 0; k < chiWidth; k++ {
			leftHandSideOfCheck = leftHandSideOfCheck.Add(chi[k].Mul(receiver.cOtReceiver.OutputAdditiveShares[j][k]))
		}
		rightHandSideOfCheck := [simplest.DigestSize]byte{}
		jthBitOfOmega := simplest.ExtractBitFromByteVector(receiver.omega[:], j)
		subtle.ConstantTimeCopy(int(jthBitOfOmega), rightHandSideOfCheck[:], round2Output.U.Bytes())
		if subtle.ConstantTimeCompare(rightHandSideOfCheck[:], leftHandSideOfCheck.Bytes()) != 1 {
			return fmt.Errorf("alice's values R and U failed to check in round 3 multiply")
		}
		receiver.outputAdditiveShare = receiver.outputAdditiveShare.Add(receiver.gadget[j].Mul(receiver.cOtReceiver.OutputAdditiveShares[j][0]))
	}
	return nil
}
