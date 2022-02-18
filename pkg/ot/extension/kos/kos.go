//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package kos in an implementation of maliciously secure OT extension protocol defined in "Protocol 9" of
// [DKLs18](https://eprint.iacr.org/2018/499.pdf). The original protocol was presented in
// [KOS15](https://eprint.iacr.org/2015/546.pdf).
package kos

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"github.com/pkg/errors"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/base/simplest"
	"golang.org/x/crypto/sha3"
)

const (
	// below are the "cryptographic parameters", including computational and statistical,
	// as well as the cOT block size parameters, which depend on these in a pre-defined way.

	// Kappa is the computational security parameter.
	Kappa = 256

	// KappaBytes is same as Kappa // 8, but avoids cpu division.
	KappaBytes = Kappa >> 3

	// L is the batch size used in the cOT functionality.
	L = 2*Kappa + 2*s

	// COtBlockSizeBytes is same as L // 8, but avoids cpu division.
	COtBlockSizeBytes = L >> 3

	// OtWidth is the number of scalars processed per "slot" of the cOT. by definition of this parameter,
	// for each of the receiver's choice bits, the sender will provide `OTWidth` scalars.
	// in turn, both the sender and receiver will obtain `OTWidth` shares _per_ slot / bit of the cOT.
	// by definition of the cOT, these "vectors of" scalars will add (componentwise) to the sender's original scalars.
	OtWidth = 2

	s                         = 80 // statistical security parameter.
	kappaOT                   = Kappa + s
	lPrime                    = L + kappaOT // length of pseudorandom seed expansion, used within cOT protocol
	cOtExtendedBlockSizeBytes = lPrime >> 3
)

type Receiver struct {
	// OutputAdditiveShares are the ultimate output received. basically just the "pads".
	OutputAdditiveShares [L][OtWidth]curves.Scalar

	// seedOtResults are the results that this party has received by playing the sender role in a base OT protocol.
	seedOtResults *simplest.SenderOutput

	// extendedPackedChoices is storage for "choice vector || gamma^{ext}" in a packed format.
	extendedPackedChoices [cOtExtendedBlockSizeBytes]byte
	psi                   [lPrime][KappaBytes]byte // transpose of v^0. gets retained between messages

	curve           *curves.Curve
	uniqueSessionId [simplest.DigestSize]byte // store this between rounds
}

type Sender struct {
	// OutputAdditiveShares are the ultimate output received. basically just the "pads".
	OutputAdditiveShares [L][OtWidth]curves.Scalar

	// seedOtResults are the results that this party has received by playing the receiver role in a base OT protocol.
	seedOtResults *simplest.ReceiverOutput

	curve *curves.Curve
}

// NewCOtReceiver creates a `Receiver` instance, ready for use as the receiver in the KOS cOT protocol
// you must supply the output gotten by running an instance of seed OT as the _sender_ (note the reversal of roles)
func NewCOtReceiver(seedOTResults *simplest.SenderOutput, curve *curves.Curve) *Receiver {
	return &Receiver{
		seedOtResults: seedOTResults,
		curve:         curve,
	}
}

// NewCOtSender creates a `Sender` instance, ready for use as the sender in the KOS cOT protocol.
// you must supply the output gotten by running an instance of seed OT as the _receiver_ (note the reversal of roles)
func NewCOtSender(seedOTResults *simplest.ReceiverOutput, curve *curves.Curve) *Sender {
	return &Sender{
		seedOtResults: seedOTResults,
		curve:         curve,
	}
}

// Round1Output is Bob's first message to Alice during cOT extension;
// these outputs are described in step 4) of Protocol 9) https://eprint.iacr.org/2018/499.pdf
type Round1Output struct {
	U      [Kappa][cOtExtendedBlockSizeBytes]byte
	WPrime [simplest.DigestSize]byte
	VPrime [simplest.DigestSize]byte
}

// Round2Output this is Alice's response to Bob in cOT extension;
// the values `tau` are specified in Alice's step 6) of Protocol 9) https://eprint.iacr.org/2018/499.pdf
type Round2Output struct {
	Tau [L][OtWidth]curves.Scalar
}

// convertBitToBitmask converts a "bit"---i.e., a `byte` which is _assumed to be_ either 0 or 1---into a bitmask,
// namely, it outputs 0x00 if `bit == 0` and 0xFF if `bit == 1`.
func convertBitToBitmask(bit byte) byte {
	return ^(bit - 0x01)
}

// the below code takes as input a `kappa` by `lPrime` _boolean_ matrix, whose rows are actually "compacted" as bytes.
// so in actuality, it's a `kappa` by `lPrime >> 3 == cOtExtendedBlockSizeBytes` matrix of _bytes_.
// its output is the same boolean matrix, but transposed, so it has dimensions `lPrime` by `kappa`.
// but likewise we want to compact the output matrix as bytes, again _row-wise_.
// so the output matrix's dimensions are lPrime by `kappa >> 3 == KappaBytes`, as a _byte_ matrix.
// the technique is fairly straightforward, but involves some bitwise operations.
func transposeBooleanMatrix(input [Kappa][cOtExtendedBlockSizeBytes]byte) [lPrime][KappaBytes]byte {
	output := [lPrime][KappaBytes]byte{}
	for rowByte := 0; rowByte < KappaBytes; rowByte++ {
		for rowBitWithinByte := 0; rowBitWithinByte < 8; rowBitWithinByte++ {
			for columnByte := 0; columnByte < cOtExtendedBlockSizeBytes; columnByte++ {
				for columnBitWithinByte := 0; columnBitWithinByte < 8; columnBitWithinByte++ {
					rowBit := rowByte<<3 + rowBitWithinByte
					columnBit := columnByte<<3 + columnBitWithinByte
					// the below code grabs the _bit_ at input[rowBit][columnBit], if input were a viewed as a boolean matrix.
					// in reality, it's packed into bytes, so instead we have to grab the `columnBitWithinByte`th bit within the appropriate byte.
					bitAtInputRowBitColumnBit := input[rowBit][columnByte] >> columnBitWithinByte & 0x01
					// now that we've grabbed the bit we care about, we need to write it into the appropriate place in the output matrix
					// the output matrix is also packed---but in the "opposite" way (the short dimension is packed, instead of the long one)
					// what we're going to do is take the _bit_ we got, and shift it by rowBitWithinByte.
					// this has the effect of preparing for us to write it into the appropriate place into the output matrix.
					shiftedBit := bitAtInputRowBitColumnBit << rowBitWithinByte
					output[columnBit][rowByte] |= shiftedBit
				}
			}
		}
	}
	return output
}

// Round1Initialize initializes the OT Extension. see page 17, steps 1), 2), 3) and 4) of Protocol 9 of the paper.
// The input `choice` vector is "packed" (i.e., the underlying abstract vector of `L` bits is represented as a `cOTBlockSizeBytes` bytes).
func (receiver *Receiver) Round1Initialize(uniqueSessionId [simplest.DigestSize]byte, choice [COtBlockSizeBytes]byte) (*Round1Output, error) {
	// salt the transcript with the OT-extension session ID
	receiver.uniqueSessionId = uniqueSessionId

	// write the input choice vector into our local data. Since `otBatchSize` is the number of bits, we are working with
	// bytes, we first need to calculate how many bytes are needed to store that many bits.
	copy(receiver.extendedPackedChoices[0:COtBlockSizeBytes], choice[:])

	// Fill the rest of the extended choice vector with random values. These random values correspond to `gamma^{ext}`.
	if _, err := rand.Read(receiver.extendedPackedChoices[COtBlockSizeBytes:]); err != nil {
		return nil, errors.Wrap(err, "sampling random coins for gamma^{ext}")
	}

	v := [2][Kappa][cOtExtendedBlockSizeBytes]byte{} // kappa * L array of _bits_, in "dense" form. contains _both_ v_0 and v_1.
	result := &Round1Output{}

	hash := sha3.New256() // basically this will contain a hash of the matrix U.
	for i := 0; i < Kappa; i++ {
		for j := 0; j < 2; j++ {
			shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
			if _, err := shake.Write(receiver.seedOtResults.OneTimePadEncryptionKeys[i][j][:]); err != nil {
				return nil, errors.Wrap(err, "writing seed OT into shake in cOT receiver round 1")
			}
			// this is the core pseudorandom expansion of the secret OT input seeds s_i^0 and s_i^1
			// see Extension, 2), in Protocol 9, page 17 of DKLs https://eprint.iacr.org/2018/499.pdf
			// use the uniqueSessionId as the "domain separator", and the _secret_ seed rho as the input!
			if _, err := shake.Read(v[j][i][:]); err != nil {
				return nil, errors.Wrap(err, "reading from shake to compute v^j in cOT receiver round 1")
			}
		}
		for j := 0; j < cOtExtendedBlockSizeBytes; j++ {
			result.U[i][j] = v[0][i][j] ^ v[1][i][j] ^ receiver.extendedPackedChoices[j]
			// U := v_i^0 ^ v_i^1 ^ w. note: in step 4) of Prot. 9, i think `w` should be bolded?
		}
		if _, err := hash.Write(result.U[i][:]); err != nil {
			return nil, err
		}
	}
	receiver.psi = transposeBooleanMatrix(v[0])
	digest := hash.Sum(nil) // go ahead and record this, so that we only have to hash the big matrix U once.
	for j := 0; j < lPrime; j++ {
		hash = sha3.New256()
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := hash.Write(jBytes[:]); err != nil { // write j into shake
			return nil, errors.Wrap(err, "writing nonce into hash while computing chiJ in cOT receiver round 1")
		}
		if _, err := hash.Write(digest); err != nil {
			return nil, errors.Wrap(err, "writing input digest into hash while computing chiJ in cOT receiver round 1")
		}
		chiJ := hash.Sum(nil)
		wJ := convertBitToBitmask(simplest.ExtractBitFromByteVector(receiver.extendedPackedChoices[:], j)) // extract j^th bit from vector of bytes w.
		for k := 0; k < KappaBytes; k++ {
			result.WPrime[k] ^= wJ & chiJ[k]
			result.VPrime[k] ^= receiver.psi[j][k] & chiJ[k]
		}
	}
	return result, nil
}

// Round2Transfer computes the OT sender ("Alice")'s part of cOT; this includes steps 2) 5) and 6) of Protocol 9
// `input` is the sender's main vector of inputs alpha_j; these are the things tA_j and tB_j will add to if w_j == 1.
// `message` contains the message the receiver ("Bob") sent us. this itself contains Bob's values WPrime, VPrime, and U
// the output is just the values `Tau` we send back to Bob.
// as a side effect of this function, our (i.e., the sender's) outputs tA_j from the cOT will be populated.
func (sender *Sender) Round2Transfer(uniqueSessionId [simplest.DigestSize]byte, input [L][OtWidth]curves.Scalar, round1Output *Round1Output) (*Round2Output, error) {
	z := [Kappa][cOtExtendedBlockSizeBytes]byte{}
	hash := sha3.New256() // basically this will contain a hash of the matrix U.

	for i := 0; i < Kappa; i++ {
		v := make([]byte, cOtExtendedBlockSizeBytes) // will contain alice's expanded PRG output for the row i, namely v_i^{\Nabla_i}.
		shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		if _, err := shake.Write(sender.seedOtResults.OneTimePadDecryptionKey[i][:]); err != nil {
			return nil, errors.Wrap(err, "sender writing seed OT decryption key into shake in sender round 2 transfer")
		}
		if _, err := shake.Read(v); err != nil {
			return nil, errors.Wrap(err, "reading from shake into row `v` in sender round 2 transfer")
		}
		// use the idExt as the domain separator, and the _secret_ seed rho as the input!
		mask := convertBitToBitmask(byte(sender.seedOtResults.RandomChoiceBits[i]))
		for j := 0; j < cOtExtendedBlockSizeBytes; j++ {
			z[i][j] = v[j] ^ mask&round1Output.U[i][j]
		}
		if _, err := hash.Write(round1Output.U[i][:]); err != nil {
			return nil, errors.Wrap(err, "writing matrix U to hash in cOT sender round 2 transfer")
		}
	}
	zeta := transposeBooleanMatrix(z)
	digest := hash.Sum(nil) // go ahead and record this, so that we only have to hash the big matrix U once.
	zPrime := [simplest.DigestSize]byte{}
	for j := 0; j < lPrime; j++ {
		hash = sha3.New256()
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := hash.Write(jBytes[:]); err != nil { // write j into hash
			return nil, errors.Wrap(err, "writing nonce into hash while computing chiJ in cOT sender round 2 transfer")
		}
		if _, err := hash.Write(digest); err != nil {
			return nil, errors.Wrap(err, "writing input digest into hash while computing chiJ in cOT sender round 2 transfer")
		}
		chiJ := hash.Sum(nil)
		for k := 0; k < KappaBytes; k++ {
			zPrime[k] ^= zeta[j][k] & chiJ[k]
		}
	}
	rhs := [simplest.DigestSize]byte{}
	for i := 0; i < KappaBytes; i++ {
		rhs[i] = round1Output.VPrime[i] ^ sender.seedOtResults.PackedRandomChoiceBits[i]&round1Output.WPrime[i]
	}
	if subtle.ConstantTimeCompare(zPrime[:], rhs[:]) != 1 {
		return nil, fmt.Errorf("main initial message from cOT receiver failed to verify")
	}
	result := &Round2Output{}
	for j := 0; j < L; j++ {
		column := make([]byte, OtWidth*simplest.DigestSize)
		shake := sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := shake.Write(jBytes[:]); err != nil { // write j into hash
			return nil, errors.Wrap(err, "writing nonce into shake while computing OutputAdditiveShares in cOT sender round 2 transfer")
		}
		if _, err := shake.Write(zeta[j][:]); err != nil {
			return nil, errors.Wrap(err, "writing input zeta_j into shake while computing OutputAdditiveShares in cOT sender round 2 transfer")
		}
		if _, err := shake.Read(column[:]); err != nil {
			return nil, errors.Wrap(err, "reading shake into column while computing OutputAdditiveShares in cOT sender round 2 transfer")
		}
		var err error
		for k := 0; k < OtWidth; k++ {
			sender.OutputAdditiveShares[j][k], err = sender.curve.Scalar.SetBytes(column[k*simplest.DigestSize : (k+1)*simplest.DigestSize])
			if err != nil {
				return nil, errors.Wrap(err, "OutputAdditiveShares scalar from bytes")
			}
		}
		for i := 0; i < KappaBytes; i++ {
			zeta[j][i] ^= sender.seedOtResults.PackedRandomChoiceBits[i] // note: overwrites zeta_j. just using it as a place to store
		}
		column = make([]byte, OtWidth*simplest.DigestSize)
		shake = sha3.NewCShake256(uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := shake.Write(jBytes[:]); err != nil { // write j into hash
			return nil, errors.Wrap(err, "writing nonce into shake while computing tau in cOT sender round 2 transfer")
		}
		if _, err := shake.Write(zeta[j][:]); err != nil {
			return nil, errors.Wrap(err, "writing input zeta_j into shake while computing tau in cOT sender round 2 transfer")
		}
		if _, err := shake.Read(column[:]); err != nil {
			return nil, errors.Wrap(err, "reading shake into column while computing tau in cOT sender round 2 transfer")
		}
		for k := 0; k < OtWidth; k++ {
			result.Tau[j][k], err = sender.curve.Scalar.SetBytes(column[k*simplest.DigestSize : (k+1)*simplest.DigestSize])
			if err != nil {
				return nil, errors.Wrap(err, "scalar Tau from bytes")
			}
			result.Tau[j][k] = result.Tau[j][k].Sub(sender.OutputAdditiveShares[j][k])
			result.Tau[j][k] = result.Tau[j][k].Add(input[j][k])
		}
	}
	return result, nil
}

// Round3Transfer does the receiver (Bob)'s step 7) of Protocol 9, namely the computation of the outputs tB.
func (receiver *Receiver) Round3Transfer(round2Output *Round2Output) error {
	for j := 0; j < L; j++ {
		column := make([]byte, OtWidth*simplest.DigestSize)
		shake := sha3.NewCShake256(receiver.uniqueSessionId[:], []byte("Coinbase_DKLs_cOT"))
		jBytes := [2]byte{}
		binary.BigEndian.PutUint16(jBytes[:], uint16(j))
		if _, err := shake.Write(jBytes[:]); err != nil { // write j into hash
			return errors.Wrap(err, "writing nonce into shake while computing tB in cOT receiver round 3 transfer")
		}
		if _, err := shake.Write(receiver.psi[j][:]); err != nil {
			return errors.Wrap(err, "writing input zeta_j into shake while computing tB in cOT receiver round 3 transfer")
		}
		if _, err := shake.Read(column[:]); err != nil {
			return errors.Wrap(err, "reading shake into column while computing tB in cOT receiver round 3 transfer")
		}
		bit := int(simplest.ExtractBitFromByteVector(receiver.extendedPackedChoices[:], j))
		var err error
		for k := 0; k < OtWidth; k++ {
			receiver.OutputAdditiveShares[j][k], err = receiver.curve.Scalar.SetBytes(column[k*simplest.DigestSize : (k+1)*simplest.DigestSize])
			if err != nil {
				return errors.Wrap(err, "scalar output additive shares from bytes")
			}
			receiver.OutputAdditiveShares[j][k] = receiver.OutputAdditiveShares[j][k].Neg()
			wj0 := receiver.OutputAdditiveShares[j][k].Bytes()
			wj1 := receiver.OutputAdditiveShares[j][k].Add(round2Output.Tau[j][k]).Bytes()
			subtle.ConstantTimeCopy(bit, wj0, wj1)
			if receiver.OutputAdditiveShares[j][k], err = receiver.curve.Scalar.SetBytes(wj0); err != nil {
				return errors.Wrap(err, "scalar output additive shares from bytes")
			}
		}
	}
	return nil
}
