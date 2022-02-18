//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v0

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"io"
	"math/big"

	"github.com/coinbase/kryptology/pkg/core"
)

type (
	seedOtVerification = [kappa][32]byte
	seedOtFinal        = [kappa][2][32]byte
	seedOtTransfer     = [kappa]*curves.EcPoint
)

// seedOTSender stores state for the "sender" role in seed OT. see Protocol 7 in Appendix A of DKLs
type seedOTSender struct {
	// Exported fields are marshaled
	Rho seedOtFinal // this will store the (vectorized) outputs of kappa executions of (random) seed OT.

	// Intermediate values that should not be marshaled
	params *Params
	b      *big.Int        // discrete log of B, which will be (re)used in _all_ executions of the seed OT.
	pub    *curves.EcPoint // the public key of b.
}

// seedOTReceiver stores state for the "receiver" role in seed OT. Protocol 7, Appendix A, of DKLs.
type seedOTReceiver struct {
	// Exported fields are marshaled
	Packed [kappa >> 3]byte   // a packed version of the above vector; used later during cOT for performance reasons
	Rho    seedOtVerification // output of seed OT. for the receiver, there is just 1 output per execution

	// Unexported fields don't get marshaled
	params *Params
	choice []int              // choice vector represented as compact binary array. Initialed from Packed
	pub    *curves.EcPoint    // i guess this is "B".
	xi     seedOtVerification // basically this just has to be kept between rounds for checking purposes, but won't be used outside
}

func (sender *seedOTSender) pubKey(w io.Writer) error {
	// returns pub, as well as the schnorr proof. serialized / packed.
	// since the return type here is exactly the same as DKG datatype, i am going to cheat and reuse that one.
	enc := gob.NewEncoder(w)
	var err error // https://github.com/golang/go/issues/6842
	if sender.b, err = sender.params.Scalar.Random(); err != nil {
		return err
	}
	if sender.pub, err = curves.NewScalarBaseMult(sender.params.Curve, sender.b); err != nil {
		return err
	}
	proof := &Schnorr{params: sender.params, Pub: sender.pub}
	if err = proof.Prove(sender.b); err != nil {
		return err
	}
	if err = enc.Encode(proof); err != nil {
		return err
	}
	if sender.pub.Y, err = core.Neg(sender.pub.Y, sender.params.Curve.Params().P); err != nil { // using Weierstrass
		return err
	}
	// ^^^ this is basically a trick, we will only "use" B (i.e., pub) from this point forward by subtracting it from A
	// so just do the negation once and then we can just "add" B from this point forward.
	return err
}

func (receiver *seedOTReceiver) pubKey(r io.Reader) error {
	dec := gob.NewDecoder(r)
	var err error
	input := &Schnorr{params: receiver.params}
	if err = dec.Decode(input); err != nil {
		return err
	}
	receiver.pub = input.Pub
	if err = input.Verify(); err != nil {
		return err
	}
	return nil
}

// Initializes the choice array from the Packed array
func (receiver *seedOTReceiver) initChoice() {
	// unpack the random values in Packed into bits in Choice
	receiver.choice = make([]int, kappa)
	for i := 0; i < len(receiver.choice); i++ {
		receiver.choice[i] = int(receiver.Packed[i>>3] >> (i & 0x07) & 0x01)
	}
}

// padTransfer this is the receiver's "Pad Transfer" phase in seed OT; see p. 16 of https://eprint.iacr.org/2018/499.pdf.
// note that we "vectorize" this kappa times; all kappa executions are blocked in this function.
// any error returned by this function will come from "below", as opposed to from this function.
func (receiver *seedOTReceiver) padTransfer(w io.Writer) error {
	enc := gob.NewEncoder(w)
	// fill the seed OT choice vector with random bytes.
	if _, err := rand.Read(receiver.Packed[:]); err != nil {
		return err
	}
	// And unpack into Choice bits
	receiver.initChoice()

	result := &[kappa]*curves.EcPoint{}
	for i := 0; i < kappa; i++ {
		a, err := receiver.params.Scalar.Random()
		if err != nil {
			return err
		}
		if result[i], err = curves.NewScalarBaseMult(receiver.params.Curve, a); err != nil {
			return err
		}
		temp := result[i].Bytes()
		if result[i], err = result[i].Add(receiver.pub); err != nil {
			return err
		}
		mask := result[i].Bytes()
		subtle.ConstantTimeCopy(receiver.choice[i], temp, mask)
		if result[i], err = curves.PointFromBytesUncompressed(receiver.params.Curve, temp); err != nil {
			return err
		}
		rho, err := receiver.pub.ScalarMult(a)
		if err != nil {
			return err
		}
		receiver.Rho[i] = sha256.Sum256(append(rho.Bytes(), byte(i))) // check whether this cuts it as a "nonce"
	}
	return enc.Encode(result)
}

func (sender *seedOTSender) padTransfer(rw io.ReadWriter) error {
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	// returns the challenges xi, concated into a block.
	input := &seedOtTransfer{}
	if err := dec.Decode(input); err != nil {
		return err
	}
	result := &seedOtVerification{}

	for i := 0; i < kappa; i++ {
		d, err := input[i].ScalarMult(sender.b)
		if err != nil {
			return err
		}
		sender.Rho[i][0] = sha256.Sum256(append(d.Bytes(), byte(i)))
		if input[i], err = input[i].Add(sender.pub); err != nil {
			return err
		} // caution: overwrite
		d, err = input[i].ScalarMult(sender.b)
		if err != nil {
			return err
		}
		sender.Rho[i][1] = sha256.Sum256(append(d.Bytes(), byte(i)))
		temp0 := sha256.Sum256(sender.Rho[i][0][:])
		temp0 = sha256.Sum256(temp0[:])
		temp1 := sha256.Sum256(sender.Rho[i][1][:])
		temp1 = sha256.Sum256(temp1[:])
		for j := 0; j < 32; j++ {
			result[i][j] = temp0[j] ^ temp1[j]
		}
	}
	return enc.Encode(result)
}

// verification corresponds to initial round of the receiver's "Verification" phase, see p. 16. cf. also "final" below.
// this is just the start of verification—in this round, the receiver outputs "rho'", which the sender will check.
func (receiver *seedOTReceiver) verification(rw io.ReadWriter) error {
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	if err := dec.Decode(&receiver.xi); err != nil {
		return err
	}
	result := &seedOtVerification{}
	for i := 0; i < kappa; i++ {
		temp0 := sha256.Sum256(receiver.Rho[i][:])
		temp0 = sha256.Sum256(temp0[:])
		temp1 := [32]byte{}
		for j := 0; j < 32; j++ {
			temp1[j] = receiver.xi[i][j] ^ temp0[j]
		}
		subtle.ConstantTimeCopy(receiver.choice[i], temp0[:], temp1[:])
		copy(result[i][:], temp0[:])
	}
	return enc.Encode(result) // this is "rho'", all in a block.
}

func (sender *seedOTSender) verification(rw io.ReadWriter) error {
	// message is rho'. returns H(rho^0) || H(rho^1)
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	input := &seedOtVerification{}
	if err := dec.Decode(&input); err != nil {
		return err
	}
	result := &seedOtFinal{}
	for i := 0; i < kappa; i++ {
		temp0 := sha256.Sum256(sender.Rho[i][0][:])
		temp1 := sha256.Sum256(temp0[:])
		if subtle.ConstantTimeCompare(temp1[:], input[i][:]) != 1 {
			return fmt.Errorf("receiver's challenge response didn't match H(H(rho^0))")
		}
		temp2 := sha256.Sum256(sender.Rho[i][1][:])
		copy(result[i][0][:], temp0[:])
		copy(result[i][1][:], temp2[:])
	}
	return enc.Encode(result)
}

// final this is the _last_ part of the "Verification" phase of seed OT; see p. 16 of https://eprint.iacr.org/2018/499.pdf.
// message is (supposedly) the concatenation of all kappa `H(rho^0) || H(rho^1)`s; we will check them ourselves.
func (receiver *seedOTReceiver) final(r io.Reader) error {
	dec := gob.NewDecoder(r)
	input := &seedOtFinal{}
	if err := dec.Decode(&input); err != nil {
		return err
	}
	for i := 0; i < kappa; i++ {
		temp0 := sha256.Sum256(receiver.Rho[i][:])
		temp1 := [32]byte{}
		subtle.ConstantTimeCopy(1-receiver.choice[i], temp1[:], input[i][0][:])
		subtle.ConstantTimeCopy(receiver.choice[i], temp1[:], input[i][1][:])
		if subtle.ConstantTimeCompare(temp0[:], temp1[:]) != 1 {
			return fmt.Errorf("sender's supposed H(rho^omega) doesn't match our own")
		}
		temp0 = sha256.Sum256(input[i][0][:])
		temp1 = sha256.Sum256(input[i][1][:])
		for j := 0; j < 32; j++ {
			temp0[j] ^= temp1[j]
		}
		if subtle.ConstantTimeCompare(temp0[:], receiver.xi[i][:]) != 1 {
			return fmt.Errorf("sender's openings H(rho^0) and H(rho^1) didn't decommit to its prior message xi")
		}
	}
	return nil
}

func (receiver *seedOTReceiver) kosSetup(rw io.ReadWriter) error {
	// this is an illustrative high-level helper method which goes through the full flow of the KOS seed OT protocol.
	// all it does it call all the right stages in the right order, and send and receive the messages to the other party
	if err := receiver.pubKey(rw); err != nil {
		return err
	}
	if err := receiver.padTransfer(rw); err != nil {
		return err
	}
	if err := receiver.verification(rw); err != nil {
		return err
	}
	return receiver.final(rw)
}

func (sender *seedOTSender) kosSetup(rw io.ReadWriter) error {
	// again a high-level helper method showing the overall flow, this time for the sender.
	if err := sender.pubKey(rw); err != nil {
		return err
	}
	if err := sender.padTransfer(rw); err != nil {
		return err
	}
	return sender.verification(rw)
}

type cOTReceiver struct {
	sender       *seedOTSender      // kinda-sorta reversed?!?
	w            []byte             // storage for choice vector || gamma^{ext}, packed.
	psi          [][kappa >> 3]byte // transpose of v^0. gets retained between messages
	tB           []*big.Int         // [2 * Multiplicity]*big.Int
	tBOT         [2 * s][]*big.Int  // [2 * s][Multiplicity]*big.Int
	l            int
	lPrime       int
	multiplicity int
}

type cOTSender struct {
	receiver     *seedOTReceiver   // kinda-sorta reversed?!?
	tA           []*big.Int        // ultimate output received. basically just the "pads"
	tAOT         [2 * s][]*big.Int // [2 * s][Multiplicity]*big.Int
	l            int
	lPrime       int
	multiplicity int
}

func newCOTReceiver(multiplicity int, sender *seedOTSender) *cOTReceiver {
	l := 2*multiplicity*kappa + 2*s
	lPrime := l + kappaOT
	var tBOT [2 * s][]*big.Int
	for i := 0; i < 2*s; i++ {
		tBOT[i] = make([]*big.Int, multiplicity)
	}
	return &cOTReceiver{
		sender:       sender,
		w:            make([]byte, lPrime>>3),
		psi:          make([][kappa >> 3]byte, lPrime),
		tB:           make([]*big.Int, 2*kappa*multiplicity),
		tBOT:         tBOT,
		l:            l,
		lPrime:       lPrime,
		multiplicity: multiplicity,
	}
}

func newCOTSender(multiplicity int, receiver *seedOTReceiver) *cOTSender {
	l := 2*multiplicity*kappa + 2*s
	lPrime := l + kappaOT
	var tAOT [2 * s][]*big.Int
	for i := 0; i < 2*s; i++ {
		tAOT[i] = make([]*big.Int, multiplicity)
	}
	return &cOTSender{
		receiver:     receiver,
		tA:           make([]*big.Int, 2*kappa*multiplicity),
		tAOT:         tAOT,
		l:            l,
		lPrime:       lPrime,
		multiplicity: multiplicity,
	}
}

type cOTInitStorage struct {
	WPrime [32]byte
	VPrime [32]byte
	U      [kappa][]byte
}

type cOTStorage struct {
	TauMain []*big.Int
	TauOT   [2 * s][]*big.Int
}

func (receiver *cOTReceiver) init(idExt [32]byte, choice []byte, w io.Writer) error {
	// input choice vector is "packed".
	copy(receiver.w[0:receiver.l>>3], choice[:])                     // write the input choice vector into our local data.
	if _, err := rand.Read(receiver.w[receiver.l>>3:]); err != nil { // fill the rest with random bytes; this is "gamma^{ext}"
		return err
	}
	hash := sha256.New()    // basically this will contain a hash of the matrix U.
	v := [2][kappa][]byte{} // kappa * l array of _bits_, in "dense" form. contains _both_ v_0 and v_1.
	for i := 0; i < 2; i++ {
		for j := 0; j < kappa; j++ {
			v[i][j] = make([]byte, receiver.lPrime>>3) // annoying
		}
	}
	result := &cOTInitStorage{}
	enc := gob.NewEncoder(w)
	for i := 0; i < kappa; i++ {
		result.U[i] = make([]byte, receiver.lPrime>>3)
	}
	hash.Reset()
	for i := 0; i < kappa; i++ {
		for j := 0; j < 2; j++ {
			row, err := core.ExpandMessageXmd(sha256.New, receiver.sender.Rho[i][j][:], idExt[:], receiver.lPrime>>3)
			if err != nil {
				return err
			}
			// this is the core pseudorandom expansion of the secret OT input seeds s_i^0 and s_i^1
			// see Extension, 2), in Protocol 9, page 17 of DKLs https://eprint.iacr.org/2018/499.pdf
			// use the idExt as the "domain separator", and the _secret_ seed rho as the input!
			copy(v[j][i][:], row) // could easily use a shake3 and "Read" it directly in.
		}
		for j := 0; j < receiver.lPrime>>3; j++ {
			result.U[i][j] = v[0][i][j] ^ v[1][i][j] ^ receiver.w[j]
			// U := v_i^0 ^ v_i^1 ^ w. note: in step 4) of Prot. 9, i think `w` should be bolded?
			for k := 0; k < 8; k++ {
				receiver.psi[j<<3+k][i>>3] |= v[0][i][j] >> k & 0x01 << (i & 0x07)
				// this is fairly tricky. basically, this is assigning psi to be the transpose of the boolean matrix v_0.
				// but because both matrices are densely packed (represented as bytes), we have to do some bitwise tricks.
			}
		}
		if _, err := hash.Write(result.U[i][:]); err != nil {
			return err
		}
	}
	digest := hash.Sum(nil) // go ahead and record this, so that we only have to hash the big matrix U once.
	for j := 0; j < receiver.lPrime; j++ {
		chiJ := sha256.Sum256(append(digest, byte(j&0x07), byte(j>>3))) // represent j = (j % 8, j // 8) as 2 bytes.
		wJ := receiver.w[j>>3] >> (j & 0x07) & 0x01                     // extract j^th bit from vector of bytes w.
		wJ = ^(wJ - 0x01)                                               // convert it into a bitmask (all 1s if true, all 0s if false).
		for k := 0; k < kappa>>3; k++ {
			result.WPrime[k] ^= wJ & chiJ[k]
			result.VPrime[k] ^= receiver.psi[j][k] & chiJ[k]
		}
	}
	// result is the concatenation of WPrime, VPrime, then the entire matrix U (row-flattened).
	return enc.Encode(result)
}

func (sender *cOTSender) transfer(idExt [32]byte, inputMain []*big.Int, inputOT [2 * s][]*big.Int, rw io.ReadWriter) error {
	// input message: Bob's values WPrime, VPrime, and U. output: tau.
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	input := &cOTInitStorage{}
	if err := dec.Decode(input); err != nil {
		return err
	}
	z := [kappa][]byte{}
	for i := 0; i < kappa; i++ {
		z[i] = make([]byte, sender.lPrime>>3)
	}
	zeta := make([][kappa >> 3]byte, sender.lPrime)
	hash := sha256.New() // basically this will contain a hash of the matrix U.

	// Unpack the random bytes in Packed into the choice array in the receiver
	sender.receiver.initChoice()

	for i := 0; i < kappa; i++ {
		row, err := core.ExpandMessageXmd(sha256.New, sender.receiver.Rho[i][:], idExt[:], sender.lPrime>>3)
		if err != nil {
			return err
		}
		// use the idExt as the domain separator, and the _secret_ seed rho as the input!
		v := make([]byte, sender.lPrime>>3) // we only need to retain one row of v at a time.
		copy(v[:], row)
		mask := byte(^(sender.receiver.choice[i] - 1))
		for j := 0; j < sender.lPrime>>3; j++ {
			z[i][j] = v[j] ^ mask&input.U[i][j]
			// U := v_i^0 ^ v_i^1 ^ w. note: in step 4) of Prot. 9, i think `w` should be bolded?
			for k := 0; k < 8; k++ {
				zeta[j<<3+k][i>>3] |= z[i][j] >> k & 0x01 << (i & 0x07)
				// assigning to zeta the matrix transposition of z. see notes above.
			}
		}
		if _, err = hash.Write(input.U[i][:]); err != nil {
			return err
		}
	}
	digest := hash.Sum(nil) // go ahead and record this, so that we only have to hash the big matrix U once.
	zPrime := [32]byte{}
	for j := 0; j < sender.lPrime; j++ {
		chiJ := sha256.Sum256(append(digest, byte(j&0x07), byte(j>>3))) // represent j = (j % 8, j // 8) as 2 bytes.
		for k := 0; k < kappa>>3; k++ {
			zPrime[k] ^= zeta[j][k] & chiJ[k]
		}
	}
	rhs := [32]byte{}
	for i := 0; i < 32; i++ {
		rhs[i] = input.VPrime[i] ^ sender.receiver.Packed[i]&input.WPrime[i]
	}
	if subtle.ConstantTimeCompare(zPrime[:], rhs[:]) != 1 {
		return fmt.Errorf("receiver's initial cOT message failed to verify")
	}
	result := &cOTStorage{}
	result.TauMain = make([]*big.Int, 2*kappa*sender.multiplicity)
	for j := 0; j < 2*kappa*sender.multiplicity; j++ {
		column := sha256.Sum256(append(zeta[j][:], byte(j&0x07), byte(j>>3)))
		sender.tA[j] = new(big.Int).SetBytes(column[:]) // not bothering to mod this. shouldn't be necessary.
		for i := 0; i < 32; i++ {
			zeta[j][i] ^= sender.receiver.Packed[i] // warning: overwrites zeta_j!!!!!! just using it as a place to store
		}
		column = sha256.Sum256(append(zeta[j][:], byte(j&0x07), byte(j>>3)))
		result.TauMain[j] = new(big.Int).SetBytes(column[:])
		result.TauMain[j] = sender.receiver.params.Scalar.Sub(result.TauMain[j], sender.tA[j])
		result.TauMain[j] = sender.receiver.params.Scalar.Add(result.TauMain[j], inputMain[j])
	}
	length := 32 * sender.multiplicity
	for j := 0; j < 2*s; j++ {
		result.TauOT[j] = make([]*big.Int, sender.multiplicity)
		column, err := core.ExpandMessageXmd(sha256.New, append(zeta[2*kappa*sender.multiplicity+j][:], byte(j&0x07), byte(j>>3)), []byte("Coinbase_tECDSA"), length)
		if err != nil {
			return err
		}
		for k := 0; k < sender.multiplicity; k++ {
			sender.tAOT[j][k] = new(big.Int).SetBytes(column[k*32 : (k+1)*32]) // not bothering to mod this. shouldn't be necessary.
		}
		for i := 0; i < 32; i++ {
			zeta[2*kappa*sender.multiplicity+j][i] ^= sender.receiver.Packed[i] // warning: overwrites zeta_j!!!!!! just using it as a place to store
		}
		column, err = core.ExpandMessageXmd(sha256.New, append(zeta[2*kappa*sender.multiplicity+j][:], byte(j&0x07), byte(j>>3)), []byte("Coinbase_tECDSA"), length)
		if err != nil {
			return err
		}
		for k := 0; k < sender.multiplicity; k++ {
			result.TauOT[j][k] = new(big.Int).SetBytes(column[k*32 : (k+1)*32])
			result.TauOT[j][k] = sender.receiver.params.Scalar.Sub(result.TauOT[j][k], sender.tAOT[j][k])
			result.TauOT[j][k] = sender.receiver.params.Scalar.Add(result.TauOT[j][k], inputOT[j][k])
		}
	}
	return enc.Encode(result)
}

func (receiver *cOTReceiver) transfer(r io.Reader) error {
	dec := gob.NewDecoder(r)
	input := &cOTStorage{}
	if err := dec.Decode(input); err != nil {
		return err
	}
	for j := 0; j < 2*kappa*receiver.multiplicity; j++ {
		column := sha256.Sum256(append(receiver.psi[j][:], byte(j&0x07), byte(j>>3)))
		bit := int(receiver.w[j>>3]) >> (j & 0x07) & 0x01
		receiver.tB[j] = new(big.Int).SetBytes(column[:])
		receiver.tB[j] = receiver.sender.params.Scalar.Neg(receiver.tB[j])
		wj0 := receiver.sender.params.Scalar.Bytes(receiver.tB[j])
		wj1 := receiver.sender.params.Scalar.Bytes(receiver.sender.params.Scalar.Add(receiver.tB[j], input.TauMain[j]))
		subtle.ConstantTimeCopy(bit, wj0, wj1)
		receiver.tB[j].SetBytes(wj0)
	}
	length := 32 * receiver.multiplicity
	for j := 0; j < 2*s; j++ {
		column, err := core.ExpandMessageXmd(sha256.New, append(receiver.psi[2*kappa*receiver.multiplicity+j][:], byte(j&0x07), byte(j>>3)), []byte("Coinbase_tECDSA"), length)
		if err != nil {
			return err
		}
		bit := int(receiver.w[(2*kappa*receiver.multiplicity+j)>>3]) >> (j & 0x07) & 0x01
		for k := 0; k < receiver.multiplicity; k++ {
			receiver.tBOT[j][k] = new(big.Int).SetBytes(column[k*32 : (k+1)*32])
			receiver.tBOT[j][k] = receiver.sender.params.Scalar.Neg(receiver.tBOT[j][k])
			wj0 := receiver.sender.params.Scalar.Bytes(receiver.tBOT[j][k])
			wj1 := receiver.sender.params.Scalar.Bytes(receiver.sender.params.Scalar.Add(receiver.tBOT[j][k], input.TauOT[j][k]))
			subtle.ConstantTimeCopy(bit, wj0, wj1)
			receiver.tBOT[j][k].SetBytes(wj0)
		}
	}
	return nil
}

func (receiver *cOTReceiver) cOT(idExt [32]byte, choice []byte, rw io.ReadWriter) error {
	if err := receiver.init(idExt, choice, rw); err != nil {
		return err
	}
	return receiver.transfer(rw)
}

func (sender *cOTSender) cOT(idExt [32]byte, input []*big.Int, inputOT [2 * s][]*big.Int, rw io.ReadWriter) error {
	return sender.transfer(idExt, input, inputOT, rw)
}
