//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/blake2b"
	"io"
)

const version = 0xcb
const nonZeroCurvePointVersion = 0x01
const isCompressed = 0x01

// PublicKey is the verification key
type PublicKey struct {
	value *curves.Ep
}

// GenerateAddress converts the public key to an address
func (pk PublicKey) GenerateAddress() string {

	var payload [40]byte
	payload[0] = version
	payload[1] = nonZeroCurvePointVersion
	payload[2] = isCompressed

	buffer := pk.value.ToAffineUncompressed()
	copy(payload[3:35], buffer[:32])
	payload[35] = buffer[32] & 1
	hash1 := sha256.Sum256(payload[:36])
	hash2 := sha256.Sum256(hash1[:])
	copy(payload[36:40], hash2[:4])
	return base58.Encode(payload[:])
}

// ParseAddress converts a given string into a public key returning an error on failure
func (pk *PublicKey) ParseAddress(b58 string) error {
	buffer := base58.Decode(b58)
	if len(buffer) != 40 {
		return fmt.Errorf("invalid byte sequence")
	}
	if buffer[0] != version {
		return fmt.Errorf("invalid version")
	}
	if buffer[1] != nonZeroCurvePointVersion {
		return fmt.Errorf("invalid non-zero curve point version")
	}
	if buffer[2] != isCompressed {
		return fmt.Errorf("invalid compressed flag")
	}
	hash1 := sha256.Sum256(buffer[:36])
	hash2 := sha256.Sum256(hash1[:])
	if subtle.ConstantTimeCompare(hash2[:4], buffer[36:40]) != 1 {
		return fmt.Errorf("invalid checksum")
	}
	x := buffer[3:35]
	x[31] |= buffer[35] << 7
	value, err := new(curves.Ep).FromAffineCompressed(x)
	if err != nil {
		return err
	}
	pk.value = value
	return nil
}

func (pk PublicKey) MarshalBinary() ([]byte, error) {
	return pk.value.ToAffineCompressed(), nil
}

func (pk *PublicKey) UnmarshalBinary(input []byte) error {
	pt, err := new(curves.Ep).FromAffineCompressed(input)
	if err != nil {
		return err
	}
	pk.value = pt
	return nil
}

func (pk *PublicKey) SetPointPallas(pallas *curves.PointPallas) {
	pk.value = pallas.GetEp()
}

// SecretKey is the signing key
type SecretKey struct {
	value *fq.Fq
}

// GetPublicKey returns the corresponding verification
func (sk SecretKey) GetPublicKey() *PublicKey {
	pk := new(curves.Ep).Mul(new(curves.Ep).Generator(), sk.value)
	return &PublicKey{pk}
}

func (sk SecretKey) MarshalBinary() ([]byte, error) {
	t := sk.value.Bytes()
	return t[:], nil
}

func (sk *SecretKey) UnmarshalBinary(input []byte) error {
	if len(input) != 32 {
		return fmt.Errorf("invalid byte sequence")
	}
	var buf [32]byte
	copy(buf[:], input)
	value, err := new(fq.Fq).SetBytes(&buf)
	if err != nil {
		return err
	}
	sk.value = value
	return nil
}

func (sk *SecretKey) SetFq(fq *fq.Fq) {
	sk.value = fq
}

// NewKeys creates a new keypair using a CSPRNG
func NewKeys() (*PublicKey, *SecretKey, error) {
	return NewKeysFromReader(crand.Reader)
}

// NewKeysFromReader creates a new keypair using the specified reader
func NewKeysFromReader(reader io.Reader) (*PublicKey, *SecretKey, error) {
	t := new(curves.ScalarPallas).Random(reader)
	sc, ok := t.(*curves.ScalarPallas)
	if !ok || t.IsZero() {
		return nil, nil, fmt.Errorf("invalid key")
	}
	sk := sc.GetFq()
	pk := new(curves.Ep).Mul(new(curves.Ep).Generator(), sk)
	if pk.IsIdentity() {
		return nil, nil, fmt.Errorf("invalid key")
	}

	return &PublicKey{pk}, &SecretKey{sk}, nil
}

// SignTransaction generates a signature over the specified txn and network id
// See https://github.com/MinaProtocol/c-reference-signer/blob/master/crypto.c#L1020
func (sk *SecretKey) SignTransaction(transaction *Transaction) (*Signature, error) {
	input := new(roinput).Init(3, 75)
	transaction.addRoInput(input)
	return sk.finishSchnorrSign(input, transaction.NetworkId)
}

// SignMessage signs a _string_. this is somewhat non-standard; we do it by just adding bytes to the roinput.
// See https://github.com/MinaProtocol/c-reference-signer/blob/master/crypto.c#L1020
func (sk *SecretKey) SignMessage(message string) (*Signature, error) {
	input := new(roinput).Init(0, len(message))
	input.AddBytes([]byte(message))
	return sk.finishSchnorrSign(input, MainNet)
}

func (sk *SecretKey) finishSchnorrSign(input *roinput, networkId NetworkType) (*Signature, error) {
	if sk.value.IsZero() {
		return nil, fmt.Errorf("invalid secret key")
	}
	pk := sk.GetPublicKey()
	k := sk.msgDerive(input, pk, networkId)
	if k.IsZero() {
		return nil, fmt.Errorf("invalid nonce generated")
	}
	// r = k*G
	r := new(curves.Ep).Generator()
	r.Mul(r, k)

	if r.Y().IsOdd() {
		k.Neg(k)
	}
	rx := r.X()
	e := msgHash(pk, rx, input, ThreeW, networkId)

	// S = k + e*sk
	e.Mul(e, sk.value)
	s := new(fq.Fq).Add(k, e)
	if rx.IsZero() || s.IsZero() {
		return nil, fmt.Errorf("invalid signature")
	}
	return &Signature{
		R: rx,
		S: s,
	}, nil
}

// VerifyTransaction checks if the signature is over the given transaction using this public key
func (pk *PublicKey) VerifyTransaction(sig *Signature, transaction *Transaction) error {
	input := new(roinput).Init(3, 75)
	transaction.addRoInput(input)
	return pk.finishSchnorrVerify(sig, input, transaction.NetworkId)
}

// VerifyMessage checks if the claimed signature on a _string_ is valid. this is nonstandard; see above.
func (pk *PublicKey) VerifyMessage(sig *Signature, message string) error {
	input := new(roinput).Init(0, len(message))
	input.AddBytes([]byte(message))
	return pk.finishSchnorrVerify(sig, input, MainNet)
}

func (pk *PublicKey) finishSchnorrVerify(sig *Signature, input *roinput, networkId NetworkType) error {
	if pk.value.IsIdentity() {
		return fmt.Errorf("invalid public key")
	}
	if sig.R.IsZero() || sig.S.IsZero() {
		return fmt.Errorf("invalid signature")
	}
	e := msgHash(pk, sig.R, input, ThreeW, networkId)
	sg := new(curves.Ep).Generator()
	sg.Mul(sg, sig.S)

	epk := new(curves.Ep).Mul(pk.value, e)
	epk.Neg(epk)

	r := new(curves.Ep).Add(sg, epk)
	if !r.Y().IsOdd() && r.X().Equal(sig.R) {
		return nil
	} else {
		return fmt.Errorf("signature verification failed")
	}
}

func msgHash(pk *PublicKey, rx *fp.Fp, input *roinput, hashType Permutation, networkId NetworkType) *fq.Fq {
	input.AddFp(pk.value.X())
	input.AddFp(pk.value.Y())
	input.AddFp(rx)

	ctx := new(Context).Init(hashType, networkId)
	fields := input.Fields()
	ctx.Update(fields)
	return ctx.Digest()
}

func (sk SecretKey) msgDerive(msg *roinput, pk *PublicKey, networkId NetworkType) *fq.Fq {
	input := msg.Clone()
	input.AddFp(pk.value.X())
	input.AddFp(pk.value.Y())
	input.AddFq(sk.value)
	input.AddBytes([]byte{byte(networkId)})
	inputBytes := input.Bytes()

	h, _ := blake2b.New(32, []byte{})
	_, _ = h.Write(inputBytes)
	hash := h.Sum(nil)

	// Clear top two bits
	hash[31] &= 0x3F
	tmp := [4]uint64{
		binary.LittleEndian.Uint64(hash[:8]),
		binary.LittleEndian.Uint64(hash[8:16]),
		binary.LittleEndian.Uint64(hash[16:24]),
		binary.LittleEndian.Uint64(hash[24:32]),
	}
	return new(fq.Fq).SetRaw(&tmp)
}
