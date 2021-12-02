//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package ted25519

import "strconv"

type Message []byte

func (m Message) String() string {
	return string(m)
}

const signatureLength = 64

type PartialSignature struct {
	ShareIdentifier byte   // x-coordinate of which signer produced signature
	Sig             []byte // 64-byte signature: R || s
}

// NewPartialSignature creates a new PartialSignature
func NewPartialSignature(identifier byte, sig []byte) *PartialSignature {
	if l := len(sig); l != signatureLength {
		panic("ted25519: invalid partial signature length: " + strconv.Itoa(l))
	}
	return &PartialSignature{ShareIdentifier: identifier, Sig: sig}
}

// R returns the R component of the signature
func (sig *PartialSignature) R() []byte {
	return sig.Sig[:32]
}

// S returns the s component of the signature
func (sig *PartialSignature) S() []byte {
	return sig.Sig[32:]
}

func (sig *PartialSignature) Bytes() []byte {
	return sig.Sig
}

// TSign generates a signature that can later be aggregated with others to produce a signature valid
// under the provided public key and nonce pair.
func TSign(message Message, key *KeyShare, pub PublicKey, nonce *NonceShare, noncePub PublicKey) *PartialSignature {
	sig := ThresholdSign(
		reverseBytes(key.Value.Bytes()), pub,
		message,
		reverseBytes(nonce.Value.Bytes()), noncePub,
	)
	return NewPartialSignature(byte(key.ShamirShare.Identifier), sig)
}
