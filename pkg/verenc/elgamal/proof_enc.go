//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	crand "crypto/rand"
	"fmt"
	"git.sr.ht/~sircmpwn/go-bare"
	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

// ProofVerEnc is a proof of verifiable encryption for a discrete log
type ProofVerEnc struct {
	challenge, schnorr1, schnorr2 curves.Scalar
}

type proofMarshal struct {
	Challenge []byte `bare:"challenge"`
	Schnorr1  []byte `bare:"schnorr1"`
	Schnorr2  []byte `bare:"schnorr2"`
	Curve     string `bare:"curve"`
}

func (pf ProofVerEnc) MarshalBinary() ([]byte, error) {
	tv := new(proofMarshal)
	tv.Challenge = pf.challenge.Bytes()
	tv.Schnorr1 = pf.schnorr1.Bytes()
	tv.Schnorr2 = pf.schnorr2.Bytes()
	tv.Curve = pf.challenge.Point().CurveName()

	return bare.Marshal(tv)
}

func (pf *ProofVerEnc) UnmarshalBinary(data []byte) error {
	tv := new(proofMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	curve := curves.GetCurveByName(tv.Curve)

	challenge, err := curve.Scalar.SetBytes(tv.Challenge)
	if err != nil {
		return err
	}
	schnorr1, err := curve.Scalar.SetBytes(tv.Schnorr1)
	if err != nil {
		return err
	}
	schnorr2, err := curve.Scalar.SetBytes(tv.Schnorr2)
	if err != nil {
		return err
	}

	pf.challenge = challenge
	pf.schnorr1 = schnorr1
	pf.schnorr2 = schnorr2

	return nil
}

// VerifiableEncrypt a message using El-Gamal. This also functions as an ECIES
// encryption algorithm. The advantage here is proofs can be made about the
// ciphertext versus plain ECIES if desired and/or linked to external proofs.
func (ek EncryptionKey) VerifiableEncrypt(msg []byte, params *EncryptParams) (*CipherText, *ProofVerEnc, error) {
	var err error
	var proof *ProofVerEnc
	var cipherText *CipherText
	var h curves.Point

	if msg == nil {
		return nil, nil, internal.ErrNilArguments
	}
	if params.Blinding == nil {
		params.Blinding = ek.Value.Scalar().Random(crand.Reader)
		for params.Blinding.IsZero() {
			params.Blinding = ek.Value.Scalar().Random(crand.Reader)
		}
	} else if params.Blinding.IsZero() {
		return nil, nil, internal.ErrZeroValue
	}

	cnonce := ek.genNonce()
	if cnonce == nil {
		return nil, nil, fmt.Errorf("unable to generate nonce")
	}

	if params.Domain == nil {
		// With no domain, the generator is used as h
		h = ek.Value.Generator()
	} else {
		// If domain is provided, calculate h using domain as part of the input, then encrypt
		genBytes := append(params.Domain, ek.Value.ToAffineUncompressed()...)
		genBytes = append(genBytes, cnonce...)
		h = ek.Value.Hash(genBytes)
	}

	cipherText, err = ek.encryptWithRandNonce(msg, params.MessageIsHashed, params.Blinding, h, cnonce)
	if err != nil {
		return nil, nil, err
	}

	if params.GenProof {
		if params.ProofNonce == nil {
			return nil, nil, internal.ErrNilArguments
		}
		proof, err = ek.genProof(params.ProofNonce, msg, params.MessageIsHashed, cipherText, params.Blinding, h)
		if err != nil {
			return nil, nil, err
		}
	}
	return cipherText, proof, nil
}

func (ek EncryptionKey) genProof(nonce, msg []byte, msgIsHashed bool, cipherText *CipherText, blinding curves.Scalar, h curves.Point) (*ProofVerEnc, error) {
	r := ek.Value.Scalar().Random(crand.Reader)
	// R1 = r * G
	r1 := ek.Value.Generator().Mul(r)
	// R2 = r * Q + b * H
	r2 := ek.Value.Mul(r).Add(h.Mul(blinding))

	challengeBytes := append(cipherText.C1.ToAffineCompressed(), cipherText.C2.ToAffineCompressed()...)
	challengeBytes = append(challengeBytes, r1.ToAffineCompressed()...)
	challengeBytes = append(challengeBytes, r2.ToAffineCompressed()...)
	challengeBytes = append(challengeBytes, nonce...)
	challenge := ek.Value.Scalar().Hash(challengeBytes)
	// b - cm
	var msgScalar curves.Scalar
	var err error
	msgScalar = r.New(0)
	if msgIsHashed {
		msgScalar, err = msgScalar.SetBytes(msg)
		if err != nil {
			return nil, err
		}
	} else {
		msgScalar = msgScalar.Hash(msg)
	}
	schnorr1 := blinding.Sub(challenge.Mul(msgScalar))
	// r - cb
	schnorr2 := r.Sub(challenge.Mul(blinding))
	return &ProofVerEnc{challenge, schnorr1, schnorr2}, nil
}

// VerifyDomainEncryptProof a Proof of Verifiable Encryption
// that was generated with EncryptDomainAndProve or
// EncryptDomainAndProveBlinding.
func (ek EncryptionKey) VerifyDomainEncryptProof(nonce []byte, ciphertext *CipherText, proof *ProofVerEnc) error {
	if ciphertext == nil || proof == nil {
		return internal.ErrNilArguments
	}
	if proof.challenge == nil || proof.schnorr1 == nil || proof.schnorr2 == nil {
		return internal.ErrNilArguments
	}
	if ciphertext.C1 == nil || ciphertext.C2 == nil {
		return internal.ErrNilArguments
	}

	genBytes := append(nonce, ek.Value.ToAffineUncompressed()...)
	genBytes = append(genBytes, ciphertext.Nonce[:]...)
	h := ek.Value.Hash(genBytes)
	return ek.verify(nonce, ciphertext, proof, h)
}

// VerifyEncryptProof a Proof of Verifiable Encryption
// that was generated with EncryptAndProve or
// EncryptAndProveBlinding
func (ek EncryptionKey) VerifyEncryptProof(nonce []byte, ciphertext *CipherText, proof *ProofVerEnc) error {
	if ciphertext == nil || proof == nil {
		return internal.ErrNilArguments
	}
	if proof.challenge == nil || proof.schnorr1 == nil || proof.schnorr2 == nil {
		return internal.ErrNilArguments
	}
	if ciphertext.C1 == nil || ciphertext.C2 == nil {
		return internal.ErrNilArguments
	}

	h := ek.Value.Generator()
	return ek.verify(nonce, ciphertext, proof, h)
}

func (ek EncryptionKey) verify(nonce []byte, ciphertext *CipherText, proof *ProofVerEnc, h curves.Point) error {
	// Reconstruct R1
	// R1 = c * C1 + schnorr2 * G = c * ( b * G ) + (r - cb) * G
	// = (cb + r - cb) * G = r * G
	r1 := ciphertext.C1.Mul(proof.challenge).Add(ek.Value.Generator().Mul(proof.schnorr2))
	// Reconstruct R2
	// R2 = c * C2 + schnorr2 * Q + schnorr1 * H =
	// c * (b * Q + m * H) + (r - cb) * Q + (b - cm) * H =
	// (cb + r - cb) * Q + (cm + b - cm) * H =
	// r * Q + b * H
	r2 := ciphertext.C2.Mul(proof.challenge).Add(ek.Value.Mul(proof.schnorr2)).Add(h.Mul(proof.schnorr1))

	challengeBytes := append(ciphertext.C1.ToAffineCompressed(), ciphertext.C2.ToAffineCompressed()...)
	challengeBytes = append(challengeBytes, r1.ToAffineCompressed()...)
	challengeBytes = append(challengeBytes, r2.ToAffineCompressed()...)
	challengeBytes = append(challengeBytes, nonce...)
	challenge := proof.challenge.Hash(challengeBytes)

	if challenge.Cmp(proof.challenge) == 0 {
		return nil
	}
	return fmt.Errorf("invalid ciphertext")
}
