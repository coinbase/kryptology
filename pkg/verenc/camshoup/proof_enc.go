//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"fmt"
	"math/big"

	"git.sr.ht/~sircmpwn/go-bare"
	"github.com/coinbase/kryptology/internal"
	mod "github.com/coinbase/kryptology/pkg/core"
)

// ProofVerEnc is a proof of verifiable encryption for a discrete log
type ProofVerEnc struct {
	challenge, r *big.Int
	m            []*big.Int
}

type proofMarshal struct {
	M         [][]byte `bare:"m"`
	R         []byte   `bare:"r"`
	Challenge []byte   `bare:"challenge"`
}

func (pf ProofVerEnc) MarshalBinary() ([]byte, error) {
	tv := new(proofMarshal)
	tv.R = pf.r.Bytes()
	tv.Challenge = pf.challenge.Bytes()
	tv.M = make([][]byte, len(pf.m))
	for i, m := range pf.m {
		tv.M[i] = m.Bytes()
	}

	return bare.Marshal(tv)
}

func (pf *ProofVerEnc) UnmarshalBinary(data []byte) error {
	tv := new(proofMarshal)
	err := bare.Unmarshal(data, tv)
	if err != nil {
		return err
	}
	pf.r = new(big.Int).SetBytes(tv.R)
	pf.challenge = new(big.Int).SetBytes(tv.Challenge)
	pf.m = make([]*big.Int, len(tv.M))
	for i, m := range tv.M {
		pf.m[i] = new(big.Int).SetBytes(m)
	}
	return nil
}

// EncryptAndProve is a NIZK where the ciphertext and commitments are computed (t values).
// The blindings are generated as part of calling this function
// Return ciphertext and proof created during encryption.
// "The protocol" from section 5.2 in <https://shoup.net/papers/verenc.pdf>
// Not using t = g^m*h^s as the idemix protocol does not use it.
// Guess is that since the knowledge of m is proved in the credential attribute proving protocol.
// Use this function if the proof is by itself and not part of a bigger composite proof.
func (ek EncryptionKey) EncryptAndProve(nonce []byte, msgs []*big.Int) (*CipherText, *ProofVerEnc, error) {
	var err error
	blindings := make([]*big.Int, len(msgs))
	for i := 0; i < len(blindings); i++ {
		blindings[i], err = ek.group.RandForEncrypt()
		if err != nil {
			return nil, nil, err
		}
	}
	return ek.EncryptAndProveBlindings(nonce, msgs, blindings)
}

// EncryptAndProveBlindings is a NIZK where the ciphertext and commitments are computed (t values).
// The blindings are generated prior to calling this function
// Return ciphertext and proof created during encryption.
// "The protocol" from section 5.2 in <https://shoup.net/papers/verenc.pdf>
// Not using t = g^m*h^s as the idemix protocol does not use it.
// Guess is that since the knowledge of m is proved in the credential attribute proving protocol.
// Use this function if the proof will be part of more proofs.
func (ek EncryptionKey) EncryptAndProveBlindings(nonce []byte, msgs []*big.Int, blindings []*big.Int) (*CipherText, *ProofVerEnc, error) {
	if len(msgs) != len(blindings) {
		return nil, nil, fmt.Errorf("number of messages %d != number of blindings %d", len(msgs), len(blindings))
	}
	if len(msgs) > len(ek.y1) {
		return nil, nil, fmt.Errorf("number of messages %d is more than supported by this key %d", len(msgs), len(ek.y1))
	}
	for i, b := range blindings {
		if b == nil {
			return nil, nil, internal.ErrNilArguments
		}
		if msgs[i] == nil {
			return nil, nil, internal.ErrNilArguments
		}
		if b.Cmp(mod.Zero) == 0 {
			return nil, nil, internal.ErrZeroValue
		}
	}

	r, err := ek.group.RandForEncrypt()
	if err != nil {
		return nil, nil, err
	}

	rBlinding, err := ek.group.RandForEncrypt()
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := ek.encryptWithR(nonce, msgs, r)
	if err != nil {
		return nil, nil, err
	}
	hs, err := ek.group.Hash(ciphertext.u, ciphertext.e, nonce)
	if err != nil {
		return nil, nil, err
	}
	ciphertextTValues, err := ek.ciphertextTestValues(rBlinding, hs, blindings)
	if err != nil {
		return nil, nil, err
	}

	challenge, err := ek.fiatShamir(nonce, ciphertext, ciphertextTValues)
	if err != nil {
		return nil, nil, err
	}

	// generate the schnorr proofs
	rHat := ek.schnorr(rBlinding, challenge, r)
	mHat := make([]*big.Int, len(msgs))
	for i, m := range msgs {
		mHat[i] = ek.schnorr(blindings[i], challenge, m)
	}

	return ciphertext, &ProofVerEnc{
		challenge: challenge,
		r:         rHat,
		m:         mHat,
	}, nil
}

// ciphertextTestValues computes commitments for the ciphertext when proving encryption is correct
func (ek EncryptionKey) ciphertextTestValues(r, hash *big.Int, msgs []*big.Int) (*CipherText, error) {
	twoR := new(big.Int).Lsh(r, 1)
	twoMsgs := make([]*big.Int, len(msgs))
	for i, m := range msgs {
		twoMsgs[i] = new(big.Int).Lsh(m, 1)
	}
	u := ek.computeU(twoR)
	e := ek.computeE(twoMsgs, twoR)
	v := ek.computeV(twoR, hash, false)
	return &CipherText{u, v, e}, nil
}

// fiatShamir computes h(n, g, Y2, Y3, Y1, C.U, C.V, C.E, CT.U, CT.V, CT.E)
func (ek EncryptionKey) fiatShamir(nonce []byte, ciphertext *CipherText, ciphertextTValues *CipherText) (*big.Int, error) {
	hValues := make([][]byte, len(ciphertext.e)+len(ciphertextTValues.e)+len(ek.y1)+9)
	hValues[0] = ek.group.n.Bytes()
	hValues[1] = ek.group.g.Bytes()
	hValues[2] = ek.y2.Bytes()
	hValues[3] = ek.y3.Bytes()
	offset := 4
	for _, y := range ek.y1 {
		hValues[offset] = y.Bytes()
		offset++
	}
	hValues[offset] = ciphertext.u.Bytes()
	offset++
	for _, n := range ciphertext.e {
		hValues[offset] = n.Bytes()
		offset++
	}
	hValues[offset] = ciphertext.v.Bytes()
	offset++

	hValues[offset] = ciphertextTValues.u.Bytes()
	offset++
	for _, n := range ciphertextTValues.e {
		hValues[offset] = n.Bytes()
		offset++
	}
	hValues[offset] = ciphertextTValues.v.Bytes()

	hValues[len(hValues)-1] = nonce
	h, err := internal.Hash([]byte("Coinbase Hash 1.0"), hValues...)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(h), nil
}

// schnorr computes tilde - challenge * value mod n^2
func (ek EncryptionKey) schnorr(tilde, challenge, value *big.Int) *big.Int {
	r := ek.group.Mul(challenge, value)
	t := new(big.Int).Sub(tilde, r)
	return t
}

// VerifyEncryptProof a Proof of Verifiable Encryption
// See section 6.2.19 in <https://dominoweb.draco.res.ibm.com/reports/rz3730_revised.pdf>
func (ek EncryptionKey) VerifyEncryptProof(nonce []byte, ciphertext *CipherText, proof *ProofVerEnc) error {
	if ciphertext == nil || proof == nil {
		return internal.ErrNilArguments
	}
	if proof.r == nil || proof.challenge == nil || proof.m == nil {
		return internal.ErrNilArguments
	}
	if ciphertext.u == nil || ciphertext.v == nil || ciphertext.e == nil {
		return internal.ErrNilArguments
	}
	if len(proof.m) > len(ek.y1) {
		return fmt.Errorf("number of messages %d is more than supported by this key %d", len(proof.m), len(ek.y1))
	}

	// Reconstruct u
	// 2c
	c2 := new(big.Int).Lsh(proof.challenge, 1)
	// 2r
	r2 := new(big.Int).Lsh(proof.r, 1)

	// u^{2c} mod n^2
	uc := ek.group.Exp(ciphertext.u, c2)

	// Reconstruct e
	// g^{2r} mod n^2
	gr := ek.group.Gexp(r2)

	// u^{2c} * g^{2r} mod n^2
	u := ek.group.Mul(uc, gr)

	e := make([]*big.Int, len(proof.m))
	for i, mm := range proof.m {
		// e^{2c}
		ec := ek.group.Exp(ciphertext.e[i], c2)
		// y1^{2r}
		yr := ek.group.Exp(ek.y1[i], r2)
		// h^{2m}
		hm := ek.group.Hexp(new(big.Int).Lsh(mm, 1))
		// e = ec * yr * hm mod n^2
		e[i] = ek.group.Mul(ek.group.Mul(ec, yr), hm)
	}

	// Reconstruct v
	// v^{2c}
	hs, err := ek.group.Hash(ciphertext.u, ciphertext.e, nonce)
	if err != nil {
		return err
	}
	vc := ek.group.Exp(ciphertext.v, c2)
	y3hs := ek.group.Exp(ek.y3, hs)
	y2y3hs := ek.group.Mul(ek.y2, y3hs)
	y2y3hsr := ek.group.Exp(y2y3hs, r2)
	v := ek.group.Mul(vc, y2y3hsr)

	ciphertextTestValues := &CipherText{u, v, e}
	challenge, err := ek.fiatShamir(nonce, ciphertext, ciphertextTestValues)
	if err != nil {
		return err
	}
	if challenge.Cmp(proof.challenge) == 0 {
		return nil
	} else {
		return fmt.Errorf("invalid ciphertext")
	}
}
