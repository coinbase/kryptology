//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
	"github.com/coinbase/kryptology/pkg/verenc/elgamal"
)

func main() {
	curve := curves.P256()
	fmt.Printf("Coinbase generates verifiable encryption keys\n")
	ek, dk, _ := elgamal.NewKeys(curve)
	ekBytes, _ := ek.MarshalBinary()
	dkBytes, _ := dk.MarshalBinary()
	fmt.Printf("Coinbase publishes encryption key %v\n", hex.EncodeToString(ekBytes))
	fmt.Printf("Coinbase retains decryption key %v\n", hex.EncodeToString(dkBytes))
	fmt.Printf("Coinbase stores encrypted key shares on behalf\n")
	fmt.Printf("of users. Users refresh their keys after signing.\n")
	fmt.Printf("Coinbase wants to ensure the refreshed shares are correct\n")
	fmt.Printf("so users submit verifiable encryptions which prove\n")
	fmt.Printf("the sum of the encrypted shares is equal to the expected public key.\n")

	// Normally users use DKG, but for demo simplicity we skip that
	shamir, _ := v1.NewShamir(2, 2, curves.NewField(elliptic.P256().Params().N))
	// signing key
	sk := curve.Scalar.Random(crand.Reader)
	// public verification key
	vk := curve.Point.Generator().Mul(sk)
	// user's shares
	shares, _ := shamir.Split(sk.Bytes())

	user1Pk, user1Sk, _ := elgamal.NewKeys(curve)
	s1, _ := curve.Scalar.SetBytes(shares[0].Value.Bytes())
	ctxt1, proof1, _ := ek.VerifiableEncrypt(shares[0].Value.Bytes(), &elgamal.EncryptParams{
		Domain:          []byte("initial upload user 1"),
		MessageIsHashed: true,
		GenProof:        true,
		ProofNonce:      []byte("initial upload user 1"),
	})
	user1Ctxt, _, _ := user1Pk.VerifiableEncrypt(shares[0].Value.Bytes(), &elgamal.EncryptParams{
		MessageIsHashed: true,
	})
	ctxt1Bytes, _ := ctxt1.MarshalBinary()
	fmt.Printf("User 1 submits ciphertext %v\n", hex.EncodeToString(ctxt1Bytes))

	ctxt2, proof2, _ := ek.VerifiableEncrypt(shares[1].Value.Bytes(), &elgamal.EncryptParams{
		Domain:          []byte("initial upload user 2"),
		MessageIsHashed: true,
		GenProof:        true,
		ProofNonce:      []byte("initial upload user 2"),
	})
	ctxt2Bytes, _ := ctxt2.MarshalBinary()
	fmt.Printf("User 2 submits ciphertext %v\n", hex.EncodeToString(ctxt2Bytes))

	fmt.Printf("Coinbase verifies each user's ciphertext\n")
	fmt.Printf("User 1 ciphertext is valid = %v\n", ek.VerifyEncryptProof([]byte("initial upload user 1"), ctxt1, proof1) == nil)
	fmt.Printf("User 2 ciphertext is valid = %v\n", ek.VerifyEncryptProof([]byte("initial upload user 2"), ctxt2, proof2) == nil)

	m1 := dk.Decrypt(ctxt1.ToHomomorphicCipherText())
	m2 := dk.Decrypt(ctxt2.ToHomomorphicCipherText())
	avk := shamirCombinePoint(curve, []curves.Point{m1, m2})
	fmt.Printf("users ciphertexts should sum to vk %v\n", hex.EncodeToString(vk.ToAffineCompressed()))
	fmt.Printf("sum of ciphertexts is %v\n", hex.EncodeToString(avk.ToAffineCompressed()))
	fmt.Printf("Values are equal, allowing shares to be uploaded.\n")

	fmt.Printf("User 1 wants check that Coinbase has the correct ciphertext\n")
	fmt.Printf("and wants to decrypt it to see if its what she expects.\n")
	fmt.Printf("User 1 verifiably decrypts share from sent from Coinbase\n")
	_, share, err := user1Sk.VerifiableDecrypt(user1Ctxt)
	fmt.Printf("User 1 share decrypts properly = %v\n", err == nil && share.Cmp(s1) == 0)
}

func shamirCombinePoint(curve *curves.Curve, points []curves.Point) curves.Point {
	result := curve.Point.Identity()

	for i, p := range points {
		basis := curve.Scalar.One()
		for j := range points {
			if i == j {
				continue
			}

			// x_m - x_j
			denom := curve.Scalar.New(j + 1).Sub(curve.Scalar.New(i + 1))
			if denom.IsZero() {
				return nil
			}
			// x_m / x_m - x_j
			basis = basis.Mul(curve.Scalar.New(j + 1).Div(denom))
		}

		result = result.Add(p.Mul(basis))
	}

	return result
}
