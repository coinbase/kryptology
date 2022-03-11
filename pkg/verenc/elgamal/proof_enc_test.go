//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestEncryptionKeyEncryptAndProve(t *testing.T) {
	bls12381 := curves.BLS12381G1()
	domain := []byte("TestEncryptionKeyEncryptAndProve")

	ek, dk, err := NewKeys(bls12381)
	require.NoError(t, err)

	testMsgs := []curves.Scalar{
		bls12381.Scalar.New(0),
		bls12381.Scalar.New(10),
		bls12381.Scalar.New(20),
		bls12381.Scalar.New(30),
		bls12381.Scalar.New(40),
		bls12381.Scalar.New(50),
		bls12381.Scalar.New(100),
		bls12381.Scalar.New(1000),
		bls12381.Scalar.New(10000),
		bls12381.Scalar.New(100000),
		bls12381.Scalar.New(1000000),
	}
	for _, msg := range testMsgs {
		msgBytes := msg.Bytes()
		require.NoError(t, err)
		cs, proof, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
			Domain:          domain,
			MessageIsHashed: true,
			GenProof:        true,
			ProofNonce:      domain,
		})
		require.NoError(t, err)

		err = ek.VerifyDomainEncryptProof(domain, cs, proof)
		require.NoError(t, err)

		_, dmsg, err := dk.VerifiableDecryptWithDomain(domain, cs)
		require.NoError(t, err)
		require.Equal(t, 0, msg.Cmp(dmsg))
	}
}

func TestEncryptionKeyEncryptAndProvePlaintextMsg(t *testing.T) {
	bls12381 := curves.BLS12381G1()
	domain := []byte("TestEncryptionKeyEncryptAndProve")

	ek, dk, err := NewKeys(bls12381)
	require.NoError(t, err)

	msg := "testMessage"
	msgBytes := []byte(msg)

	cs, proof, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: false,
		GenProof:        true,
		ProofNonce:      domain,
	})
	require.NoError(t, err)

	err = ek.VerifyDomainEncryptProof(domain, cs, proof)
	require.NoError(t, err)

	dmsgBytes, _, err := dk.VerifiableDecryptWithDomain(domain, cs)
	require.NoError(t, err)
	require.Equal(t, msgBytes, dmsgBytes)
	require.Equal(t, msg, string(dmsgBytes))
}

func TestEncryptionKeyEncryptAndProveBlinding(t *testing.T) {
	bls12381 := curves.BLS12381G1()
	domain := []byte("TestEncryptionKeyEncryptAndProveBlinding")

	ek, dk, err := NewKeys(bls12381)
	require.NoError(t, err)

	testMsgs := []*struct {
		test, blinding curves.Scalar
	}{
		{bls12381.Scalar.New(0), bls12381.Scalar.New(1)},
		{bls12381.Scalar.New(10), bls12381.Scalar.New(2)},
		{bls12381.Scalar.New(20), bls12381.Scalar.New(3)},
		{bls12381.Scalar.New(30), bls12381.Scalar.New(4)},
		{bls12381.Scalar.New(40), bls12381.Scalar.New(5)},
		{bls12381.Scalar.New(50), bls12381.Scalar.New(6)},
		{bls12381.Scalar.New(100), bls12381.Scalar.New(7)},
		{bls12381.Scalar.New(1000), bls12381.Scalar.New(8)},
		{bls12381.Scalar.New(10000), bls12381.Scalar.New(9)},
		{bls12381.Scalar.New(100000), bls12381.Scalar.New(10)},
		{bls12381.Scalar.New(1000000), bls12381.Scalar.New(11)},
	}
	for _, msg := range testMsgs {
		msgTestBytes := msg.test.Bytes()
		cs, proof, err := ek.VerifiableEncrypt(msgTestBytes, &EncryptParams{
			Domain:          domain,
			MessageIsHashed: true,
			Blinding:        msg.blinding,
			GenProof:        true,
			ProofNonce:      domain,
		})
		require.NoError(t, err)

		err = ek.VerifyDomainEncryptProof(domain, cs, proof)
		require.NoError(t, err)

		_, dmsg, err := dk.VerifiableDecryptWithDomain(domain, cs)
		require.NoError(t, err)
		require.Equal(t, 0, msg.test.Cmp(dmsg))
	}
}

func TestEncryptionKeyEncryptAndProveInvalidInputs(t *testing.T) {
	bls12381 := curves.BLS12381G1()
	domain := []byte("TestEncryptionKeyEncryptAndProveInvalidInputs")

	ek, _, err := NewKeys(bls12381)
	require.NoError(t, err)

	_, _, err = ek.VerifiableEncrypt(nil, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
		GenProof:        true,
		ProofNonce:      domain,
	})
	require.Error(t, err)

	msg2 := bls12381.Scalar.New(2)
	msg2Bytes := msg2.Bytes()
	_, _, err = ek.VerifiableEncrypt(msg2Bytes, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
		Blinding:        bls12381.Scalar.New(0),
		GenProof:        true,
		ProofNonce:      domain,
	})
	require.Error(t, err)
}

func TestMarshalUnmarshalWithDomain(t *testing.T) {
	bls12381 := curves.BLS12381G1()
	domain := []byte("TestEncryptionKeyEncryptAndProve")

	ek, _, err := NewKeys(bls12381)
	require.NoError(t, err)

	testMsgs := []curves.Scalar{
		bls12381.Scalar.New(0),
		bls12381.Scalar.New(10),
		bls12381.Scalar.New(100),
		bls12381.Scalar.New(1000),
		bls12381.Scalar.New(1000000),
	}
	for _, msg := range testMsgs {
		msgBytes := msg.Bytes()
		require.NoError(t, err)
		cs, proof, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
			Domain:          domain,
			MessageIsHashed: true,
			GenProof:        true,
			ProofNonce:      domain,
		})
		require.NoError(t, err)

		proofBytes, err := proof.MarshalBinary()
		require.NoError(t, err)

		proofUnmarshaled := ProofVerEnc{}
		err = proofUnmarshaled.UnmarshalBinary(proofBytes)
		require.NoError(t, err)

		err = ek.VerifyDomainEncryptProof(domain, cs, proof)
		require.NoError(t, err)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	bls12381 := curves.BLS12381G1()
	domain := []byte("TestEncryptionKeyEncryptAndProve")

	ek, _, err := NewKeys(bls12381)
	require.NoError(t, err)

	testMsgs := []curves.Scalar{
		bls12381.Scalar.New(0),
		bls12381.Scalar.New(10),
		bls12381.Scalar.New(100),
		bls12381.Scalar.New(1000),
		bls12381.Scalar.New(1000000),
	}
	for _, msg := range testMsgs {
		msgBytes := msg.Bytes()
		require.NoError(t, err)
		cs, proof, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
			MessageIsHashed: true,
			GenProof:        true,
			ProofNonce:      domain,
		})
		require.NoError(t, err)

		proofBytes, err := proof.MarshalBinary()
		require.NoError(t, err)

		proofUnmarshaled := ProofVerEnc{}
		err = proofUnmarshaled.UnmarshalBinary(proofBytes)
		require.NoError(t, err)

		err = ek.VerifyEncryptProof(domain, cs, proof)
		require.NoError(t, err)
	}
}
