//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package elgamal

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryptionKeyEncrypt(t *testing.T) {
	k256 := curves.K256()
	domain := []byte("TestEncryptionKeyEncrypt")

	ek, dk, err := NewKeys(k256)
	require.NoError(t, err)

	testMsgs := []curves.Scalar{
		k256.Scalar.New(0),
		k256.Scalar.New(10),
		k256.Scalar.New(20),
		k256.Scalar.New(30),
		k256.Scalar.New(40),
		k256.Scalar.New(50),
		k256.Scalar.New(100),
		k256.Scalar.New(1000),
		k256.Scalar.New(10000),
		k256.Scalar.New(100000),
		k256.Scalar.New(1000000),
	}

	for _, msg := range testMsgs {
		msgBytes := msg.Bytes()
		require.NoError(t, err)
		cs, _, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
			Domain:          domain,
			MessageIsHashed: true,
		})
		require.NoError(t, err)
		_, m, err := dk.VerifiableDecryptWithDomain(domain, cs)
		require.NoError(t, err)
		require.Equal(t, m.Cmp(msg), 0)
	}
}

func TestEncryptionKeyEncryptInvalidMessages(t *testing.T) {
	k256 := curves.K256()
	domain := []byte("TestEncryptionKeyEncryptInvalidMessages")

	ek, dk, err := NewKeys(k256)
	require.NoError(t, err)

	// nil message
	_, _, err = ek.VerifiableEncrypt(nil, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
	})
	require.Error(t, err)

	msg := k256.Scalar.New(1234567890)
	msgBytes := msg.Bytes()
	cs, _, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
	})
	require.NoError(t, err)
	// invalid domain i.e. not the same domain used to encrypt
	_, _, err = dk.VerifiableDecryptWithDomain([]byte{}, cs)
	require.Error(t, err)
}

func TestEncryptionKeyMarshaling(t *testing.T) {
	k256 := curves.K256()
	ek, _, err := NewKeys(k256)
	require.NoError(t, err)

	bin, err := ek.MarshalBinary()
	require.NoError(t, err)

	ekClone := new(EncryptionKey)
	err = ekClone.UnmarshalBinary(bin)
	require.NoError(t, err)
	require.True(t, ek.value.Equal(ekClone.value))
}
