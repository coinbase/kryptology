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

func TestDecryptionKeyMarshal(t *testing.T) {
	k256 := curves.K256()
	_, dk, err := NewKeys(k256)
	require.NoError(t, err)
	bin, err := dk.MarshalBinary()
	require.NoError(t, err)
	dup := new(DecryptionKey)
	err = dup.UnmarshalBinary(bin)
	require.NoError(t, err)
	require.Equal(t, 0, dk.x.Cmp(dup.x))
}

func TestDecryptionKeyDecryptBadCiphertext(t *testing.T) {
	k256 := curves.K256()
	_, dk, err := NewKeys(k256)
	require.NoError(t, err)

	// nil ciphertext
	_, _, err = dk.VerifiableDecryptWithDomain([]byte{}, nil)
	require.Error(t, err)

	// empty ciphertext
	_, _, err = dk.VerifiableDecryptWithDomain([]byte{}, new(CipherText))
	require.Error(t, err)

	cs := new(CipherText)
	cs.c1 = k256.Point.Generator()
	cs.c2 = k256.Point.Generator()
	cs.nonce = make([]byte, 12)
	cs.aead = make([]byte, 16)

	// empty data in ciphertext
	_, _, err = dk.VerifiableDecryptWithDomain([]byte{}, cs)
	require.Error(t, err)

	cs.c1 = k256.Point.Identity()
	cs.c2 = k256.Point.Identity()
	cs.nonce = []byte{}
	cs.aead = []byte{}
	// ensure no panic happens when nonce and aead are invalid lengths
	_, _, err = dk.VerifiableDecryptWithDomain([]byte{}, cs)
	require.Error(t, err)
}
