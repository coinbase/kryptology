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

func TestCipherTextMarshal(t *testing.T) {
	domain := []byte("TestCipherTextMarshal")

	k256 := curves.K256()
	ek, _, err := NewKeys(k256)
	require.NoError(t, err)

	msg := k256.Scalar.New(1)
	msgBytes := msg.Bytes()
	require.NoError(t, err)
	cs, _, err := ek.VerifiableEncrypt(msgBytes, &EncryptParams{
		Domain:          domain,
		MessageIsHashed: true,
	})
	require.NoError(t, err)

	bin, err := cs.MarshalBinary()
	require.NoError(t, err)
	dup := new(CipherText)
	err = dup.UnmarshalBinary(bin)
	require.NoError(t, err)
	require.True(t, cs.c1.Equal(dup.c1))
	require.True(t, cs.c2.Equal(dup.c2))
	require.Equal(t, cs.nonce, dup.nonce)
	require.Equal(t, cs.aead, dup.aead)
}
