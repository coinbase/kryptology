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
	require.True(t, cs.C1.Equal(dup.C1))
	require.True(t, cs.C2.Equal(dup.C2))
	require.Equal(t, cs.Nonce, dup.Nonce)
	require.Equal(t, cs.Aead, dup.Aead)
}
