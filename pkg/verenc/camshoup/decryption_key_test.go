//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecryptionKeyMarshal(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)
	_, dk, err := NewKeys(3, group)
	require.NoError(t, err)
	bin, err := dk.MarshalBinary()
	require.NoError(t, err)
	dup := new(DecryptionKey)
	err = dup.UnmarshalBinary(bin)
	require.NoError(t, err)
	require.Equal(t, 0, dk.x3.Cmp(dup.x3))
	require.Equal(t, 0, dk.x2.Cmp(dup.x2))
	for i, x := range dk.x1 {
		require.Equal(t, 0, x.Cmp(dup.x1[i]))
	}
}

func TestDecryptionKeyDecryptBadCiphertext(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)
	_, dk, err := NewKeys(3, group)
	require.NoError(t, err)

	_, err = dk.Decrypt([]byte{}, nil)
	require.Error(t, err)

	_, err = dk.Decrypt([]byte{}, new(CipherText))
	require.Error(t, err)

	cs := new(CipherText)
	cs.v = big.NewInt(1)
	cs.u = big.NewInt(1)
	cs.e = []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)}

	_, err = dk.Decrypt([]byte{}, cs)
	require.Error(t, err)
	// all 1s are valid ciphertexts, so we pick other random values
	cs.e = []*big.Int{big.NewInt(2), big.NewInt(2), big.NewInt(2)}

	_, err = dk.Decrypt([]byte{}, cs)
	require.Error(t, err)

	cs.v = big.NewInt(0)
	cs.u = big.NewInt(0)
	cs.e = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	_, err = dk.Decrypt([]byte{}, cs)
	require.Error(t, err)

	cs.u = big.NewInt(1)
	cs.e = []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}
	cs.v = new(big.Int).Add(group.n2, big.NewInt(1))
	_, err = dk.Decrypt([]byte{}, cs)
	require.Error(t, err)
}
