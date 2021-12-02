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

func TestCipherTextMarshal(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	domain := []byte("TestCipherTextMarshal")

	ek, _, err := NewKeys(1, group)
	require.NoError(t, err)

	msg := big.NewInt(1)
	cs, err := ek.Encrypt(domain, []*big.Int{msg})
	require.NoError(t, err)

	bin, err := cs.MarshalBinary()
	require.NoError(t, err)
	dup := new(CipherText)
	err = dup.UnmarshalBinary(bin)
	require.NoError(t, err)
	require.Equal(t, 0, cs.u.Cmp(dup.u))
	require.Equal(t, 0, cs.v.Cmp(dup.v))
	for i, e := range cs.e {
		require.Equal(t, 0, e.Cmp(dup.e[i]))
	}
}
