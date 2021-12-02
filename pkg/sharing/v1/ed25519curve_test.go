//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEd25519ScalarMult(t *testing.T) {
	// These values were caught during testing where this combination
	// yields leading zeros in which big.Int chops.
	// This test makes sure that this case is correctly handled
	y := new(big.Int).SetBytes([]byte{37, 228, 49, 105, 78, 97, 108, 221, 63, 25, 125, 212, 108, 189, 247, 169, 52, 86, 150, 97, 93, 199, 212, 254, 122, 98, 189, 7, 97, 14, 78, 12})
	x := new(big.Int).SetInt64(4)
	curve := Ed25519()
	require.True(t, curve.IsOnCurve(nil, y))
	_, newY := curve.ScalarMult(nil, y, x.Bytes())
	require.True(t, curve.IsOnCurve(nil, newY))
}
