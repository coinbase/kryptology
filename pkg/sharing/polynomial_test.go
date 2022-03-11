//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Copyright Coinbase, Inc. All Rights Reserved.
//
//
// SPDX-License-Identifier: Apache-2.0
//

package sharing

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves"
)

func TestNewPoly(t *testing.T) {
	curve := curves.BLS12381G1()
	secret := curve.NewScalar().Hash([]byte("test"))

	poly := new(Polynomial).Init(secret, 4, crand.Reader)
	require.NotNil(t, poly)

	require.Equal(t, poly.Coefficients[0], secret)
}
