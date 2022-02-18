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

package v1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPoly(t *testing.T) {
	secret := field.ElementFromBytes([]byte("test"))

	poly, err := newPoly(secret, 4)
	require.Nil(t, err)
	require.NotNil(t, poly)

	require.Equal(t, poly.Coefficients[0], secret)
}
