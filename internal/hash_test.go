//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package internal

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestByteSub(t *testing.T) {
	f := bytes.Repeat([]byte{0xFF}, 32)
	ByteSub(f)
	assert.Equal(t, f[0], byte(0xFE))
	for i := 1; i < len(f); i++ {
		assert.Equal(t, f[i], byte(0xFF))
	}
	ByteSub(f)
	assert.Equal(t, f[0], byte(0xFD))
	for i := 1; i < len(f); i++ {
		assert.Equal(t, f[i], byte(0xFF))
	}
	f[0] = 0x2
	ByteSub(f)
	for i := 1; i < len(f); i++ {
		assert.Equal(t, f[i], byte(0xFF))
	}
	ByteSub(f)
	assert.Equal(t, f[0], byte(0xFF))
	assert.Equal(t, f[1], byte(0xFE))
	for i := 2; i < len(f); i++ {
		assert.Equal(t, f[i], byte(0xFF))
	}
	ByteSub(f)
	assert.Equal(t, f[0], byte(0xFE))
	assert.Equal(t, f[1], byte(0xFE))
	for i := 2; i < len(f); i++ {
		assert.Equal(t, f[i], byte(0xFF))
	}
	f[0] = 1
	f[1] = 1
	ByteSub(f)
	assert.Equal(t, f[0], byte(0xFF))
	assert.Equal(t, f[1], byte(0xFF))
	assert.Equal(t, f[2], byte(0xFE))
	for i := 3; i < len(f); i++ {
		assert.Equal(t, f[i], byte(0xFF))
	}
}

func TestByteSubAll1(t *testing.T) {
	f := bytes.Repeat([]byte{0x1}, 32)
	ByteSub(f)
	for i := 0; i < len(f); i++ {
		assert.Equal(t, f[i], byte(0xFF))
	}
}
