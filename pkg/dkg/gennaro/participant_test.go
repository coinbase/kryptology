//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package gennaro

import (
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/coinbase/kryptology/internal"
	"github.com/stretchr/testify/require"
)

var testGenerator, _ = curves.NewScalarBaseMult(btcec.S256(), big.NewInt(3333))

func TestNewParticipantWorks(t *testing.T) {
	p, err := NewParticipant(1, 2, testGenerator, curves.NewK256Scalar(), 2)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.Equal(t, p.id, uint32(1))
	require.Equal(t, p.round, 1)
	require.Equal(t, p.curve, btcec.S256())
	require.NotNil(t, p.pedersen)
	require.NotNil(t, p.feldman)
	require.Nil(t, p.pedersenResult)
	require.NotNil(t, p.otherParticipantShares)
	require.NotNil(t, p.scalar)
	_, ok := p.otherParticipantShares[2]
	require.True(t, ok)
}

func TestNewParticipantBadInputs(t *testing.T) {
	_, err := NewParticipant(0, 0, nil, nil)
	require.Error(t, err)
	require.Equal(t, err, internal.ErrNilArguments)
	_, err = NewParticipant(1, 2, nil, nil)
	require.Error(t, err)
	require.Equal(t, err, internal.ErrNilArguments)
	_, err = NewParticipant(1, 2, testGenerator, nil)
	require.Error(t, err)
	require.Equal(t, err, internal.ErrNilArguments)
}
