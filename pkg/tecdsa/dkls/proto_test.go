//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkls

import (
	"bytes"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Runs a DKG on initialized Alice/Bob objects. Reports any errors encountered.
func iteratedDkg(alice *AliceDkg, bob *BobDkg) (error, error) {
	var (
		buf  bytes.Buffer
		aErr error
		bErr error
	)

	for aErr != io.EOF || bErr != io.EOF {
		// Crank each protocol forward one iteration
		aErr = alice.Next(&buf)
		if aErr != nil && aErr != io.EOF {
			return aErr, nil
		}

		bErr = bob.Next(&buf)
		if bErr != nil && bErr != io.EOF {
			return nil, bErr
		}
	}
	return aErr, bErr
}

// Runs Sign protocol on initialized alice/bob objects.
func iteratedSign(alice *AliceSign, bob *BobSign) (error, error) {
	var (
		aErr, bErr error
		buf        bytes.Buffer
	)

	// Run until both parties complete the protocol
	for !(aErr == io.EOF && bErr == io.EOF) {
		aErr = alice.Next(&buf)
		if !(aErr == nil || aErr == io.EOF) {
			break
		}

		bErr = bob.Next(&buf)
		if !(bErr == nil || bErr == io.EOF) {
			break
		}
	}
	return aErr, bErr
}

// Running steps in sequence ensures that no hidden read/write dependency exist in the read/write interfaces.
func TestDkgProto(t *testing.T) {
	params, err := NewParams(btcec.S256(), curves.K256Scalar{})
	require.NoError(t, err)

	alice := NewAliceDkg(params)
	bob := NewBobDkg(params)
	aErr, bErr := iteratedDkg(alice, bob)

	t.Run("both alice/bob complete simultaneously", func(t *testing.T) {
		require.ErrorIs(t, aErr, io.EOF)
		require.ErrorIs(t, bErr, io.EOF)
	})

	t.Run("OT results are correct", func(t *testing.T) {
		assert.NoError(t, verifyOt(alice.alice, bob.bob))
	})

	t.Run("Both parties produces identical composite pubkey", func(t *testing.T) {
		assert.Equal(t,
			alice.alice.Pk,
			bob.bob.Pk,
		)
	})

	var aliceResult *DkgResult
	var bobResult *DkgResult
	t.Run("alices produces valid result", func(t *testing.T) {
		// Get the result
		r, err := alice.Result()

		// Test
		require.NoError(t, err)
		require.NotNil(t, r)
		require.IsType(t, &DkgResult{}, r)
		aliceResult = r.(*DkgResult)

		// Decode and verify
		_, err = NewAliceSign(params, nil, aliceResult.DkgState)
		assert.NoError(t, err)
	})
	t.Run("alices produces valid result", func(t *testing.T) {
		// Get the result
		r, err := bob.Result()

		// Test
		require.NoError(t, err)
		require.NotNil(t, r)
		require.IsType(t, &DkgResult{}, r)
		bobResult = r.(*DkgResult)

		// Decode and verify
		_, err = NewBobSign(params, nil, bobResult.DkgState)
		assert.NoError(t, err)
	})

	t.Run("alice/bob agree on pubkey", func(t *testing.T) {
		assert.Equal(t, aliceResult.Pubkey, bobResult.Pubkey)
	})
}

// DKG > Result > NewDklsSign > Sign > Result
func TestDkgSignProto(t *testing.T) {
	// Setup
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.NoError(t, err)

	aliceDkg := NewAliceDkg(params)
	bobDkg := NewBobDkg(params)

	// DKG
	aErr, bErr := iteratedDkg(aliceDkg, bobDkg)
	require.ErrorIs(t, aErr, io.EOF)
	require.ErrorIs(t, bErr, io.EOF)

	// Result
	aliceDkgResult, err := aliceDkg.Result()
	require.NoError(t, err)

	bobDkgResult, err := bobDkg.Result()
	require.NoError(t, err)

	// New DklsSign
	msg := []byte("As soon as you trust yourself, you will know how to live.")
	digest := sha256.Sum256(msg)
	aliceSign, err := NewAliceSign(params, digest[:], aliceDkgResult.(*DkgResult).DkgState)
	require.NoError(t, err)
	bobSign, err := NewBobSign(params, digest[:], bobDkgResult.(*DkgResult).DkgState)
	require.NoError(t, err)

	// Sign
	t.Run("sign", func(t *testing.T) {
		aErr, bErr = iteratedSign(aliceSign, bobSign)
		assert.ErrorIs(t, aErr, io.EOF)
		assert.ErrorIs(t, bErr, io.EOF)
	})
	// Don't continue to verifying results if sign didn't run to completion.
	require.ErrorIs(t, aErr, io.EOF)
	require.ErrorIs(t, bErr, io.EOF)

	// Result
	var result interface{}
	t.Run("bob produces result of correct type", func(t *testing.T) {
		result, err = bobSign.Result()
		assert.NoError(t, err)
	})
	require.NotNil(t, result)
	require.IsType(t, &curves.EcdsaSignature{}, result)

	t.Run("valid signature", func(t *testing.T) {
		assert.True(t,
			curves.VerifyEcdsa(aliceDkg.alice.Pk,
				digest[:],
				result.(*curves.EcdsaSignature),
			),
			"signature failed verification",
		)
	})
}

// Decode > NewDklsSign > Sign > Result
// NOTE: this cold-start test ensures backwards compatibility with durable,
// encoding DKG state that may exist within production systems like test
// Breaking changes must consider downstream production impacts.
func TestSignColdStart(t *testing.T) {
	msg := []byte("We see in the world that which we carry in our heart")
	digest := sha256.Sum256(msg)
	params, err := NewParams(btcec.S256(), curves.NewK256Scalar())
	require.NoError(t, err)

	// Decode alice/bob state from file
	aliceDkg, err := ioutil.ReadFile("testdata/alice-dkls-dkg.bin")
	require.NoError(t, err)
	bobDkg, err := ioutil.ReadFile("testdata/bob-dkls-dkg.bin")
	require.NoError(t, err)

	// Decode proto objects
	alice, err := NewAliceSign(params, digest[:], aliceDkg)
	require.NoError(t, err)

	bob, err := NewBobSign(params, digest[:], bobDkg)
	require.NoError(t, err)

	// Sign
	aErr, bErr := iteratedSign(alice, bob)
	require.ErrorIs(t, aErr, io.EOF, "got err=%v", aErr)
	require.ErrorIs(t, bErr, io.EOF, "got err=%v", bErr)

	// Extract the result and verify the type
	result, err := bob.Result()
	require.NoError(t, err)
	require.IsType(t, &curves.EcdsaSignature{}, result)

	// Test the result
	assert.True(t,
		curves.VerifyEcdsa(alice.alice.Pk,
			digest[:],
			result.(*curves.EcdsaSignature),
		),
		"signature failed verification",
	)
}

func TestEncodeDecode(t *testing.T) {
	params, err := NewParams(btcec.S256(), curves.K256Scalar{})
	require.NoError(t, err)

	alice := NewAliceDkg(params)
	bob := NewBobDkg(params)
	_, _ = iteratedDkg(alice, bob)

	var aliceBytes []byte
	var bobBytes []byte
	t.Run("Encode Alice/Bob", func(t *testing.T) {
		aliceBytes, err = EncodeAlice(alice.alice)
		require.NoError(t, err)

		bobBytes, err = EncodeBob(bob.bob)
		require.NoError(t, err)
	})
	require.NotEmpty(t, aliceBytes)
	require.NotEmpty(t, bobBytes)

	t.Run("Decode Alice", func(t *testing.T) {
		decodedAlice, err := DecodeAlice(params, aliceBytes)
		require.NoError(t, err)
		require.NotNil(t, decodedAlice)

		assert.Equal(t, alice.alice.Pk, decodedAlice.Pk)
		assert.Equal(t, alice.alice.PkA, decodedAlice.PkA)
		assert.Equal(t, alice.alice.SkA, decodedAlice.SkA)
	})

	t.Run("Decode Bob", func(t *testing.T) {
		decodedBob, err := DecodeBob(params, bobBytes)
		require.NoError(t, err)
		require.NotNil(t, decodedBob)

		assert.Equal(t, bob.bob.Pk, decodedBob.Pk)
		assert.Equal(t, bob.bob.PkB, decodedBob.PkB)
		assert.Equal(t, bob.bob.SkB, decodedBob.SkB)
	})
}
