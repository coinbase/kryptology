//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/big"
	"testing"

	v0 "github.com/coinbase/kryptology/pkg/tecdsa/dkls/v0"
	"github.com/coinbase/kryptology/pkg/tecdsa/dkls/v1/dkg"
	"github.com/btcsuite/btcd/btcec"

	"github.com/coinbase/kryptology/pkg/core/protocol"

	"golang.org/x/crypto/sha3"

	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/ot/extension/kos"
	"github.com/stretchr/testify/require"
)

func runIteratedProtocol(alice protocol.Iterator, bob protocol.Iterator) (error, error) {
	var (
		message *protocol.Message
		aErr    error
		bErr    error
	)

	for aErr != protocol.ErrProtocolFinished || bErr != protocol.ErrProtocolFinished {
		// Crank each protocol forward one iteration
		message, bErr = bob.Next(message)
		if bErr != nil && bErr != protocol.ErrProtocolFinished {
			return nil, bErr
		}

		message, aErr = alice.Next(message)
		if aErr != nil && aErr != protocol.ErrProtocolFinished {
			return aErr, nil
		}
	}
	return aErr, bErr
}

// Running steps in sequence ensures that no hidden read/write dependency exist in the read/write interfaces.
func TestDkgProto(t *testing.T) {
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		alice := NewAliceDkg(curve, protocol.Version1)
		bob := NewBobDkg(curve, protocol.Version1)
		aErr, bErr := runIteratedProtocol(alice, bob)

		t.Run("both alice/bob complete simultaneously", func(t *testing.T) {
			require.ErrorIs(t, aErr, protocol.ErrProtocolFinished)
			require.ErrorIs(t, bErr, protocol.ErrProtocolFinished)
		})

		for i := 0; i < kos.Kappa; i++ {
			if alice.Alice.Output().SeedOtResult.OneTimePadDecryptionKey[i] != bob.Bob.Output().SeedOtResult.OneTimePadEncryptionKeys[i][alice.Alice.Output().SeedOtResult.RandomChoiceBits[i]] {
				t.Errorf("oblivious transfer is incorrect at index i=%v", i)
			}
		}

		t.Run("Both parties produces identical composite pubkey", func(t *testing.T) {
			require.True(t, alice.Alice.Output().PublicKey.Equal(bob.Bob.Output().PublicKey))
		})

		var aliceResult *dkg.AliceOutput
		var bobResult *dkg.BobOutput
		t.Run("alice produces valid result", func(t *testing.T) {
			// Get the result
			r, err := alice.Result(protocol.Version1)

			// Test
			require.NoError(t, err)
			require.NotNil(t, r)
			aliceResult, err = DecodeAliceDkgResult(r)
			require.NoError(t, err)
		})
		t.Run("bob produces valid result", func(t *testing.T) {
			// Get the result
			r, err := bob.Result(protocol.Version1)

			// Test
			require.NoError(t, err)
			require.NotNil(t, r)
			bobResult, err = DecodeBobDkgResult(r)
			require.NoError(t, err)
		})

		t.Run("alice/bob agree on pubkey", func(t *testing.T) {
			require.Equal(t, aliceResult.PublicKey, bobResult.PublicKey)
		})
	}
}

// DKG > Output > NewDklsSign > Sign > Output
func TestDkgSignProto(t *testing.T) {
	// Setup
	curve := curves.K256()

	aliceDkg := NewAliceDkg(curve, protocol.Version1)
	bobDkg := NewBobDkg(curve, protocol.Version1)

	// DKG
	aErr, bErr := runIteratedProtocol(aliceDkg, bobDkg)
	require.ErrorIs(t, aErr, protocol.ErrProtocolFinished)
	require.ErrorIs(t, bErr, protocol.ErrProtocolFinished)

	// Output
	aliceDkgResultMessage, err := aliceDkg.Result(protocol.Version1)
	require.NoError(t, err)

	bobDkgResultMessage, err := bobDkg.Result(protocol.Version1)
	require.NoError(t, err)

	// New DklsSign
	msg := []byte("As soon as you trust yourself, you will know how to live.")
	aliceSign, err := NewAliceSign(curve, msg, aliceDkgResultMessage, protocol.Version1)
	require.NoError(t, err)
	bobSign, err := NewBobSign(curve, msg, bobDkgResultMessage, protocol.Version1)
	require.NoError(t, err)

	// Sign
	t.Run("sign", func(t *testing.T) {
		aErr, bErr = runIteratedProtocol(bobSign, aliceSign)
		require.ErrorIs(t, aErr, protocol.ErrProtocolFinished)
		require.ErrorIs(t, bErr, protocol.ErrProtocolFinished)
	})
	// Don't continue to verifying results if sign didn't run to completion.
	require.ErrorIs(t, aErr, protocol.ErrProtocolFinished)
	require.ErrorIs(t, bErr, protocol.ErrProtocolFinished)

	// Output
	var result *curves.EcdsaSignature
	t.Run("bob produces result of correct type", func(t *testing.T) {
		resultMessage, err := bobSign.Result(protocol.Version1)
		require.NoError(t, err)
		result, err = DecodeSignature(resultMessage)
		require.NoError(t, err)
	})
	require.NotNil(t, result)

	t.Run("valid signature", func(t *testing.T) {
		hash := sha3.New256()
		_, err = hash.Write(msg)
		require.NoError(t, err)
		digest := hash.Sum(nil)
		unCompressedAffinePublicKey := aliceDkg.Output().PublicKey.ToAffineUncompressed()
		require.Equal(t, 65, len(unCompressedAffinePublicKey))
		x := new(big.Int).SetBytes(unCompressedAffinePublicKey[1:33])
		y := new(big.Int).SetBytes(unCompressedAffinePublicKey[33:])
		ecCurve, err := curve.ToEllipticCurve()
		require.NoError(t, err)
		publicKey := &curves.EcPoint{
			Curve: ecCurve,
			X:     x,
			Y:     y,
		}
		require.True(t,
			curves.VerifyEcdsa(publicKey,
				digest[:],
				result,
			),
			"signature failed verification",
		)
	})
}

// Decode > NewDklsSign > Sign > Output
// NOTE: this cold-start test ensures backwards compatibility with durable,
// encoding DKG state that may exist within production systems like test
// Breaking changes must consider downstream production impacts.
func TestSignColdStart(t *testing.T) {
	// Decode alice/bob state from file
	aliceDkg, err := ioutil.ReadFile("testdata/alice-dkls-v1-dkg.bin")
	require.NoError(t, err)
	bobDkg, err := ioutil.ReadFile("testdata/bob-dkls-v1-dkg.bin")
	require.NoError(t, err)

	// The choice of json marshaling is arbitrary, the binary could have been marshaled in other forms as well
	// The purpose here is to obtain an instance of `protocol.Message`

	aliceDkgMessage := &protocol.Message{}
	err = json.Unmarshal(aliceDkg, aliceDkgMessage)
	require.NoError(t, err)

	bobDkgMessage := &protocol.Message{}
	err = json.Unmarshal(bobDkg, bobDkgMessage)
	require.NoError(t, err)

	signV1(aliceDkgMessage, bobDkgMessage, t)
}

func TestEncodeDecode(t *testing.T) {
	curve := curves.K256()

	alice := NewAliceDkg(curve, protocol.Version1)
	bob := NewBobDkg(curve, protocol.Version1)
	_, _ = runIteratedProtocol(alice, bob)

	var aliceBytes []byte
	var bobBytes []byte
	t.Run("Encode Alice/Bob", func(t *testing.T) {
		aliceDkgMessage, err := EncodeAliceDkgOutput(alice.Alice.Output(), protocol.Version1)
		require.NoError(t, err)
		aliceBytes, err = json.Marshal(aliceDkgMessage)
		require.NoError(t, err)

		bobDkgMessage, err := EncodeBobDkgOutput(bob.Bob.Output(), protocol.Version1)
		require.NoError(t, err)
		bobBytes, err = json.Marshal(bobDkgMessage)
		require.NoError(t, err)
	})
	require.NotEmpty(t, aliceBytes)
	require.NotEmpty(t, bobBytes)

	t.Run("Decode Alice", func(t *testing.T) {
		decodedAliceMessage := &protocol.Message{}
		err := json.Unmarshal(aliceBytes, decodedAliceMessage)
		require.NoError(t, err)
		require.NotNil(t, decodedAliceMessage)
		decodedAlice, err := DecodeAliceDkgResult(decodedAliceMessage)
		require.NoError(t, err)

		require.True(t, alice.Output().PublicKey.Equal(decodedAlice.PublicKey))
		require.Equal(t, alice.Output().SecretKeyShare, decodedAlice.SecretKeyShare)
	})

	t.Run("Decode Bob", func(t *testing.T) {
		decodedBobMessage := &protocol.Message{}
		err := json.Unmarshal(bobBytes, decodedBobMessage)
		require.NoError(t, err)
		require.NotNil(t, decodedBobMessage)
		decodedBob, err := DecodeBobDkgResult(decodedBobMessage)
		require.NoError(t, err)

		require.True(t, bob.Output().PublicKey.Equal(decodedBob.PublicKey))
		require.Equal(t, bob.Output().SecretKeyShare, decodedBob.SecretKeyShare)
	})
}

func runV0IteratedProtocol(alice v0.ProtocolIterator, bob v0.ProtocolIterator) (error, error) {
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

// TestV0ToV1 tests the case where a DKG is run on V0 of the protocol and its output is used in V1 signing protocol.
func TestV0ToV1(t *testing.T) {
	params, err := v0.NewParams(btcec.S256(), curves.K256Scalar{})
	require.NoError(t, err)

	alice := v0.NewAliceDkg(params)
	bob := v0.NewBobDkg(params)
	_, _ = runV0IteratedProtocol(alice, bob)

	var aliceBytes []byte
	var bobBytes []byte
	t.Run("Encode Alice/Bob", func(t *testing.T) {
		aliceBytes, err = v0.EncodeAlice(alice.Alice)
		require.NoError(t, err)

		bobBytes, err = v0.EncodeBob(bob.Bob)
		require.NoError(t, err)
	})
	require.NotEmpty(t, aliceBytes)
	require.NotEmpty(t, bobBytes)

	signV0(params, aliceBytes, bobBytes, t)
	convertV0AndSignV1(params, aliceBytes, bobBytes, t)
}

// The content of this function are copied from the `proto_test.go` file in the v0 package.
func signV0(params *v0.Params, aliceBytes []byte, bobBytes []byte, t *testing.T) {
	aliceDkg, err := v0.DecodeAlice(params, aliceBytes)
	require.NoError(t, err)

	// New DklsSign
	msg := []byte("As soon as you trust yourself, you will know how to live.")
	digest := sha256.Sum256(msg)
	aliceSign, err := v0.NewAliceSign(params, digest[:], aliceBytes)
	require.NoError(t, err)
	bobSign, err := v0.NewBobSign(params, digest[:], bobBytes)
	require.NoError(t, err)

	// Sign
	var aErr error
	var bErr error
	t.Run("sign", func(t *testing.T) {
		aErr, bErr = runV0IteratedProtocol(aliceSign, bobSign)
		require.ErrorIs(t, aErr, io.EOF)
		require.ErrorIs(t, bErr, io.EOF)
	})
	// Don't continue to verifying results if sign didn't run to completion.
	require.ErrorIs(t, aErr, io.EOF)
	require.ErrorIs(t, bErr, io.EOF)

	// Result
	var result interface{}
	t.Run("bob produces result of correct type", func(t *testing.T) {
		result, err = bobSign.Result()
		require.NoError(t, err)
	})
	require.NotNil(t, result)
	require.IsType(t, &curves.EcdsaSignature{}, result)

	t.Run("valid signature", func(t *testing.T) {
		require.True(t,
			curves.VerifyEcdsa(aliceDkg.Pk,
				digest[:],
				result.(*curves.EcdsaSignature),
			),
			"signature failed verification",
		)
	})
}

func convertV0AndSignV1(params *v0.Params, aliceBytes []byte, bobBytes []byte, t *testing.T) {
	// Now convert the encoded value to V1 and then run the V1 signing protocol.
	aliceDkgResultMessage, err := ConvertAliceDkgOutputToV1(params, aliceBytes)
	require.NoError(t, err)

	bobDkgResultMessage, err := ConvertBobDkgOutputToV1(params, bobBytes)
	require.NoError(t, err)
	signV1(aliceDkgResultMessage, bobDkgResultMessage, t)
}

func signV1(aliceDkgResultMessage *protocol.Message, bobDkgResultMessage *protocol.Message, t *testing.T) {
	// New DklsSign
	curve := curves.K256()
	msg := []byte("As soon as you trust yourself, you will know how to live.")
	aliceSign, err := NewAliceSign(curve, msg, aliceDkgResultMessage, protocol.Version1)
	require.NoError(t, err)
	bobSign, err := NewBobSign(curve, msg, bobDkgResultMessage, protocol.Version1)
	require.NoError(t, err)

	// Sign
	var aErr error
	var bErr error
	t.Run("sign", func(t *testing.T) {
		aErr, bErr = runIteratedProtocol(bobSign, aliceSign)
		require.ErrorIs(t, aErr, protocol.ErrProtocolFinished)
		require.ErrorIs(t, bErr, protocol.ErrProtocolFinished)
	})
	// Don't continue to verifying results if sign didn't run to completion.
	require.ErrorIs(t, aErr, protocol.ErrProtocolFinished)
	require.ErrorIs(t, bErr, protocol.ErrProtocolFinished)

	// Output
	var result *curves.EcdsaSignature
	t.Run("bob produces result of correct type", func(t *testing.T) {
		resultMessage, err := bobSign.Result(protocol.Version1)
		require.NoError(t, err)
		result, err = DecodeSignature(resultMessage)
		require.NoError(t, err)
	})
	require.NotNil(t, result)

	aliceDkg, err := DecodeAliceDkgResult(aliceDkgResultMessage)
	require.NoError(t, err)

	t.Run("valid signature", func(t *testing.T) {
		hash := sha3.New256()
		_, err = hash.Write(msg)
		require.NoError(t, err)
		digest := hash.Sum(nil)
		unCompressedAffinePublicKey := aliceDkg.PublicKey.ToAffineUncompressed()
		require.Equal(t, 65, len(unCompressedAffinePublicKey))
		x := new(big.Int).SetBytes(unCompressedAffinePublicKey[1:33])
		y := new(big.Int).SetBytes(unCompressedAffinePublicKey[33:])
		ecCurve, err := curve.ToEllipticCurve()
		require.NoError(t, err)
		publicKey := &curves.EcPoint{
			Curve: ecCurve,
			X:     x,
			Y:     y,
		}
		require.True(t,
			curves.VerifyEcdsa(publicKey,
				digest[:],
				result,
			),
			"signature failed verification",
		)
	})
}
