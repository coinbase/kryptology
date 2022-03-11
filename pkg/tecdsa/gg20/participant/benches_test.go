//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"crypto/elliptic"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"
)

func BenchmarkDealingProofParams(b *testing.B) {
	if testing.Short() {
		b.SkipNow()
	}

	for i := 0; i < b.N; i++ {
		_, err := dealer.NewProofParams()
		require.NoError(b, err)
	}
}

func BenchmarkDealingShares(b *testing.B) {
	// Skip these benchmarks in short-mode because they're high-variance and
	// they trigger the regression testing hook.
	if testing.Short() {
		b.SkipNow()
	}

	curve := btcec.S256()
	b.Run("Secp256k1 - 2 of 2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 2, 2)
			require.NoError(b, err)
		}
	})
	b.Run("Secp256k1 - 2 of 3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 2, 3)
			require.NoError(b, err)
		}
	})
	b.Run("Secp256k1 - 3 of 5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 3, 5)
			require.NoError(b, err)
		}
	})
	b.Run("Secp256k1 - 4 of 7", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 4, 7)
			require.NoError(b, err)
		}
	})
	b.Run("Secp256k1 - 5 of 9", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 5, 9)
			require.NoError(b, err)
		}
	})

	b.Run("Secp256k1 - 10 of 19", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 10, 19)
			require.NoError(b, err)
		}
	})
	b.Run("Secp256k1 - 25 of 49", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 25, 49)
			require.NoError(b, err)
		}
	})
	b.Run("Secp256k1 - 50 of 99", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 50, 99)
			require.NoError(b, err)
		}
	})
	b.Run("Secp256k1 - 100 of 199", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := benchDealShares(curve, 100, 199)
			require.NoError(b, err)
		}
	})
}

func benchDealShares(curve elliptic.Curve, threshold, count uint32) error {
	_, sharesMap, err := dealer.NewDealerShares(curve, threshold, count, nil)
	if err != nil {
		return err
	}
	for len(sharesMap) > 3 {
		delete(sharesMap, uint32(len(sharesMap)))
	}
	_, err = dealer.PreparePublicShares(sharesMap)
	return err
}

func BenchmarkDealingPaillierKeys(b *testing.B) {
	if testing.Short() {
		b.SkipNow()
	}

	for i := 0; i < b.N; i++ {
		_, _, err := paillier.NewKeys()
		require.NoError(b, err)
	}
}

func BenchmarkSigning(b *testing.B) {
	curve := btcec.S256()
	hash, err := core.Hash([]byte("It is not good to have a rule of many."), curve)
	require.NoError(b, err)
	hashBytes := hash.Bytes()

	b.Run("Secp256k1 - 2 of 2", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 2, 2),
			)
		}
	})
	b.Run("Secp256k1 - 2 of 3", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 2, 3),
			)
		}
	})
	b.Run("Secp256k1 - 3 of 5", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 3, 5),
			)
		}
	})
	b.Run("Secp256k1 - 4 of 7", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 4, 7),
			)
		}
	})
	b.Run("Secp256k1 - 5 of 9", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 5, 9),
			)
		}
	})

	// Skip long-running tests in `-short` mode
	if testing.Short() {
		b.SkipNow()
	}

	b.Run("Secp256k1 - 10 of 19", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 10, 19),
			)
		}
	})
	b.Run("Secp256k1 - 25 of 49", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 25, 49),
			)
		}
	})
	b.Run("Secp256k1 - 50 of 99", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 50, 99),
			)
		}
	})
	b.Run("Secp256k1 - 100 of 199", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			require.NoError(b,
				benchSign(b, hashBytes, curve, k256Verifier, 100, 199),
			)
		}
	})
}

func benchSign(b *testing.B, hash []byte, curve elliptic.Curve, verify curves.EcdsaVerify, threshold, count uint32) error {
	// Setup signers
	b.StopTimer()

	pk, sharesMap, _ := dealer.NewDealerShares(curve, threshold, count, nil)
	for len(sharesMap) > int(threshold) {
		delete(sharesMap, uint32(len(sharesMap)))
	}
	pubSharesMap, _ := dealer.PreparePublicShares(sharesMap)
	keysMap := make(map[uint32]*paillier.SecretKey, threshold)
	pubKeys := make(map[uint32]*paillier.PublicKey, threshold)
	keyPrimesArray := genPrimesArray(int(threshold))
	for i := range sharesMap {
		keysMap[i], _ = paillier.NewSecretKey(keyPrimesArray[i-1].p, keyPrimesArray[i-1].q)
		pubKeys[i] = &keysMap[i].PublicKey
	}
	proofParams := &dealer.TrustedDealerKeyGenType{
		ProofParams: dealerParams,
	}

	signersMap := make(map[uint32]*Signer, threshold)
	for i, k := range keysMap {
		p := Participant{*sharesMap[i], k}
		signersMap[i], _ = p.PrepareToSign(pk, verify, curve, proofParams, pubSharesMap, pubKeys)
	}

	// Ignore the setup in the benchmarks
	b.StartTimer()

	// Run signing rounds
	// Sign Round 1
	var err error
	signerOut := make(map[uint32]*Round1Bcast, threshold)
	for i, s := range signersMap {
		signerOut[i], _, err = s.SignRound1()
		if err != nil {
			return err
		}
	}

	// Sign Round 2
	p2p := make(map[uint32]map[uint32]*P2PSend)
	for i, s := range signersMap {
		in := make(map[uint32]*Round1Bcast, threshold-1)
		for j := range signersMap {
			if i == j {
				continue
			}
			in[j] = signerOut[j]
		}
		p2p[i], err = s.SignRound2(in, nil) // TODO: fix me later
		if err != nil {
			return nil
		}
	}

	// Sign Round 3
	r3Bcast := make(map[uint32]*Round3Bcast, threshold)
	for i, s := range signersMap {
		in := make(map[uint32]*P2PSend, threshold-1)
		for j := range signersMap {
			if i == j {
				continue
			}
			in[j] = p2p[j][i]
		}
		r3Bcast[i], err = s.SignRound3(in)
		if err != nil {
			return err
		}
	}

	// Sign Round 4
	r4Bcast := make(map[uint32]*Round4Bcast, threshold)
	for i, s := range signersMap {
		in := make(map[uint32]*Round3Bcast, threshold-1)
		for j := range signersMap {
			if i == j {
				continue
			}
			in[j] = r3Bcast[j]
		}
		r4Bcast[i], err = s.SignRound4(in)
		if err != nil {
			return err
		}
	}

	// Sign Round 5
	r5Bcast := make(map[uint32]*Round5Bcast, threshold)
	r5P2p := make(map[uint32]map[uint32]*Round5P2PSend, threshold)
	for i, s := range signersMap {
		in := make(map[uint32]*Round4Bcast, threshold-1)
		for j := range signersMap {
			if i == j {
				continue
			}
			in[j] = r4Bcast[j]
		}
		r5Bcast[i], r5P2p[i], err = s.SignRound5(in)
		if err != nil {
			return err
		}
	}

	// Sign Round 6
	r6Bcast := make(map[uint32]*Round6FullBcast, threshold)
	for i, s := range signersMap {
		in := make(map[uint32]*Round5Bcast, threshold-1)
		for j := range signersMap {
			if i == j {
				continue
			}
			in[j] = r5Bcast[j]
		}
		r6Bcast[i], err = s.SignRound6Full(hash, in, r5P2p[i])
		if err != nil {
			return err
		}
	}

	// Signature output
	for i, s := range signersMap {
		in := make(map[uint32]*Round6FullBcast, threshold-1)
		for j := range signersMap {
			if i == j {
				continue
			}
			in[j] = r6Bcast[j]
		}
		_, err = s.SignOutput(in)
		if err != nil {
			return err
		}
	}

	return nil
}

// Benchmark 2-party signing
func BenchmarkSign2p(b *testing.B) {
	// Dealer-related setup (not part of signing being measured)
	k256 := btcec.S256()

	pk, sharesMap, err := dealer.NewDealerShares(k256, 2, 2, nil)
	require.NoError(b, err)

	pubSharesMap, err := dealer.PreparePublicShares(sharesMap)
	require.NoError(b, err)

	keyPrimesArray := genPrimesArray(2)
	paillier1, err := paillier.NewSecretKey(keyPrimesArray[0].p, keyPrimesArray[0].q)
	require.NoError(b, err)
	paillier2, err := paillier.NewSecretKey(keyPrimesArray[1].p, keyPrimesArray[1].q)
	require.NoError(b, err)

	dealerSetup := &signingSetup{
		curve:        k256,
		pk:           pk,
		sharesMap:    sharesMap,
		pubSharesMap: pubSharesMap,
		pubkeys: map[uint32]*paillier.PublicKey{
			1: &paillier1.PublicKey,
			2: &paillier2.PublicKey,
		},
		privkeys: map[uint32]*paillier.SecretKey{
			1: paillier1,
			2: paillier2,
		},
		proofParams: &dealer.TrustedDealerKeyGenType{
			ProofParams: dealerParams,
		},
	}

	b.ResetTimer()

	msgMetrics := &msgCounter{}
	for i := 0; i < b.N; i++ {
		sign2p(b, msgMetrics, dealerSetup)
	}

	// Report mean messaging metrics
	b.ReportMetric(float64(msgMetrics.messages/b.N), "msgs/sign")
	b.ReportMetric(float64(msgMetrics.bytes/b.N), "bytes/sign")
}

type signingSetup struct {
	curve        elliptic.Curve
	pk           *curves.EcPoint
	sharesMap    map[uint32]*dealer.Share
	pubSharesMap map[uint32]*dealer.PublicShare
	pubkeys      map[uint32]*paillier.PublicKey
	privkeys     map[uint32]*paillier.SecretKey
	proofParams  *dealer.TrustedDealerKeyGenType
}

// Run a 2-party signing protocol and report messaging metrics.
func sign2p(b *testing.B, bw *msgCounter, setup *signingSetup) {
	// Hash of message for signature
	hashBi, err := core.Hash([]byte("I will be brief. Your noble son is mad."), setup.curve)
	require.NoError(b, err)
	msgHash := hashBi.Bytes()

	// Create signers
	p1 := Participant{*setup.sharesMap[1], setup.privkeys[1]}
	s1, err := p1.PrepareToSign(
		setup.pk,
		k256Verifier,
		setup.curve,
		setup.proofParams,
		setup.pubSharesMap,
		setup.pubkeys)
	require.NoError(b, err)

	p2 := Participant{*setup.sharesMap[2], setup.privkeys[2]}
	s2, err := p2.PrepareToSign(
		setup.pk,
		k256Verifier,
		setup.curve,
		setup.proofParams,
		setup.pubSharesMap,
		setup.pubkeys)
	require.NoError(b, err)

	//
	// Sign Round 1
	//
	r1_s1_bcast, r1_s1_p2p, err := s1.SignRound1()
	require.NoError(b, err)

	r1_s2_bcast, r1_s2_p2p, err := s2.SignRound1()
	require.NoError(b, err)

	// Count R1 msgs
	require.NoError(b,
		bw.Count(
			r1_s1_bcast,
			r1_s1_p2p,
			r1_s2_bcast,
			r1_s2_p2p,
		))
	b.Log()
	b.Logf("R1 %#v", bw)

	//
	// Sign Round 2
	//
	r2_s1_p2p, err := s1.SignRound2(
		map[uint32]*Round1Bcast{2: r1_s2_bcast},
		map[uint32]*Round1P2PSend{2: r1_s2_p2p[1]},
	)
	require.NoError(b, err)

	r2_s2_p2p, err := s2.SignRound2(
		map[uint32]*Round1Bcast{1: r1_s1_bcast},
		map[uint32]*Round1P2PSend{1: r1_s1_p2p[2]},
	)
	require.NoError(b, err)

	// Count R2 msgs
	require.NoError(b,
		bw.Count(
			r2_s1_p2p,
			r2_s2_p2p,
		))
	b.Logf("R2 %#v", bw)

	//
	// Sign Round 3
	//
	r3_s1_bcast, err := s1.SignRound3(
		map[uint32]*P2PSend{2: r2_s2_p2p[1]},
	)
	require.NoError(b, err)

	r3_s2_bcast, err := s2.SignRound3(
		map[uint32]*P2PSend{1: r2_s1_p2p[2]},
	)
	require.NoError(b, err)

	// Count R3 msgs
	require.NoError(b,
		bw.Count(
			r3_s1_bcast,
			r3_s2_bcast,
		))
	b.Logf("R3 %#v", bw)

	//
	// Sign Round 4
	//
	r4_s1_bcast, err := s1.SignRound4(
		map[uint32]*Round3Bcast{2: r3_s2_bcast})
	require.NoError(b, err)

	r4_s2_bcast, err := s2.SignRound4(
		map[uint32]*Round3Bcast{1: r3_s1_bcast})
	require.NoError(b, err)

	// Count R4 msgs
	require.NoError(b,
		bw.Count(
			r4_s1_bcast,
			r4_s2_bcast,
		))
	b.Logf("R4 %#v", bw)

	//
	// Sign Round 5
	//
	r5_s1_bcast, r5_s1_p2p, err := s1.SignRound5(
		map[uint32]*Round4Bcast{2: r4_s2_bcast},
	)
	require.NoError(b, err)

	r5_s2_bcast, r5_s2_p2p, err := s2.SignRound5(
		map[uint32]*Round4Bcast{1: r4_s1_bcast},
	)
	require.NoError(b, err)

	// Count R5 msgs
	require.NoError(b,
		bw.Count(
			r5_s1_bcast,
			r5_s1_p2p,
			r5_s2_bcast,
			r5_s2_p2p,
		))
	b.Logf("R5 %#v", bw)

	//
	// Sign Round 6
	//
	r6_s1_bcast, err := s1.SignRound6Full(msgHash,
		map[uint32]*Round5Bcast{2: r5_s2_bcast},
		map[uint32]*Round5P2PSend{2: r5_s2_p2p[1]},
	)
	require.NoError(b, err)

	r6_s2_bcast, err := s2.SignRound6Full(msgHash,
		map[uint32]*Round5Bcast{1: r5_s1_bcast},
		map[uint32]*Round5P2PSend{1: r5_s1_p2p[2]},
	)
	require.NoError(b, err)

	// Count R6 msgs
	require.NoError(b,
		bw.Count(
			r6_s1_bcast,
			r6_s2_bcast,
		))
	b.Logf("R6 %#v", bw)

	//
	// Compute signature
	//

	s1_sig, err := s1.SignOutput(
		map[uint32]*Round6FullBcast{2: r6_s2_bcast},
	)
	require.NoError(b, err)

	s2_sig, err := s2.SignOutput(
		map[uint32]*Round6FullBcast{1: r6_s1_bcast},
	)
	require.NoError(b, err)

	// Verify that both parties compute the same signature
	require.Equal(b, s1_sig, s2_sig, "computed ECDSA signature do not match")
}

// Tracks messaging-related metrics: msg count, serialized total bytes
type msgCounter struct {
	bytes    int
	messages int
}

// Accumulates message and byte counts
func (m *msgCounter) Count(msgs ...interface{}) error {
	for _, msg := range msgs {
		if msg == nil {
			continue
		}
		// Count a discrete message
		m.messages++

		// Serialize and count the byte length
		msgBytes, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		// fmt.Println(string(msgBytes))
		m.bytes += len(msgBytes)
	}
	return nil
}
