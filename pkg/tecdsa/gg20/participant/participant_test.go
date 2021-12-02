//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"

	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/stretchr/testify/assert"

	"github.com/coinbase/kryptology/internal"
	"github.com/btcsuite/btcd/btcec"
)

func TestConvertToAdditiveWorks(t *testing.T) {
	curve := btcec.S256()
	_, shares, err := dealer.NewDealerShares(curve, 3, 5, nil)
	if err != nil {
		t.Errorf("NewDealerShares failed: %v", err)
	}
	publicShares, err := dealer.PreparePublicShares(shares)
	if err != nil {
		t.Errorf("PreparePublicShares failed: %v", err)
	}

	for _, s := range shares {
		pi := Participant{
			dealer.Share{
				ShamirShare: s.ShamirShare,
				Point:       s.Point,
			},
			nil,
		}
		_, err := pi.convertToAdditive(curve, publicShares)
		if err != nil {
			t.Errorf("convertToAdditive failed: %v", err)
		}
	}
}

func TestConvertToAdditiveNil(t *testing.T) {
	curve := btcec.S256()
	var publicSharesMap map[uint32]*dealer.PublicShare

	pi := Participant{Share: dealer.Share{}}
	_, err := pi.convertToAdditive(curve, publicSharesMap)
	if err == nil {
		t.Errorf("convertToAdditive should've failed")
	}
	_, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
	if err != nil {
		t.Errorf("NewDealerShares failed: %v", err)
	}
	publicSharesMap, err = dealer.PreparePublicShares(shares)
	if err != nil {
		t.Errorf("PreparePublicShares failed: %v", err)
	}

	_, err = pi.convertToAdditive(curve, publicSharesMap)
	if err == nil {
		t.Errorf("convertToAdditive should've failed")
	}
}

func TestConvertToAdditiveNotEnoughShares(t *testing.T) {
	curve := btcec.S256()
	_, shares, err := dealer.NewDealerShares(curve, 2, 3, nil)
	if err != nil {
		t.Errorf("NewDealerShares failed: %v", err)
	}
	publicSharesMap, err := dealer.PreparePublicShares(shares)
	if err != nil {
		t.Errorf("PreparePublicShares failed: %v", err)
	}

	pi := Participant{Share: dealer.Share{}}

	_, err = pi.convertToAdditive(curve, map[uint32]*dealer.PublicShare{})
	internal.AssertSomeError(t, err)

	_, err = pi.convertToAdditive(curve, map[uint32]*dealer.PublicShare{1: publicSharesMap[1]})
	internal.AssertSomeError(t, err)
}

func TestConvertToAdditiveRecombine(t *testing.T) {
	curve := btcec.S256()
	pk, sharesMap, err := dealer.NewDealerShares(curve, 3, 5, nil)
	if err != nil {
		t.Errorf("NewDealerShares failed: %v", err)
	}

	// 5*4*3 possible combinations, try them all.
	for i, s := range sharesMap {
		pi := Participant{
			dealer.Share{
				ShamirShare: s.ShamirShare,
				Point:       s.Point,
			}, nil,
		}
		for j := range sharesMap {
			if i == j {
				continue
			}

			for k := range sharesMap {
				if k == i || k == j {
					continue
				}

				// Downsize to this particular set of signers
				signerMap := map[uint32]*dealer.Share{
					i: sharesMap[i],
					j: sharesMap[j],
					k: sharesMap[k],
				}
				publicSharesMap, err := dealer.PreparePublicShares(signerMap)
				if err != nil {
					t.Errorf("PreparePublicShares failed: %v", err)
				}

				pss, err := pi.convertToAdditive(curve,
					map[uint32]*dealer.PublicShare{
						i: publicSharesMap[i],
						j: publicSharesMap[j],
						k: publicSharesMap[k]})
				if err != nil {
					t.Errorf("convertToAdditive failed: %v", err)
				}

				// See if combining works
				x := new(big.Int)
				y := new(big.Int)
				for _, ps := range pss.publicSharesMap {
					x, y = curve.Add(x, y, ps.Point.X, ps.Point.Y)
				}

				internal.AssertBigIntEq(t, pk.X, x)
				internal.AssertBigIntEq(t, pk.Y, y)
			}
		}
	}
}

// Test that verifyStateMap checks rounds as expected
func TestVerifyStateMapRoundCheck(t *testing.T) {
	tests := []struct {
		name       string
		stateRound uint
		roundIn    uint
		expected   error
	}{
		{"positive", 5, 5, nil},
		{"positive", 6, 6, nil},
		{"positive", 1, 1, nil},
		{"positive", 5, 5, nil},
		{"negative", 5, 0, internal.ErrInvalidRound},
		{"negative", 1, 2, internal.ErrInvalidRound},
		{"negative", 3, 5, internal.ErrInvalidRound},
	}
	// Run all the tests!
	for _, test := range tests {
		s := &Signer{}

		t.Run(test.name, func(t *testing.T) {
			// set the state round
			s.Round = test.stateRound

			// test
			err := s.verifyStateMap(test.roundIn, nil)

			// verify the error is as expected
			if err != test.expected {
				t.Errorf("unexpected error: want=%v got=%v", test.expected, err)
			}
		})
	}
}

// Test that verifyStateMap checks rounds as expected
func TestSetCosigners(t *testing.T) {
	tests := []struct {
		name        string
		cosigners   map[uint32]*Round1Bcast
		threshold   int
		expectedErr error
		expectedLen int
	}{
		{
			name:        "includes-self",
			cosigners:   map[uint32]*Round1Bcast{1: {}, 2: {}, 5: {}},
			threshold:   3,
			expectedErr: nil,
			expectedLen: 3,
		},
		{
			name:        "excludes-self",
			cosigners:   map[uint32]*Round1Bcast{1: {}, 5: {}},
			threshold:   3,
			expectedErr: nil,
			expectedLen: 2,
		},
		{
			name:        "wrong-length",
			cosigners:   map[uint32]*Round1Bcast{1: {}, 5: {}},
			threshold:   4,
			expectedErr: internal.ErrIncorrectCount,
			expectedLen: 0,
		},
	}
	// Run all the tests!
	for _, test := range tests {
		s := &Signer{}

		t.Run(test.name, func(t *testing.T) {
			// setup
			s.resetSignRound()
			s.state = &state{}
			s.threshold = uint(test.threshold)

			cosigners := make([]uint32, 0)
			for k := range test.cosigners {
				cosigners = append(cosigners, k)
			}

			err := s.setCosigners(cosigners)

			// did we get the expected result?
			if err != test.expectedErr {
				t.Errorf("wrong error. want=%v  got=%v", test.expectedErr, err)
			}
			if len(s.state.cosigners) != test.expectedLen {
				t.Errorf("wrong length. want=%v  got=%v", test.expectedErr.Error(), len(test.cosigners))
			}
		})
	}
}

// Test that verifyStateMap checks rounds as expected
func TestVerifyStateMapCosigners(t *testing.T) {
	tests := []struct {
		name        string
		self        uint32
		cosigners   map[uint32]*Round1Bcast
		testSigners map[uint32]bool
		expectedOk  bool
	}{
		{
			name:        "positive-1-2-5-with-self",
			self:        5,
			cosigners:   map[uint32]*Round1Bcast{1: {}, 2: {}, 5: {}},
			testSigners: map[uint32]bool{1: true, 2: false, 5: true},
			expectedOk:  true,
		},
		{
			name:        "positive-1-2-5-with-self-excluded-from-cosigners",
			self:        5,
			cosigners:   map[uint32]*Round1Bcast{1: {}, 2: {}},
			testSigners: map[uint32]bool{1: true, 2: false, 5: true},
			expectedOk:  true,
		},
		{
			name:        "positive-1-2-missing-self",
			self:        5,
			cosigners:   map[uint32]*Round1Bcast{1: {}, 2: {}},
			testSigners: map[uint32]bool{1: true, 2: false},
			expectedOk:  true,
		},
		{
			name:        "positive-1-2-10",
			self:        1,
			cosigners:   map[uint32]*Round1Bcast{1: {}, 2: {}, 10: {}},
			testSigners: map[uint32]bool{1: true, 2: false, 10: false},
			expectedOk:  true,
		},
		{
			name:        "negative-missing-5",
			self:        1,
			cosigners:   map[uint32]*Round1Bcast{1: {}, 2: {}, 5: {}},
			testSigners: map[uint32]bool{1: true, 2: false},
			expectedOk:  false,
		},
		{
			name:        "negative-missing-2",
			self:        1,
			cosigners:   map[uint32]*Round1Bcast{1: {}, 2: {}, 5: {}},
			testSigners: map[uint32]bool{1: true, 5: false},
			expectedOk:  false,
		},
	}
	// Run all the tests!
	for _, test := range tests {
		s := &Signer{}

		t.Run(test.name, func(t *testing.T) {
			// setup
			s.resetSignRound()
			s.state = &state{}
			s.id = test.self
			s.threshold = 3
			cosigners := make([]uint32, 0)
			for id := range test.cosigners {
				cosigners = append(cosigners, id)
			}
			err := s.setCosigners(cosigners)
			internal.AssertNoError(t, err)

			// func under test
			err = s.verifyStateMap(1, test.testSigners)
			// did we get the expected result?
			if test.expectedOk {
				internal.AssertNoError(t, err)
			} else {
				internal.AssertSomeError(t, err)
			}
		})
	}
}

func TestNormalizeSK256(t *testing.T) {
	// btcec always produces normalized signatures
	// instead just double check that s gets negated
	curve := btcec.S256()

	signer := Signer{
		state: &state{},
	}
	signer.Curve = curve
	qDiv2, ok := new(big.Int).SetString("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16)
	if !ok {
		t.Error("Couldn't convert q/2")
	}
	for i := 0; i < 500; i++ {
		s, err := core.Rand(qDiv2)
		assert.NoError(t, err)

		sNorm := signer.normalizeS(s)

		assert.Equal(t, s, sNorm)
	}
	for i := 0; i < 500; i++ {
		s, err := core.Rand(qDiv2)
		s.Add(s, qDiv2)
		assert.NoError(t, err)

		sNorm := signer.normalizeS(s)

		assert.NotEqual(t, s, sNorm)
	}
}

func TestNormalizeSK256Identity(t *testing.T) {
	curve := btcec.S256()

	signer := Signer{
		state: &state{},
	}
	signer.Curve = curve
	for i := 0; i < 1000; i++ {
		msg, err := core.Rand(curve.N)
		assert.NoError(t, err)
		sk, err := btcec.NewPrivateKey(curve)
		assert.NoError(t, err)

		sig, err := sk.Sign(msg.Bytes())
		assert.NoError(t, err)

		sNorm := signer.normalizeS(sig.S)

		assert.Equal(t, sig.S, sNorm)
	}
}

func TestNormalizeSP256(t *testing.T) {
	p256 := elliptic.P256()
	signer := Signer{
		state: &state{},
	}
	signer.Curve = p256
	sk, err := ecdsa.GenerateKey(p256, rand.Reader)
	assert.NoError(t, err)
	for i := 0; i < 1000; i++ {
		msg, err := core.Rand(p256.Params().N)
		assert.NoError(t, err)
		r, s, err := ecdsa.Sign(rand.Reader, sk, msg.Bytes())
		assert.NoError(t, err)

		newS := signer.normalizeS(s)
		assert.True(t, ecdsa.Verify(&sk.PublicKey, msg.Bytes(), r, newS))
	}
}

func TestSerializeParticipantData(t *testing.T) {
	participants := 5
	curve := btcec.S256()
	ecdsaPk, sharesMap, err := dealer.NewDealerShares(curve, 3, uint32(participants), nil)
	assert.NoError(t, err)
	pubSharesMap, err := dealer.PreparePublicShares(sharesMap)
	assert.NoError(t, err)
	paillierKeys := make(map[uint32]*paillier.SecretKey, participants)
	encryptKeys := make(map[uint32]*paillier.PublicKey, participants)
	for i, k := range genPrimesArray(participants) {
		id := uint32(i + 1)
		paillierKeys[id], err = paillier.NewSecretKey(k.p, k.q)
		encryptKeys[id] = paillier.NewPubkey(paillierKeys[id].PublicKey.N)
		assert.NoError(t, err)
	}

	keyGenType := dealer.TrustedDealerKeyGenType{
		ProofParams: dealerParams,
	}

	p := dealer.ParticipantData{
		EcdsaPublicKey: ecdsaPk,
		KeyGenType:     keyGenType,
		PublicShares:   pubSharesMap,
		EncryptKeys:    encryptKeys,
	}

	for i := 0; i < participants; i++ {
		id := uint32(i + 1)
		p.Id = id
		p.DecryptKey = paillierKeys[id]
		p.SecretKeyShare = sharesMap[id]

		data, err := json.Marshal(p)
		assert.NoError(t, err)

		p2 := new(dealer.ParticipantData)
		assert.NoError(t, json.Unmarshal(data, p2))
		assert.Equal(t, p.Id, p2.Id)
		assert.Equal(t, p.DecryptKey, p2.DecryptKey)
		assert.Equal(t, p.SecretKeyShare, p2.SecretKeyShare)
		assert.Equal(t, p.KeyGenType, p2.KeyGenType)
		assert.Equal(t, p.EcdsaPublicKey, p2.EcdsaPublicKey)
		assert.Equal(t, p.EncryptKeys, p2.EncryptKeys)
		assert.Equal(t, p.PublicShares, p2.PublicShares)
	}
}
