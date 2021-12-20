//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"crypto/sha512"
	"flag"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/ted25519/frost"

	"filippo.io/edwards25519"
	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
)

const LIMIT = 4
const THRESHOLD = 2
const Ctx = "string to prevent replay attack"

func main() {
	var threshold int
	var limit int
	var help bool
	flag.IntVar(&threshold, "t", THRESHOLD, "the minimum number of participants to sign")
	flag.IntVar(&threshold, "threshold", THRESHOLD, "the minimum number of participants to sign")
	flag.IntVar(&limit, "n", LIMIT, "the total number of participants")
	flag.IntVar(&limit, "limit", LIMIT, "the total number of participants")
	flag.BoolVar(&help, "h", false, "Print this menu")
	flag.BoolVar(&help, "help", false, "Print this menu")
	flag.Parse()

	if help {
		printHelp()
		return
	}

	fmt.Printf("Threshold is %d\n", threshold)
	fmt.Printf("Total participants is %d\n", limit)

	// DEMO doing FROST DKG and that signers can compute a signature
	participants := createDkgParticipants(threshold, limit)

	// DKG Round 1
	rnd1Bcast, rnd1P2p := round1(participants)

	// DKG Round 2
	verificationKey, signingShares := round2(participants, rnd1Bcast, rnd1P2p)

	// Signing common setup for all participants
	msg := []byte("All my bitcoin is stored here")
	curve := curves.ED25519()
	scheme, _ := sharing.NewShamir(uint32(threshold), uint32(limit), curve)
	shares := make([]*sharing.ShamirShare, 0, threshold)
	cnt := 0
	for _, share := range signingShares {
		if cnt == threshold {
			break
		}
		cnt++
		shares = append(shares, share)
	}
	sk, err := scheme.Combine(shares...)
	if err != nil {
		panic(err)
	}
	vk := curve.ScalarBaseMult(sk)
	if !vk.Equal(verificationKey) {
		panic("verification keys are not equal")
	}

	skC := sk.(*curves.ScalarEd25519).GetEdwardsScalar()

	r, s := sign(skC, vk.ToAffineCompressed(), []byte("no nonce"), msg)
	ok := verify(vk.ToAffineCompressed(), msg, r, s)
	fmt.Printf("Signature verification - %v\n", ok)

	// Test threshold signing
	lCoeffs, err := scheme.LagrangeCoeffs([]uint32{signingShares[1].Id, signingShares[2].Id})
	if err != nil {
		panic(err)
	}
	signers := make(map[uint32]*frost.Signer, 2)
	signers[1], err = frost.NewSigner(participants[1], 1, uint32(threshold), lCoeffs, []uint32{1, 2}, &frost.Ed25519ChallengeDeriver{})
	if err != nil {
		panic(err)
	}
	signers[2], err = frost.NewSigner(participants[2], 2, uint32(threshold), lCoeffs, []uint32{1, 2}, &frost.Ed25519ChallengeDeriver{})
	if err != nil {
		panic(err)
	}

	sigRnd1Bcast := make(map[uint32]*frost.Round1Bcast, 2)
	sigRnd1Bcast[1], err = signers[1].SignRound1()
	if err != nil {
		panic(err)
	}
	sigRnd1Bcast[2], err = signers[2].SignRound1()
	if err != nil {
		panic(err)
	}
	sigRng2BCast := make(map[uint32]*frost.Round2Bcast, 2)
	sigRng2BCast[1], err = signers[1].SignRound2(msg, sigRnd1Bcast)
	if err != nil {
		panic(err)
	}
	sigRng2BCast[2], err = signers[2].SignRound2(msg, sigRnd1Bcast)
	if err != nil {
		panic(err)
	}
	sigRng3BCast, err := signers[1].SignRound3(sigRng2BCast)
	if err != nil {
		panic(err)
	}

	sigR := sigRng3BCast.R.(*curves.PointEd25519).GetEdwardsPoint()
	sigS := sigRng3BCast.Z.(*curves.ScalarEd25519).GetEdwardsScalar()

	ok = verify(vk.ToAffineCompressed(), msg, sigR, sigS)
	fmt.Printf("Threshold Signature verification - %v\n", ok)
}

func sign(skC *edwards25519.Scalar, pubKey, nonce, msg []byte) (*edwards25519.Point, *edwards25519.Scalar) {
	h := sha512.New()
	_, _ = h.Write(nonce)
	_, _ = h.Write(msg)
	digest := h.Sum(nil)
	digestReduced, err := edwards25519.NewScalar().SetUniformBytes(digest)
	if err != nil {
		panic(err)
	}
	r := edwards25519.NewGeneratorPoint().ScalarBaseMult(digestReduced)

	encodedR := r.Bytes()
	h.Reset()
	_, _ = h.Write(encodedR)
	_, _ = h.Write(pubKey)
	_, _ = h.Write(msg)

	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	s := edwards25519.NewScalar().MultiplyAdd(k, skC, digestReduced)
	return r, s
}

func verify(pk, msg []byte, r *edwards25519.Point, s *edwards25519.Scalar) bool {
	h := sha512.New()
	_, _ = h.Write(r.Bytes())
	_, _ = h.Write(pk)
	_, _ = h.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		panic(err)
	}
	minusA, _ := edwards25519.NewIdentityPoint().SetBytes(pk)
	minusA.Negate(minusA)
	lhs := edwards25519.NewIdentityPoint().VarTimeDoubleScalarBaseMult(k, minusA, s)
	return lhs.Equal(r) == 1
}

func round1(participants map[uint32]*dkg.DkgParticipant) (map[uint32]*dkg.Round1Bcast, map[uint32]dkg.Round1P2PSend) {
	// DKG Round 1
	rnd1Bcast := make(map[uint32]*dkg.Round1Bcast, len(participants))
	rnd1P2p := make(map[uint32]dkg.Round1P2PSend, len(participants))
	for id, p := range participants {
		fmt.Printf("Computing DKG Round 1 for participant %d\n", id)
		bcast, p2psend, err := p.Round1(nil)
		if err != nil {
			panic(err)
		}
		rnd1Bcast[id] = bcast
		rnd1P2p[id] = p2psend
	}
	return rnd1Bcast, rnd1P2p
}

func round2(participants map[uint32]*dkg.DkgParticipant,
	rnd1Bcast map[uint32]*dkg.Round1Bcast,
	rnd1P2p map[uint32]dkg.Round1P2PSend,
) (curves.Point, map[uint32]*sharing.ShamirShare) {
	signingShares := make(map[uint32]*sharing.ShamirShare, len(participants))
	var verificationKey curves.Point
	for id := range rnd1Bcast {
		fmt.Printf("Computing DKG Round 2 for participant %d\n", id)
		rnd1P2pForP := make(map[uint32]*sharing.ShamirShare)
		for jid := range rnd1P2p {
			if jid == id {
				continue
			}
			rnd1P2pForP[jid] = rnd1P2p[jid][id]
		}
		rnd2Out, err := participants[id].Round2(rnd1Bcast, rnd1P2pForP)
		if err != nil {
			panic(err)
		}
		verificationKey = rnd2Out.VerificationKey
		share := &sharing.ShamirShare{
			Id:    id,
			Value: participants[id].SkShare.Bytes(),
		}
		signingShares[id] = share
	}
	return verificationKey, signingShares
}

func createDkgParticipants(thresh, limit int) map[uint32]*dkg.DkgParticipant {
	curve := curves.ED25519()
	participants := make(map[uint32]*dkg.DkgParticipant, limit)
	for i := 1; i <= limit; i++ {
		otherIds := make([]uint32, limit-1)
		idx := 0
		for j := 1; j <= limit; j++ {
			if i == j {
				continue
			}
			otherIds[idx] = uint32(j)
			idx++
		}
		p, err := dkg.NewDkgParticipant(uint32(i), uint32(thresh), Ctx, curve, otherIds...)
		if err != nil {
			panic(err)
		}
		participants[uint32(i)] = p
	}
	return participants
}

func printHelp() {
	fmt.Printf(`
ed25519 INPUT
Simulate a DKG using Ed25519 keys
FLAGS:
  -h, --help						Show this help message and exit
  -n, --limit						The total number of participants
  -t, --treshold					The minimum number of participants needed to sign
`)
}
