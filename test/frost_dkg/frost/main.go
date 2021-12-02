//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"flag"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/coinbase/kryptology/pkg/sharing"
	"github.com/coinbase/kryptology/pkg/ted25519/frost"
)

const LIMIT = 5
const THRESHOLD = 3
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
	fmt.Printf("**FROST DKG Round 1**\n")
	rnd1Bcast, rnd1P2p := round1(participants)

	// DKG Round 2
	fmt.Printf("**FROST DKG Round 2**\n")
	verificationKey, _ := round2(participants, rnd1Bcast, rnd1P2p)

	// Prepare Lagrange coefficients
	curve := curves.ED25519()
	scheme, _ := sharing.NewShamir(uint32(threshold), uint32(limit), curve)
	shares := make([]*sharing.ShamirShare, threshold)
	for i := 0; i < threshold; i++ {
		shares[i] = &sharing.ShamirShare{Id: uint32(i + 1), Value: participants[uint32(i+1)].SkShare.Bytes()}
	}

	lCoeffs, _ := scheme.LagrangeCoeffs(map[uint32]*sharing.ShamirShare{
		shares[0].Id: shares[0],
		shares[1].Id: shares[1],
		shares[2].Id: shares[2],
	})

	// Using signer starting from 1 as cosigners
	var err error
	signerIds := make([]uint32, threshold)
	for i := 0; i < threshold; i++ {
		signerIds[i] = uint32(i + 1)
	}
	signers := make(map[uint32]*frost.Signer, threshold)
	for i := 1; i <= threshold; i++ {
		signers[uint32(i)], err = frost.NewSigner(participants[uint32(i)], uint32(i), uint32(threshold), lCoeffs, signerIds, &frost.Ed25519ChallengeDeriver{})
		if err != nil {
			panic(err)
		}
	}

	// Running sign round 1
	fmt.Printf("**FROST Sign Round 1**\n")
	round2Input := make(map[uint32]*frost.Round1Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		fmt.Printf("Computing Sign Round 1 for cosigner %d\n", i)
		round1Out, err := signers[uint32(i)].SignRound1()
		if err != nil {
			panic(err)
		}
		round2Input[uint32(i)] = round1Out
	}

	// Running sign round 2
	fmt.Printf("**FROST Sign Round 2**\n")
	msg := []byte("message")
	round3Input := make(map[uint32]*frost.Round2Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		fmt.Printf("Computing Sign Round 2 for cosigner %d\n", i)
		round2Out, err := signers[uint32(i)].SignRound2(msg, round2Input)
		if err != nil {
			panic(err)
		}
		round3Input[uint32(i)] = round2Out
	}

	// Running sign round 3
	fmt.Printf("**FROST Sign Round 3**\n")
	result := make(map[uint32]*frost.Round3Bcast, threshold)
	for i := 1; i <= threshold; i++ {
		fmt.Printf("Computing Sign Round 3 for cosigner %d\n", i)
		round3Out, err := signers[uint32(i)].SignRound3(round3Input)
		if err != nil {
			panic(err)
		}
		result[uint32(i)] = round3Out
	}

	// Verify everybody's signature is valid
	deriver := &frost.Ed25519ChallengeDeriver{}
	for i := 1; i <= threshold; i++ {
		Z := result[uint32(i)].Z
		C := result[uint32(i)].C
		// Compute R' = z*G + (-c)*vk
		zG := curve.ScalarBaseMult(Z)
		cvk := verificationKey.Mul(C.Neg())
		tempR := zG.Add(cvk)
		// Step 6 - c' = H(m, R')
		tempC, err := deriver.DeriveChallenge(msg, verificationKey, tempR)
		if err != nil {
			panic(err)
		}

		// Step 7 - Check c = c'
		if tempC.Cmp(C) != 0 {
			fmt.Printf("invalid signature: c != c' for signer %d\n", i)
		}
	}
	fmt.Printf("Signature is computed successfully!\n")
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
bls INPUT
Simulate a DKG using K256 keys
FLAGS:
  -h, --help						Show this help message and exit
  -n, --limit						The total number of participants
  -t, --treshold					The minimum number of participants needed to sign
`)
}
