//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha512"
	"flag"
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing"
	"math/big"

	dkg "github.com/coinbase/kryptology/pkg/dkg/frost"
	"github.com/btcsuite/btcd/btcec"
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
	curve := curves.K256()
	msg := []byte("All my bitcoin is stored here")
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

	pk := curve.ScalarBaseMult(sk)
	if !pk.Equal(verificationKey) {
		panic("verification keys are not equal")
	}

	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), sk.Bytes())
	hBytes := sha512.Sum384(msg)
	hMsg := new(big.Int).SetBytes(hBytes[:])
	hMsg.Mod(hMsg, btcec.S256().N)

	r, s, err := ecdsa.Sign(crand.Reader, privKey.ToECDSA(), hMsg.Bytes())
	if err != nil {
		panic(err)
	}
	ok := ecdsa.Verify(pubKey.ToECDSA(), hMsg.Bytes(), r, s)
	fmt.Printf("Signature verification - %v\n", ok)
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
	curve := curves.K256()
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
