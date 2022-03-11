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
	dkg "github.com/coinbase/kryptology/pkg/dkg/gennaro"
	sharing "github.com/coinbase/kryptology/pkg/sharing/v1"
	bls "github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
)

const LIMIT = 4
const THRESHOLD = 2

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

	// DEMO doing Gennaro DKG and that signers can compute a signature
	participants := createDkgParticipants(threshold, limit)

	// DKG Round 1
	rnd1Bcast, rnd1P2p := round1(participants)

	// DKG Round 2
	rnd2Bcast := round2(participants, rnd1Bcast, rnd1P2p)

	// DKG Round 3
	verificationKey, signingShares := round3(participants, rnd2Bcast)

	// Signing common setup for all participants
	scheme := bls.NewSigEth2()
	msg := []byte("All my bitcoin is stored here")

	// Signing
	partialSigs := make([]*bls.PartialSignature, 0, threshold)
	cnt := 0
	for id, sk := range signingShares {
		if cnt == threshold {
			break
		}
		cnt++
		fmt.Printf("Signing for participant %d\n", id)
		skShare := new(bls.SecretKeyShare)
		// secret share expects 1 byte identifier at the end of the array
		skBytes := make([]byte, bls.SecretKeyShareSize)
		copy(skBytes, sk[4:])
		skBytes[bls.SecretKeyShareSize-1] = sk[3]
		err := skShare.UnmarshalBinary(skBytes)
		if err != nil {
			panic(err)
		}

		sig, err := scheme.PartialSign(skShare, msg)
		if err != nil {
			panic(err)
		}
		partialSigs = append(partialSigs, sig)
	}
	if verificationKey == nil {
		panic("verification key was never complete")
	}

	sig, err := scheme.CombineSignatures(partialSigs...)
	if err != nil {
		panic(err)
	}

	curve := sharing.Bls12381G1()
	pkBytes, err := curve.CompressedBytesFromBigInts(verificationKey.X, verificationKey.Y)
	if err != nil {
		panic(err)
	}
	pk := new(bls.PublicKey)
	err = pk.UnmarshalBinary(pkBytes)
	if err != nil {
		panic(err)
	}

	ok, err := scheme.Verify(pk, msg, sig)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Signature verification - %v\n", ok)
}

func round1(participants map[uint32]*dkg.Participant) (map[uint32]dkg.Round1Bcast, map[uint32]dkg.Round1P2PSend) {
	// DKG Round 1
	rnd1Bcast := make(map[uint32]dkg.Round1Bcast, len(participants))
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

func round2(participants map[uint32]*dkg.Participant,
	rnd1Bcast map[uint32]dkg.Round1Bcast,
	rnd1P2p map[uint32]dkg.Round1P2PSend,
) map[uint32]dkg.Round2Bcast {
	rnd2Bcast := make(map[uint32]dkg.Round2Bcast, len(participants))
	for id := range rnd1Bcast {
		fmt.Printf("Computing DKG Round 2 for participant %d\n", id)

		rnd1P2pForP := make(map[uint32]*dkg.Round1P2PSendPacket)
		for jid := range rnd1P2p {
			if jid == id {
				continue
			}
			rnd1P2pForP[jid] = rnd1P2p[jid][id]
		}
		bcast, err := participants[id].Round2(rnd1Bcast, rnd1P2pForP)
		if err != nil {
			panic(err)
		}
		rnd2Bcast[id] = bcast
	}

	return rnd2Bcast
}

func round3(participants map[uint32]*dkg.Participant, rnd2Bcast map[uint32]dkg.Round2Bcast) (*curves.EcPoint, map[uint32][]byte) {
	signingShares := make(map[uint32][]byte, len(participants))
	var verificationKey *curves.EcPoint
	for id := range rnd2Bcast {
		fmt.Printf("Computing DKG Round 3 for participant %d\n", id)
		pk, sk, err := participants[id].Round3(rnd2Bcast)
		verificationKey = pk
		if err != nil {
			panic(err)
		}
		fmt.Printf("DKG completed for participant %d\n", id)
		signingShares[id] = sk.Bytes()
	}
	return verificationKey, signingShares
}

func createDkgParticipants(thresh, limit int) map[uint32]*dkg.Participant {
	curve := sharing.Bls12381G1()
	gx, gy := curve.Hash([]byte("Fair is foul, and foul is fair: Hover through the fog and filthy air."))
	generator := &curves.EcPoint{
		Curve: curve,
		X:     gx,
		Y:     gy,
	}
	participants := make(map[uint32]*dkg.Participant, limit)
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
		p, err := dkg.NewParticipant(uint32(i), uint32(thresh), generator, curves.NewBls12381Scalar(), otherIds...)
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
Simulate a DKG using BLS keys
FLAGS:
  -h, --help						Show this help message and exit
  -n, --limit						The total number of participants
  -t, --treshold					The minimum number of participants needed to sign
`)
}
