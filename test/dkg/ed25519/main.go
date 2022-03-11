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

	"filippo.io/edwards25519"

	"github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core/curves"
	dkg "github.com/coinbase/kryptology/pkg/dkg/gennaro"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
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
	msg := []byte("All my bitcoin is stored here")
	curve := v1.Ed25519()
	scheme, _ := v1.NewShamir(threshold, limit, curves.NewField(curve.N))
	shares := make([]*v1.ShamirShare, 0, threshold)
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

	sk = internal.ReverseScalarBytes(sk)
	var ska [32]byte
	copy(ska[:], sk[:])

	skC, err := edwards25519.NewScalar().SetCanonicalBytes(ska[:])
	if err != nil {
		panic(err)
	}
	vk := edwards25519.NewIdentityPoint().ScalarBaseMult(skC)
	vk2, err := internal.BigInt2Ed25519Point(verificationKey.Y)
	if err != nil {
		panic(err)
	}
	if vk.Equal(vk2) == 0 {
		panic("not equal")
	}

	r, s := sign(skC, vk2.Bytes(), []byte("no nonce"), msg)

	ok := verify(vk2.Bytes(), msg, r, s)

	fmt.Printf("Signature verification - %v\n", ok)
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

func round3(participants map[uint32]*dkg.Participant, rnd2Bcast map[uint32]dkg.Round2Bcast) (*curves.EcPoint, map[uint32]*v1.ShamirShare) {
	signingShares := make(map[uint32]*v1.ShamirShare, len(participants))
	var verificationKey *curves.EcPoint
	for id := range rnd2Bcast {
		fmt.Printf("Computing DKG Round 3 for participant %d\n", id)
		pk, sk, err := participants[id].Round3(rnd2Bcast)
		verificationKey = pk
		if err != nil {
			panic(err)
		}
		fmt.Printf("DKG completed for participant %d\n", id)
		signingShares[id] = sk
	}
	return verificationKey, signingShares
}

func createDkgParticipants(thresh, limit int) map[uint32]*dkg.Participant {
	curve := v1.Ed25519()
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
		p, err := dkg.NewParticipant(uint32(i), uint32(thresh), generator, curves.NewEd25519Scalar(), otherIds...)
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
