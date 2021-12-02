//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"encoding/json"
	"log"
	"os"

	dkg "github.com/coinbase/kryptology/pkg/dkg/gennaro2p"
	"github.com/pkg/errors"
)

type server struct {
	p *dkg.Participant
	l *log.Logger
}

type phase1Response struct {
	R1 dkg.Round1Message `json:"r1"`
	R2 dkg.Round2Message `json:"r2"`
}

// Runs server's R1 and R2
func (s *server) phase1(in *dkg.Round1Message) (*dkg.Round1Message, *dkg.Round2Message) {
	// Setup logger
	s.l = log.New(os.Stdout, "[server] ", log.Lshortfile|log.Lmsgprefix)

	s.l.Println("Initializing server")
	var err error
	s.p, err = dkg.NewParticipant(serverSageSsid, clientSsid, in.Blind, curveScalar, curve)
	dieOnError(err)

	// DKG Round 1
	s.l.Println("Running DKG round 1")
	r1Out, err := s.p.Round1(nil)
	dieOnError(err)

	s.l.Printf("r1Out=%#v", r1Out)

	// DKG Round 2
	s.l.Println("Running DKG round 2")
	r2out, err := s.p.Round2(in)
	dieOnError(err)
	s.l.Printf("r2out=%#v", r2out)
	return r1Out, r2out
}

// Runs server's finalize
func (s *server) phase2(in *dkg.Round2Message) {
	// DKG finalize
	s.l.Println("Finalize DKG")
	result, err := s.p.Finalize(in)
	dieOnError(err)
	s.l.Printf("result=%#v", result)
}

// Runs server's R1 and R2 with in/out in JSON
func (s *server) phase1Json(req []byte) []byte {
	// Deserialize the Round1 input
	in := &dkg.Round1Message{}
	err := json.Unmarshal(req, &in)
	dieOnError(errors.Wrapf(err, "unmarshaling Round1Message from req=%v", string(req)))

	// Run phase 1 and marshal
	r1, r2 := s.phase1(in)
	out, err := json.Marshal(&phase1Response{*r1, *r2})
	dieOnError(errors.Wrap(err, "marshaling phase1 response"))
	return out
}

// Runs server's Finalize with in/out in JSON
func (s *server) phase2Json(req []byte) {
	// Deserialize the Round2 input
	in := &dkg.Round2Message{}
	err := json.Unmarshal(req, &in)
	dieOnError(errors.Wrapf(err, "unmarshaling Round2Message from req=%v", string(req)))

	// Run finalize
	s.phase2(in)
}
