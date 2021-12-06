//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

//
// Demonstrates 2-party (client-server) DKG and message serialization
//

package main

import (
	"encoding/json"
	"fmt"
	crypto "github.com/coinbase/kryptology/pkg/core/curves"
	"log"
	"os"

	"github.com/btcsuite/btcd/btcec"
	"github.com/coinbase/kryptology/pkg/dkg/gennaro2p"
	"github.com/pkg/errors"
)

const (
	clientSsid     = 1
	serverSageSsid = 2
	useJson        = true
)

// Scalar for the curve we're using
var (
	curveScalar = crypto.NewK256Scalar()
	curve       = btcec.S256()
)

// Initiate and run a DKG with JSON-serialized messages
func runClientJson(s *server) {
	// Setup
	lg := log.New(os.Stdout, "[client] ", log.Lshortfile|log.Lmsgprefix)

	lg.Println("Creating client")
	client, err := gennaro2p.NewParticipant(clientSsid, serverSageSsid, nil, curveScalar, curve)
	dieOnError(err)

	// DKG Round 1
	lg.Println("Running DKG round 1")
	clientR1, err := client.Round1(nil)
	dieOnError(err)
	lg.Printf("clientR1=%#v", clientR1)

	// Marshal
	clientR1Json, err := json.Marshal(clientR1)
	dieOnError(errors.Wrap(err, "marhsaling clientR1Json"))

	// Contact server
	lg.Println("Calling server.Phase1")
	phase1Json := s.phase1Json(clientR1Json)

	// unmarshal
	var p1 phase1Response
	err = json.Unmarshal(phase1Json, &p1)
	dieOnError(errors.Wrap(err, "unmarshaling phase 1 response"))

	lg.Printf("phase 1 response=%v", p1)

	// DKG Round 2
	lg.Println("Running DKG round 2")
	clientR2, err := client.Round2(&p1.R1)
	dieOnError(err)
	lg.Printf("clientR2=%#v", clientR2)

	// DKG finalize
	lg.Println("Finalize DKG")
	result, err := client.Finalize(&p1.R2)
	dieOnError(err)
	lg.Printf("result=%#v", result)

	// Marshal R2 output
	clientR2Json, err := json.Marshal(clientR2)
	dieOnError(err)

	// Contact server
	lg.Println("Calling server.Phase2")
	s.phase2Json(clientR2Json)
}

// Initiate and run a DKG
func runClient(s *server) {
	// Setup
	lg := log.New(os.Stdout, "[client] ", log.Lshortfile|log.Lmsgprefix)

	lg.Println("Creating client")
	client, err := gennaro2p.NewParticipant(clientSsid, serverSageSsid, nil, curveScalar, curve)
	dieOnError(err)

	// DKG Round 1
	lg.Println("Running DKG round 1")
	clientR1, err := client.Round1(nil)
	dieOnError(err)
	lg.Printf("clientR1=%#v", clientR1)

	// Contact server
	lg.Println("Calling server.Phase1")
	serverR1, serverR2 := s.phase1(clientR1)

	// DKG Round 2
	lg.Println("Running DKG round 2")
	clientR2, err := client.Round2(serverR1)
	dieOnError(err)
	lg.Printf("clientR2=%#v", clientR2)

	// DKG finalize
	lg.Println("Finalize DKG")
	result, err := client.Finalize(serverR2)
	dieOnError(err)
	lg.Printf("result=%#v", result)

	// Contact server
	lg.Println("Calling server.Finalize")
	s.phase2(clientR2)
}

// Run!
func main() {
	if useJson {
		runClientJson(&server{})
	} else {
		runClient(&server{})
	}
}

// If there's an error, print and exit(1)
func dieOnError(err error) {
	if err != nil {
		fmt.Printf("Fatal: %v\n", err)
		os.Exit(1)
	}
}
