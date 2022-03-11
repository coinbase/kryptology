//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	bls "github.com/coinbase/kryptology/pkg/signatures/bls/bls_sig"
)

type signOp struct {
	Data      string `json:"data"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type cmdFlags struct {
	Generate   bool
	PublicKeys bool
	Sign       bool
	Verify     bool
	Number     int
}

func parseCliArgs() cmdFlags {
	var generate, publickeys, sign, verify bool
	var number int
	flag.BoolVar(&generate, "g", false, "Generate public keys")
	flag.BoolVar(&publickeys, "p", false, "Verify public keys")
	flag.BoolVar(&sign, "s", false, "Generate signatures")
	flag.BoolVar(&verify, "v", false, "Verify signatures")
	flag.IntVar(&number, "n", 25, "The number of items to generate")
	flag.Parse()
	return cmdFlags{
		generate, publickeys, sign, verify, number,
	}
}

func main() {
	flags := parseCliArgs()

	if flags.Generate {
		generate(flags.Number)
	} else if flags.PublicKeys {
		publicKeys()
	} else if flags.Sign {
		sign(flags.Number)
	} else if flags.Verify {
		verify()
	}
}

func generate(number int) {
	scheme := bls.NewSigPop()
	publicKeys := make([]string, number)
	for i := 0; i < number; i++ {
		publicKey, _, err := scheme.Keygen()
		if err != nil {
			fmt.Printf("Keygen error occurred: %v\n", err)
			os.Exit(1)
		}
		b, _ := publicKey.MarshalBinary()
		publicKeys[i] = hex.EncodeToString(b)
	}
	out, _ := json.Marshal(publicKeys)
	fmt.Println(string(out))
}

func publicKeys() {
	input, err := getInput()
	if err != nil {
		fmt.Printf("Unable to read input: %v", err)
		os.Exit(1)
	}
	var pubkeys []string
	err = json.Unmarshal(input, &pubkeys)
	if err != nil {
		fmt.Printf("Unable to parse json input: %v", err)
		os.Exit(1)
	}
	fmt.Printf("Checking public keys")
	for _, pk := range pubkeys {
		data, err := hex.DecodeString(pk)
		if err != nil {
			fmt.Printf("Unable to parse hex input: %v", err)
			os.Exit(1)
		}
		pubkey := new(bls.PublicKey)
		fmt.Printf("Checking %s - ", pk)
		err = pubkey.UnmarshalBinary(data)
		if err != nil {
			fmt.Printf("fail\n")
			os.Exit(1)
		}
		fmt.Printf("pass\n")
	}
}

func sign(number int) {
	tests := []string{
		"", "aaa", "aaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	var err error
	scheme := bls.NewSigPop()
	secretKeys := make([]*bls.SecretKey, number)
	publicKeys := make([]*bls.PublicKey, number)
	for i := 0; i < number; i++ {
		publicKeys[i], secretKeys[i], err = scheme.Keygen()
		if err != nil {
			fmt.Printf("Keygen error occurred: %v\n", err)
			os.Exit(1)
		}
	}

	sigs := make([]*signOp, number*len(tests))

	k := 0
	for _, t := range tests {
		for j := 0; j < len(secretKeys); j++ {
			signature, err := scheme.Sign(secretKeys[j], []byte(t))
			if err != nil {
				fmt.Printf("Signing failed: %v\n", err)
				os.Exit(1)
			}
			pk, _ := publicKeys[j].MarshalBinary()
			sig, _ := signature.MarshalBinary()
			sigs[k] = &signOp{
				Data:      t,
				PublicKey: hex.EncodeToString(pk),
				Signature: hex.EncodeToString(sig),
			}
			k++
		}
	}

	data, err := json.Marshal(sigs)
	if err != nil {
		fmt.Printf("Unable to convert signatures to json")
		os.Exit(1)
	}
	fmt.Print(string(data))
}

func verify() {
	input, err := getInput()
	if err != nil {
		fmt.Printf("Unable to read input: %v", err)
		os.Exit(1)
	}
	var operations []signOp
	err = json.Unmarshal(input, &operations)
	if err != nil {
		fmt.Printf("Unable to parse json input: %v", err)
		os.Exit(1)
	}
	scheme := bls.NewSigPop()
	for _, op := range operations {
		fmt.Printf("Checking %s - ", op.PublicKey)
		data, err := hex.DecodeString(op.PublicKey)
		if err != nil {
			fmt.Printf("fail. Unable to parse hex input: %v", err)
			os.Exit(1)
		}
		pubkey := new(bls.PublicKey)
		err = pubkey.UnmarshalBinary(data)
		if err != nil {
			fmt.Printf("fail. Invalid public key: %v", err)
			os.Exit(1)
		}
		data, err = hex.DecodeString(op.Signature)
		if err != nil {
			fmt.Printf("fail. Unable to parse hex input: %v", err)
			os.Exit(1)
		}
		sig := new(bls.Signature)
		err = sig.UnmarshalBinary(data)
		if err != nil {
			fmt.Printf("fail. Invalid signature format: %v", err)
			os.Exit(1)
		}
		ok, err := scheme.Verify(pubkey, []byte(op.Data), sig)
		if !ok || err != nil {
			fmt.Printf("fail. Invalid signature")
			os.Exit(1)
		}
		fmt.Printf("pass.")
	}
}

func getInput() ([]byte, error) {
	fi, _ := os.Stdin.Stat()

	var data []byte

	if (fi.Mode() & os.ModeCharDevice) == 0 {
		// Read from pipe
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			data = append(data, scanner.Bytes()...)
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}
	} else {
		// Read from file
		arguments := flag.Args()
		if len(arguments) < 1 {
			return nil, fmt.Errorf("expected data argument")
		}

		_, err := os.Stat(arguments[0])

		if os.IsNotExist(err) {
			data = []byte(arguments[0])
		} else {
			contents, err := ioutil.ReadFile(arguments[0])
			if err != nil {
				return nil, err
			}
			data = contents
		}
	}

	return data, nil
}
