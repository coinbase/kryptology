//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/coinbase/kryptology/pkg/accumulator"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

func main() {
	curve := curves.BLS12381(&curves.PointBls12381G1{})
	sk, _ := new(accumulator.SecretKey).New(curve, []byte("1234567890"))
	pk, _ := sk.GetPublicKey(curve)
	skBytes, _ := sk.MarshalBinary()
	pkBytes, _ := pk.MarshalBinary()
	fmt.Println("Coinbase generates secret key and public key pair...")
	fmt.Printf("Coinbase publishes public key %v\n", hex.EncodeToString(pkBytes))
	fmt.Printf("Coinbase retains secret key %v\n", hex.EncodeToString(skBytes))

	// Enter initial elements
	fmt.Println("Coinbase starts initiating an accumulator")
	var userInput []string
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("Coinbase enters the elements accumulated in the initial accumulator, press enter to start")
	for scanner.Scan() {
		fmt.Println("Enter a string or stop")
		line := scanner.Text()
		if line == "stop" {
			break
		}
		userInput = append(userInput, line+"\n")
	}
	elements := make([]accumulator.Element, len(userInput))
	for i := 0; i < len(elements); i++ {
		elements[i] = curve.Scalar.Hash([]byte(userInput[i]))
	}

	// Coinbase initiates a new accumulator with elements
	acc, err := new(accumulator.Accumulator).WithElements(curve, sk, elements)
	if err != nil || acc == nil {
		panic(err)
	}
	accBytes, _ := acc.MarshalBinary()
	fmt.Printf("Accumulator Initiated! Value is %v\n", hex.EncodeToString(accBytes))

	// Initiate a new membership witness
	fmt.Println("Coinbase issues a membership witness to a user")
	fmt.Println("Coinbase enters the element that a membership witness is associated with")
	reader := bufio.NewReader(os.Stdin)
	witnessInput, _ := reader.ReadString('\n')
	witElement := curve.Scalar.Hash([]byte(witnessInput))
	wit, err := new(accumulator.MembershipWitness).New(witElement, acc, sk)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Coinbase issued membership witness associated to element %v\n", witnessInput)

	// User uses the witness to verify the membership
	fmt.Println("The user can use the witness to verify the associated element is accumulated")
	fmt.Println("verifying...")
	err = wit.Verify(pk, acc)
	if err != nil {
		panic(err)
	}
	fmt.Println("membership verification succeeds!")

	// Batch Update accumulator and membership witness
	fmt.Println("Coinbase could batch update the accumulator")
	fmt.Println("That is, Coinbase can add/delete multiple elements together")
	var addInput []string
	fmt.Println("Enter elements that you want to batch add, press enter the start")
	for scanner.Scan() {
		fmt.Println("Enter a string or stop")
		line := scanner.Text()
		if line == "stop" {
			break
		}
		addInput = append(addInput, line+"\n")
	}
	additions := make([]accumulator.Element, len(addInput))
	for i := 0; i < len(additions); i++ {
		additions[i] = curve.Scalar.Hash([]byte(addInput[i]))
	}

	var deleteInput []string
	fmt.Println("Enter elements that you want to batch delete, press enter to start")
	for scanner.Scan() {
		fmt.Println("Enter a string or stop")
		line := scanner.Text()
		if line == "stop" {
			break
		}
		deleteInput = append(deleteInput, line+"\n")
	}
	deletions := make([]accumulator.Element, len(deleteInput))
	for i := 0; i < len(deletions); i++ {
		deletions[i] = curve.Scalar.Hash([]byte(deleteInput[i]))
	}

	// Batch update accumulator
	_, coefficients, err := acc.Update(sk, additions, deletions)
	if err != nil {
		panic(err)
	}
	accBytes, _ = acc.MarshalBinary()
	fmt.Println("Accumulator batch-update succeeds!")
	fmt.Printf("The new accumulator value is %v\n", hex.EncodeToString(accBytes))

	// Batch update witness accordingly
	fmt.Println("User should batch-update his/her witness accordingly. This can be done by a trusted third party")
	fmt.Println("so that the witness is still usable to verify the associated element is accumulated")
	_, err = wit.BatchUpdate(additions, deletions, coefficients)
	if err != nil {
		panic(err)
	}
	err = wit.Verify(pk, acc)
	if err != nil {
		panic(err)
	}
	fmt.Println("Verification succeeds after batch-update")

	// Proof ownership of witness
	fmt.Println("The user can also generate a zero-knowledge proof proving the ownership of witness")
	params, err := new(accumulator.ProofParams).New(curve, pk, []byte("entropy"))
	if err != nil {
		panic(err)
	}
	mpc, err := new(accumulator.MembershipProofCommitting).New(wit, acc, params, pk)
	if err != nil {
		panic(err)
	}
	challenge := curve.Scalar.Hash(mpc.GetChallengeBytes())
	proof := mpc.GenProof(challenge)
	finalProof, err := proof.Finalize(acc, params, pk, challenge)
	if err != nil {
		panic(err)
	}
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		panic(err)
	}
	fmt.Println("ZK proof successfully generated!")
	fmt.Printf("ZK proof value is %v\n", hex.EncodeToString(proofBytes))
	fmt.Println("Verifying....")
	challenge2 := finalProof.GetChallenge(curve)
	if challenge.Cmp(challenge2) == 0 {
		fmt.Println("proof verification succeeds!")
	} else {
		fmt.Println("proof verification fails!")
	}
}
