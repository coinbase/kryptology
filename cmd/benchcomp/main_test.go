//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"strings"
	"testing"
)

func TestPerformanceDeviation(t *testing.T) {
	goodComputationBench := "Benchmark_ABC             842688              1396 ns/op"
	badComputationBench := "Benchmark_ABC             842688              13960 ns/op"
	if err := Compare(strings.NewReader(goodComputationBench), strings.NewReader(badComputationBench)); err == nil {
		t.Errorf("Expected performance deviation: [%v], but did not detect any!", err)
	}
}

func TestParsing(t *testing.T) {
	// TODO: the current parser ignores the 3rd and 4th column of data (e.g., the custom benchmarks)
	output := `
garbage data
BenchmarkSigning/Secp256k1_-_5_of_9-16                         1        5794642205 ns/op
BenchmarkSign2p-16                                             2         685590314 ns/op             29319 bytes/sign           16.00 msgs/sign
garbage data
`
	o, _, err := parseBenchmarks(strings.NewReader(output), strings.NewReader(output))
	if err != nil {
		t.Errorf("Failed to parse test input %v", err)
	}

	if len(o) != 2 {
		t.Errorf("Incorrect output length. Expected 2, got %#v", o)
	}
	if _, ok := o["BenchmarkSigning/Secp256k1_-_5_of_9-16"]; !ok {
		t.Errorf("Did not find BenchmarkSigning/Secp256k1_-_5_of_9-16 in the parsed output")
	}
	if _, ok := o["BenchmarkSign2p-16"]; !ok {
		t.Errorf("Did not find BenchmarkSign2p-16 in the parsed output")
	}
}
