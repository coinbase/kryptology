//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// benchcomp implements a command that receives two benchmarks files as input and flags the benchmarks that have
// degraded by more than a threshold amount. The main goal of this tool is to be used in CI
// to check each PR.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
	"golang.org/x/tools/benchmark/parse"
)

const THRESHOLD = 1.1

func main() {
	cReader, nReader, err := parseCmdArgs()
	if err != nil {
		panic(err)
	}

	if err := Compare(cReader, nReader); err != nil {
		panic(err)
	}
}

func parseCmdArgs() (io.Reader, io.Reader, error) {
	cFlag := flag.String("current", "current-bench.log", "The patch to the log file containing the output of the current benchmark result.")
	nFlag := flag.String("new", "new-bench.log", "The patch to the log file containing the output of the new benchmark result.")
	flag.Parse()
	cBytes, err := ioutil.ReadFile(*cFlag)
	if err != nil {
		return nil, nil, fmt.Errorf("reading current log file %v", err)
	}
	nBytes, err := ioutil.ReadFile(*nFlag)
	if err != nil {
		return nil, nil, fmt.Errorf("reading new log file %v", err)
	}

	return bytes.NewBuffer(cBytes), bytes.NewBuffer(nBytes), nil
}

// Compare expects two readers which contain the output of two runs of `go test -bench` command and throws an error if
// the performance has degraded by more than `THRESHOLD` amount.
func Compare(currBench, newBench io.Reader) error {
	c, n, err := parseBenchmarks(currBench, newBench)
	if err != nil {
		return errors.Wrap(err, "parsing benchmark outputs")
	}

	perfDeviations := make([]string, 0)
	for bench := range c {
		if _, ok := n[bench]; !ok {
			// New benchmark, skipping
			continue
		} else {
			currB := c[bench]
			newB := n[bench]
			err = compareBenches(currB, newB)
			if err != nil {
				perfDeviations = append(perfDeviations, fmt.Sprintf("%v", err))
			}
		}
	}

	if len(perfDeviations) != 0 {
		return fmt.Errorf("%#v", perfDeviations)
	}
	return nil
}

func parseBenchmarks(currBench, newBench io.Reader) (parse.Set, parse.Set, error) {
	c, err := parse.ParseSet(currBench)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing current benchmark output")
	}
	n, err := parse.ParseSet(newBench)
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing new benchmark output")
	}

	return c, n, nil
}

func compareBenches(currB, newB []*parse.Benchmark) error {
	currMap := make(map[string]*parse.Benchmark)
	newMap := make(map[string]*parse.Benchmark)
	for _, b := range currB {
		// TODO: double check what is in Name
		currMap[b.Name] = b
	}
	for _, b := range newB {
		// TODO: double check what is in Name
		newMap[b.Name] = b
	}
	for name := range currMap {
		if _, ok := newMap[name]; ok {
			compare := []struct {
				current float64
				new     float64
			}{
				{
					current: float64(currMap[name].AllocedBytesPerOp),
					new:     float64(newMap[name].AllocedBytesPerOp),
				},
				{
					current: float64(currMap[name].AllocsPerOp),
					new:     float64(newMap[name].AllocsPerOp),
				},
				{
					current: currMap[name].NsPerOp,
					new:     newMap[name].NsPerOp,
				},
				{
					current: currMap[name].MBPerS,
					new:     newMap[name].MBPerS,
				},
			}
			for _, t := range compare {
				if t.new > t.current*THRESHOLD {
					percent := (t.new - t.current) * 100 / t.current
					return fmt.Errorf("benchmark %s exceeded previous benchmark by %0.2f percent. Current: %0.2f, New: %0.2f", name, percent, t.current, t.new)
				}
			}
		}
	}
	return nil
}
