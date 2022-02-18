//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package core

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// An entry into our test table
type entry struct {
	// Input
	msg []byte

	// Result (actual, not expected)
	commit   Commitment
	decommit *Witness
	err      error
}

// Test inputs and placeholders for results that will be filled in
// during init()
var testResults = []entry{
	{[]byte("This is a test message"), nil, nil, nil},
	{[]byte("short msg"), nil, nil, nil},
	{[]byte("This input field is intentionally longer than the SHA256 block size to ensure that the entire message is processed"),
		nil, nil, nil},
	{[]byte{0xFB, 0x1A, 0x18, 0x47, 0x39, 0x3C, 0x9F, 0x45, 0x5F, 0x29, 0x4C, 0x51, 0x42, 0x30, 0xA6, 0xB9},
		nil, nil, nil},
	// msg = \epsilon (empty string)
	{[]byte{}, nil, nil, nil},
	// msg == nil
	{nil, nil, nil, nil},
}

// Run our inputs through commit and record the outputs
func init() {
	for i := range testResults {
		entry := &testResults[i]
		entry.commit, entry.decommit, entry.err = Commit(entry.msg)
	}
}

// Computing commitments should never produce errors
func TestCommitWithoutErrors(t *testing.T) {
	for _, entry := range testResults {
		if entry.err != nil {
			t.Errorf("received Commit(%v): %v", entry.msg, entry.err)
		}
	}
}

// Commitments should be 256b == 64B in length
func TestCommitmentsAreExpectedLength(t *testing.T) {
	const expLen = 256 / 8
	for _, entry := range testResults {
		if len(entry.commit) != expLen {
			t.Errorf("commitment is not expected length: %v != %v", len(entry.commit), expLen)
		}
	}
}

// Decommit cannot be nil
func TestCommmitProducesDecommit(t *testing.T) {
	for _, entry := range testResults {
		if entry.decommit == nil {
			t.Errorf("decommit cannot be nil: Commit(%v)", entry.msg)
		}
	}
}

// Decommit value should contain the same message
func TestCommmitProducesDecommitWithSameMessage(t *testing.T) {
	for _, entry := range testResults {
		if !bytes.Equal(entry.msg, entry.decommit.Msg) {
			t.Errorf("decommit.msg != msg: %v != %v", entry.msg, entry.decommit.Msg)
		}
	}
}

// Commitments should be unique
func TestCommmitProducesDistinctCommitments(t *testing.T) {
	seen := make(map[[Size]byte]bool)

	// Check the pre-computed commitments for uniquness
	for _, entry := range testResults {

		// Slices cannot be used as hash keys, so we need to copy into
		// an array. Oh, go-lang.
		var cee [Size]byte
		copy(cee[:], entry.commit)

		// Ensure each commit is unique
		if seen[cee] {
			t.Errorf("duplicate commit found: %v", cee)
		}
		seen[cee] = true
	}
}

// Commitments should be unique even for the same message since the nonce is
// randomly selected
func TestCommmitDistinctCommitments(t *testing.T) {
	seen := make(map[[Size]byte]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		c, _, err := Commit(msg)
		if err != nil {
			t.Error(err)
		}

		// Slices cannot be used as hash keys, so copy into an array
		var cee [Size]byte
		copy(cee[:], []byte(c))

		// Ensure each commit is unique
		if seen[cee] {
			t.Errorf("duplicate commit found: %v", cee)
		}
		seen[cee] = true
	}
}

// Nonces must be 256b = 64B
func TestCommmitNonceIsExpectedLength(t *testing.T) {
	const expLen = 256 / 8

	// Check the pre-computed nonces
	for _, entry := range testResults {
		if len(entry.decommit.r) != expLen {
			t.Errorf("nonce is not expected length: %v != %v", len(entry.decommit.r), expLen)
		}
	}
}

// Randomly selected nonces will be unique with overwhelming probability
func TestCommmitProducesDistinctNonces(t *testing.T) {
	seen := make(map[[Size]byte]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		_, dee, err := Commit(msg)
		if err != nil {
			t.Error(err)
		}

		// Ensure each nonce is unique
		if seen[dee.r] {
			t.Errorf("duplicate nonce found: %v", dee.r)
		}
		seen[dee.r] = true
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	for _, entry := range testResults {

		// Open each commitment
		ok, err := Open(entry.commit, *entry.decommit)

		// There should be no error
		if err != nil {
			t.Error(err)
		}

		// The commitments should verify
		if !ok {
			t.Errorf("commitment failed to open: %v", entry.msg)
		}
	}
}

func TestOpenOnModifiedNonce(t *testing.T) {
	for _, entry := range testResults {
		dʹ := copyWitness(entry.decommit)

		// Modify the nonce
		dʹ.r[0] ^= 0x40

		// Open and check for failure
		ok, err := Open(entry.commit, *dʹ)
		assertFailedOpen(t, ok, err)
	}
}

func TestOpenOnZeroPrefixNonce(t *testing.T) {
	for _, entry := range testResults {
		dʹ := copyWitness(entry.decommit)

		// Modify the nonce
		dʹ.r[0] = 0x00
		dʹ.r[1] = 0x00
		dʹ.r[2] = 0x00
		dʹ.r[3] = 0x00
		dʹ.r[4] = 0x00
		dʹ.r[5] = 0x00
		dʹ.r[6] = 0x00
		dʹ.r[7] = 0x00
		dʹ.r[8] = 0x00
		dʹ.r[9] = 0x00
		dʹ.r[10] = 0x00

		// Open and check for failure
		ok, err := Open(entry.commit, *dʹ)
		assertFailedOpen(t, ok, err)
	}
}

// Makes a deep copy of a Witness
func copyWitness(d *Witness) *Witness {
	msg := make([]byte, len(d.Msg))
	var r [Size]byte

	copy(msg, d.Msg)
	copy(r[:], d.r[:])
	return &Witness{msg, r}
}

// Asserts that err != nil, and ok == false.
func assertFailedOpen(t *testing.T, ok bool, err error) {
	// There should be no error
	if err != nil {
		t.Error(err)
	}

	// But the commitments should fail
	if ok {
		t.Error("commitment was verified but was expected to fail")
	}
}

// An unrelated message should fail on open
func TestOpenOnNewMessage(t *testing.T) {
	for _, entry := range testResults {
		dʹ := copyWitness(entry.decommit)

		// Use a distinct message
		dʹ.Msg = []byte("no one expects the spanish inquisition")

		// Open and check for failure
		ok, err := Open(entry.commit, *dʹ)
		assertFailedOpen(t, ok, err)
	}
}

// An appended message should fail on open
func TestOpenOnAppendedMessage(t *testing.T) {
	for _, entry := range testResults {
		dʹ := copyWitness(entry.decommit)

		// Modify the message
		dʹ.Msg = []byte("no one expects the spanish inquisition")

		// Open and check for failure
		ok, err := Open(entry.commit, *dʹ)
		assertFailedOpen(t, ok, err)
	}
}

// A modified message should fail on open
func TestOpenOnModifiedMessage(t *testing.T) {
	for _, entry := range testResults {
		// Skip the empty string message for this test case
		if len(entry.msg) == 0 {
			continue
		}

		// Modify the message _in situ_
		dʹ := copyWitness(entry.decommit)
		dʹ.Msg[1] ^= 0x99

		// Open and check for failure
		ok, err := Open(entry.commit, *dʹ)
		assertFailedOpen(t, ok, err)
	}
}

// A modified commitment should fail on open
func TestOpenOnModifiedCommitment(t *testing.T) {
	for _, entry := range testResults {
		// Copy and then modify the commitment
		cʹ := make([]byte, Size)
		copy(cʹ[:], entry.commit)
		cʹ[6] ^= 0x33

		// Open and check for failure
		ok, err := Open(cʹ, *entry.decommit)
		assertFailedOpen(t, ok, err)
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	for _, entry := range testResults {
		// Open and check for failure
		ok, err := Open(entry.commit, Witness{})
		assertFailedOpen(t, ok, err)
	}
}

// A nil commit should return an error
func TestOpenOnNilCommitment(t *testing.T) {
	_, err := Open(nil, Witness{})
	assertError(t, err)
}

// Verifies that err != nil
func assertError(t *testing.T, err error) {
	if err == nil {
		t.Error("expected an error but received nil")
	}
}

// Ill-formed commitment should produce an error
func TestOpenOnLongCommitment(t *testing.T) {
	tooLong := make([]byte, Size+1)
	_, err := Open(tooLong, Witness{})
	assertError(t, err)
}

// Ill-formed commitment should produce an error
func TestOpenOnShortCommitment(t *testing.T) {
	tooShort := make([]byte, Size-1)
	_, err := Open(tooShort, Witness{})
	assertError(t, err)
}

// Tests that marshal-unmarshal is the identity function
func TestWitnessMarshalRoundTrip(t *testing.T) {
	expected := &Witness{
		[]byte("I'm the dude. So that's what you call me"),
		[Size]byte{0xAC},
	}

	// Marhal and test
	jsonBytes, err := json.Marshal(expected)
	require.NoError(t, err)
	require.NotNil(t, jsonBytes)

	// Unmarshal and test
	actual := &Witness{}
	require.NoError(t, json.Unmarshal(jsonBytes, actual))
	require.Equal(t, expected.Msg, actual.Msg)
	require.Equal(t, expected.r, actual.r)
}

// Tests that marshal-unmarshal is the identity function
func TestCommitmentMarshalRoundTrip(t *testing.T) {
	expected := Commitment([]byte("That or uh his-dudeness or duder or el duderino."))

	// Marhal and test
	jsonBytes, err := json.Marshal(expected)
	require.NoError(t, err)
	require.NotNil(t, jsonBytes)

	// Unmarshal and test
	actual := Commitment{}
	require.NoError(t, json.Unmarshal(jsonBytes, &actual))
	require.Equal(t, []byte(expected), []byte(actual))
}
