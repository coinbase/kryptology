//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v0

import (
	"encoding/gob"
	"io"
)

func (alice *Alice) dkgCommit(w io.Writer) error {
	var err error
	enc := gob.NewEncoder(w)
	if alice.SkA, err = alice.params.Scalar.Random(); err != nil {
		return err
	}
	alice.PkA = &Schnorr{params: alice.params}      // kind of awkward where this should be defined.
	result, err := alice.PkA.ProveCommit(alice.SkA) // will mutate `pkA`
	if err != nil {
		return err
	}
	return enc.Encode(&result)
}

// dkgCommit receives Bob's commitment and returns schnorr statment + proof.
func (bob *Bob) dkgCommit(rw io.ReadWriter) error {
	enc := gob.NewEncoder(rw)
	dec := gob.NewDecoder(rw)
	var err error
	if err = dec.Decode(&bob.com); err != nil {
		return err
	}
	if bob.SkB, err = bob.params.Scalar.Random(); err != nil {
		return err
	}
	bob.PkB = &Schnorr{params: bob.params}
	if err = bob.PkB.Prove(bob.SkB); err != nil {
		return err
	}
	return enc.Encode(bob.PkB)
}

// dkgVerify input: Bob's statement + schnorr proof.
func (alice *Alice) dkgVerify(rw io.ReadWriter) error {
	dec := gob.NewDecoder(rw)
	enc := gob.NewEncoder(rw)
	var err error
	input := &Schnorr{params: alice.params}
	if err = dec.Decode(input); err != nil {
		return err
	}
	if err = input.Verify(); err != nil {
		return err
	}
	if alice.Pk, err = input.Pub.ScalarMult(alice.SkA); err != nil {
		return err
	}
	return enc.Encode(alice.PkA)
}

func (bob *Bob) dkgVerify(r io.Reader) error {
	dec := gob.NewDecoder(r)
	var err error
	input := &Schnorr{params: bob.params}
	if err = dec.Decode(input); err != nil {
		return err
	}
	if err = input.DecommitVerify(bob.com); err != nil {
		return err
	}
	if bob.Pk, err = input.Pub.ScalarMult(bob.SkB); err != nil {
		return err
	}
	return nil
}

func (alice *Alice) DKG(rw io.ReadWriter) error {
	if err := alice.dkgCommit(rw); err != nil {
		return err
	}
	if err := alice.dkgVerify(rw); err != nil {
		return err
	}
	return alice.Receiver.kosSetup(rw)
}

func (bob *Bob) DKG(rw io.ReadWriter) error {
	if err := bob.dkgCommit(rw); err != nil {
		return err
	}
	if err := bob.dkgVerify(rw); err != nil {
		return err
	}
	return bob.Sender.kosSetup(rw)
}
