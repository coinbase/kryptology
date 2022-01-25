//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"fmt"
	"github.com/coinbase/kryptology/pkg/core/curves"
)

type MinaTSchnorrHandler struct{}

func (m MinaTSchnorrHandler) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	txn := new(Transaction)
	err := txn.UnmarshalBinary(msg)
	if err != nil {
		return nil, err
	}
	input := new(roinput).Init(3, 75)
	txn.addRoInput(input)

	pt, ok := pubKey.(*curves.PointPallas)
	if !ok {
		return nil, fmt.Errorf("invalid point")
	}
	R, ok := r.(*curves.PointPallas)
	if !ok {
		return nil, fmt.Errorf("invalid point")
	}

	pk := new(PublicKey)
	pk.value = pt.GetEp()

	sc := msgHash(pk, R.X(), input, ThreeW, MainNet)
	s := new(curves.ScalarPallas)
	s.SetFq(sc)
	return s, nil
}
