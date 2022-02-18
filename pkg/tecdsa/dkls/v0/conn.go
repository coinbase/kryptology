//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v0

import "io"

type pipeWrapper struct {
	r         *io.PipeReader
	w         *io.PipeWriter
	exchanged int // basically we only use this during testing, to track bytes exchanged
}

func (wrapper *pipeWrapper) Write(p []byte) (n int, err error) {
	n, err = wrapper.w.Write(p)
	wrapper.exchanged += n
	return
}

func (wrapper *pipeWrapper) Read(p []byte) (n int, err error) {
	n, err = wrapper.r.Read(p)
	wrapper.exchanged += n
	return
}

func NewPipeWrappers() (*pipeWrapper, *pipeWrapper) {
	leftOut, leftIn := io.Pipe()
	rightOut, rightIn := io.Pipe()
	return &pipeWrapper{r: leftOut, w: rightIn}, &pipeWrapper{r: rightOut, w: leftIn}
}
