// Package v1 provides a wrapper around the [DKLs18](https://eprint.iacr.org/2018/499.pdf) sign and dkg and provides
// serialization, serialization, and versioning for the serialized data.
package v1

import (
	"github.com/coinbase/kryptology/pkg/core/protocol"
)

// Basic protocol interface implementation that calls the next step func in a pre-defined list
type protoStepper struct {
	steps []func(input *protocol.Message) (*protocol.Message, error)
	step  int
}

// Next runs the next step in the protocol and reports errors or increments the step index
func (p *protoStepper) Next(input *protocol.Message) (*protocol.Message, error) {
	if p.complete() {
		return nil, protocol.ErrProtocolFinished
	}

	// Run the current protocol step and report any errors
	output, err := p.steps[p.step](input)
	if err != nil {
		return nil, err
	}

	// Increment the step index and report success
	p.step++
	return output, nil
}

// Reports true if the step index exceeds the number of steps
func (p *protoStepper) complete() bool { return p.step >= len(p.steps) /**/ }
