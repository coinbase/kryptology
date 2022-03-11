package bls12381

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/coinbase/kryptology/pkg/core/curves/native"
)

func TestSinglePairing(t *testing.T) {
	g := new(G1).Generator()
	h := new(G2).Generator()

	e := new(Engine)
	e.AddPair(g, h)
	p := e.Result()
	p.Neg(p)

	e.Reset()
	e.AddPairInvG2(g, h)
	q := e.Result()
	e.Reset()
	e.AddPairInvG1(g, h)
	r := e.Result()

	require.Equal(t, 1, p.Equal(q))
	require.Equal(t, 1, q.Equal(r))
}

func TestMultiPairing(t *testing.T) {
	const Tests = 10
	e1 := new(Engine)
	e2 := new(Engine)

	g1s := make([]*G1, Tests)
	g2s := make([]*G2, Tests)
	sc := make([]*native.Field, Tests)
	res := make([]*Gt, Tests)
	expected := new(Gt).SetOne()

	for i := 0; i < Tests; i++ {
		var bytes [64]byte
		g1s[i] = new(G1).Generator()
		g2s[i] = new(G2).Generator()
		sc[i] = Bls12381FqNew()
		_, _ = crand.Read(bytes[:])
		sc[i].SetBytesWide(&bytes)
		if i&1 == 0 {
			g1s[i].Mul(g1s[i], sc[i])
		} else {
			g2s[i].Mul(g2s[i], sc[i])
		}
		e1.AddPair(g1s[i], g2s[i])
		e2.AddPair(g1s[i], g2s[i])
		res[i] = e1.Result()
		e1.Reset()
		expected.Add(expected, res[i])
	}

	actual := e2.Result()
	require.Equal(t, 1, expected.Equal(actual))
}
