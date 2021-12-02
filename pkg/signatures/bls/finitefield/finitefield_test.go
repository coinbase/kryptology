package finitefield

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	one                = big.NewInt(1)
	modulus, modulusOk = new(big.Int).SetString(
		"1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
		16,
	)
	oneBelowModulus = zero().Sub(modulus, one)
	oneAboveModulus = zero().Add(modulus, one)
	field           = New(modulus)
)

type buggedReader struct{}

func (r buggedReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("EOF")
}

func zero() *big.Int {
	return new(big.Int)
}

func assertElementZero(t *testing.T, e *Element) {
	assert.Equal(t, zero().Bytes(), e.Bytes())
}

type binaryOperation func(*Element) *Element

func assertUnequalFieldsPanic(t *testing.T, b binaryOperation) {
	altField := New(big.NewInt(23))
	altElement := altField.NewElement(one)

	assert.PanicsWithValue(
		t,
		"fields must match for valid binary operation",
		func() { b(altElement) },
	)
}

func TestModulus(t *testing.T) {
	assert.True(t, modulusOk)
}

func TestNew(t *testing.T) {
	assert.PanicsWithValue(
		t,
		fmt.Sprintf("modulus: %x is not a prime", oneBelowModulus),
		func() { New(oneBelowModulus) },
	)
	assert.NotPanics(
		t,
		func() { New(modulus) },
	)
}

func TestNewElement(t *testing.T) {
	assert.PanicsWithValue(
		t,
		fmt.Sprintf("value: %x is not within field: %x", modulus, field.Modulus),
		func() { newElement(field, modulus) },
	)
	assert.NotPanics(
		t,
		func() { newElement(field, oneBelowModulus) },
	)
}

func TestIsValid(t *testing.T) {
	assert.False(t, field.IsValid(zero().Neg(one)))
	assert.False(t, field.IsValid(modulus))
	assert.False(t, field.IsValid(oneAboveModulus))
	assert.True(t, field.IsValid(oneBelowModulus))
}

func TestFieldNewElement(t *testing.T) {
	element := field.NewElement(oneBelowModulus)

	assert.Equal(t, oneBelowModulus, element.value)
	assert.Equal(t, field, element.Field)
}

func TestZero(t *testing.T) {
	assert.Equal(t, zero(), field.Zero().value)
	assert.Equal(t, field, field.Zero().Field)
}

func TestOne(t *testing.T) {
	assert.Equal(t, field.One().value, one)
	assert.Equal(t, field.One().Field, field)
}

func TestRandomElement(t *testing.T) {
	randomElement1, err := field.RandomElement(nil)
	require.NoError(t, err)
	randomElement2, err := field.RandomElement(nil)
	require.NoError(t, err)
	randomElement3, err := field.RandomElement(new(buggedReader))
	require.Error(t, err)

	assert.Equal(t, field, randomElement1.Field)
	assert.Equal(t, field, randomElement2.Field)
	assert.NotEqual(t, randomElement1.value, randomElement2.value)
	assert.Nil(t, randomElement3)
}

func TestElementFromBytes(t *testing.T) {
	element := field.ElementFromBytes(oneBelowModulus.Bytes())

	assert.Equal(t, field, element.Field)
	assert.Equal(t, oneBelowModulus, element.value)
}

func TestReducedElementFromBytes(t *testing.T) {
	element := field.ReducedElementFromBytes(oneBelowModulus.Bytes())

	assert.Equal(t, field, element.Field)
	assert.Equal(t, oneBelowModulus, element.value)

	element = field.ReducedElementFromBytes(oneAboveModulus.Bytes())

	assert.Equal(t, field, element.Field)
	assert.Equal(t, one, element.value)
}

func TestAdd(t *testing.T) {
	element1 := field.NewElement(one)
	element2 := field.NewElement(big.NewInt(2))
	element3 := field.NewElement(oneBelowModulus)
	element4 := &Element{field, modulus}

	assert.Equal(t, element2, element1.Add(element1))
	assert.Equal(t, big.NewInt(3), element1.Add(element2).value)
	assert.Equal(t, big.NewInt(3), element2.Add(element1).value)
	assert.Equal(t, one, element1.Add(element4).value)
	assert.Equal(t, one, element3.Add(element2).value)
	assertElementZero(t, element1.Add(element3))
	assertUnequalFieldsPanic(t, element1.Add)
}

func TestSub(t *testing.T) {
	element1 := field.NewElement(one)
	element2 := field.NewElement(big.NewInt(2))
	element3 := field.NewElement(oneBelowModulus)
	element4 := &Element{field, modulus}

	assertElementZero(t, element1.Sub(element1))
	assert.Equal(t, element3, element1.Sub(element2))
	assert.Equal(t, element1, element2.Sub(element1))
	assert.Equal(t, element1, element1.Sub(element4))
	assert.Equal(t, element3, element4.Sub(element1))
	assert.Equal(t, element1, element4.Sub(element3))
	assert.Equal(t, element3, element3.Sub(element4))
	assertUnequalFieldsPanic(t, element1.Sub)
}

func TestMul(t *testing.T) {
	element1 := field.NewElement(one)
	element2 := field.NewElement(big.NewInt(2))
	element3 := field.NewElement(oneBelowModulus)
	element4 := field.NewElement(zero())
	expectedProduct, ok := new(big.Int).SetString(
		"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3eb",
		16,
	)
	require.True(t, ok)

	assertElementZero(t, element1.Mul(element4))
	assertElementZero(t, element4.Mul(element1))
	assert.Equal(t, element3, element1.Mul(element3))
	assert.Equal(t, element3, element3.Mul(element1))
	assert.Equal(t, expectedProduct, element3.Mul(element2).value)
	assert.Equal(t, expectedProduct, element2.Mul(element3).value)
	assertUnequalFieldsPanic(t, element1.Mul)
}

func TestDiv(t *testing.T) {
	element1 := field.NewElement(one)
	element2 := field.NewElement(big.NewInt(2))
	element3 := field.NewElement(oneBelowModulus)
	element4 := field.NewElement(zero())
	expectedQuotient1, ok := new(big.Int).SetString(
		"80000000000000000000000000000000a6f7cef517bce6b2c09318d2e7ae9f6",
		16,
	)
	require.True(t, ok)
	expectedQuotient2, ok := new(big.Int).SetString(
		"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3eb",
		16,
	)
	require.True(t, ok)

	assertElementZero(t, element4.Div(element3))
	assert.Equal(t, element3, element3.Div(element1))
	assert.Equal(t, expectedQuotient1, element3.Div(element2).value)
	assert.Equal(t, expectedQuotient2, element2.Div(element3).value)
	assert.Panics(t, func() { element3.Div(element4) })
	assertUnequalFieldsPanic(t, element1.Div)
}

func TestIsEqual(t *testing.T) {
	element1 := field.NewElement(oneBelowModulus)
	element2 := field.NewElement(big.NewInt(23))
	element3 := field.NewElement(oneBelowModulus)
	altField := New(big.NewInt(23))
	altElement1 := altField.NewElement(one)

	assert.False(t, element1.IsEqual(element2))
	assert.True(t, element1.IsEqual(element3))
	assert.True(t, element1.IsEqual(element1))
	assert.False(t, element1.IsEqual(altElement1))
}

func TestBigInt(t *testing.T) {
	element := field.NewElement(oneBelowModulus)

	assert.Equal(t, oneBelowModulus, element.BigInt())
}

func TestBytes(t *testing.T) {
	element := field.NewElement(oneBelowModulus)

	assert.Equal(
		t,
		[]byte{
			0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
			0x0, 0x0, 0x0, 0x0, 0x0, 0x14, 0xde, 0xf9, 0xde, 0xa2,
			0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5,
			0xd3, 0xec,
		},
		element.Bytes(),
	)
}

func TestClone(t *testing.T) {
	element := field.NewElement(oneBelowModulus)
	clone := element.Clone()

	assert.Equal(t, clone, element)

	clone.value.Add(one, one)

	assert.NotEqual(t, clone, element)
}
