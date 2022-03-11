# BLS Signatures

An implementation of the Boneh-Lynn-Shacham (BLS) signatures according to the [standard](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1)
on top of the Barreto-Lynn-Scott (BLS) 12-381 curve. The [BLS12-381 curve](https://github.com/zkcrypto/pairing/tree/master/src/bls12_381#serialization) provides roughly
128-bits of security and BLS is a digital signature with aggregation properties.

We have implemented all three signature schemes described in the [standard](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1)
which are designed to handle rogue-key attacks differently. These three are:

- **Basic** handles rogue key attacks by requiring all signed messages in an aggregate signature be distinct
- **Message Augmentation** handles rogue key attacks by prepending the public key to the message during signing which ensures that all messages are distinct for different public keys.
- **Proof of Possession** handles rogue key attacks by validating public keys in a separate step called a proof of possession. This allows for faster aggregate verification.

Pairing-friendly curves have two generator-groups &#x1D53E;<sub>1</sub>, &#x1D53E;<sub>2</sub>. 
Data in &#x1D53E;<sub>2</sub> is twice the size of &#x1D53E;<sub>1</sub> and operations are slower. 
BLS signatures require signatures and public keys to be in opposite groups i.e. signatures in &#x1D53E;<sub>1</sub> and public keys in &#x1D53E;<sub>2</sub> or
signatures in &#x1D53E;<sub>2</sub> and public keys in &#x1D53E;<sub>1</sub>. This means one of two things:

- **Short public keys, long signatures**: Signatures are longer and slower to create, verify, and aggregate but public keys are small and fast to aggregate. Used when signing and verification operations not computed as often or for minimizing storage or bandwidth for public keys.
- **Short signatures, long public keys**: Signatures are short and fast to create, verify, and aggregate but public keys are bigger and slower to aggregate. Used when signing and verification operations are computed often or for minimizing storage or bandwidth for signatures.

This library supports both of these variants for all three signature schemes. The more widely deployed
variant is short public keys, long signatures. We refer to this variant as `UsualBls`. The other variant,
short signatures, long public keys, is named `TinyBls`.
The naming convention follows Sig`SchemeType`[Vt] where **Vt** is short for variant. For example,

- **Usual Bls Basic -> SigBasic**: Provides all the functions for the Basic signature scheme with signatures in &#x1D53E;<sub>2</sub> and public keys in &#x1D53E;<sub>1</sub>
- **Tiny Bls Basic -> SigBasicVt**: Provides all the functions for the Basic signature scheme with signatures in &#x1D53E;<sub>1</sub> and public keys in &#x1D53E;<sub>2</sub>

One final note, in cryptography, it is considered good practice to use domain separation values to limit attacks to specific contexts. The [standard](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/?include_text=1)
recommends specific values for each scheme but this library also supports supplying custom domain separation values. For example, there are two functions for creating
a BLS signing instance:

- **NewSigBasic()** creates a Basic BLS signature using the recommended domain separation value.
- **NewSigBasicWithDst(dst)** creates a Basic BLS signature using the parameter `dst` as the domain separation value such as in the [Eth2.0 Spec](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/phase0/validator.md#attestation-aggregation)

Also implemented is Threshold BLS as described in section 3.2 of [B03](https://www.cc.gatech.edu/~aboldyre/papers/bold.pdf).

- ThresholdKeygen(parts, threshold int) -> ([]*SecretKeyShare, error)
- PartialSign(share *SecretKeyShare, msg []byte) -> *PartialSignature
- CombineSigs(*PartialSignature...) -> *Signature

## Security Considerations

### Validating secret keys

Low entropy secret keys are a problem since this means an attacker can more easily guess the value and now can impersonate the key holder.
Secret keys are derived using trusted random number generators (TRNG). If the TRNG produces bad entropy
the secret key will be weak. Secret keys are checked to be non-zero values. A zero value secret key
not only fails the entropy test but also yields a public key that will validate any signature.

### Validating public keys

Public keys are ensured to be valid. A valid public key means
it represents a valid, non-identity elliptic curve point in the correct subgroup.
Public keys that are the identity element mean any signature would pass a call to verify.

### Validating signatures

Generated signatures are ensured to be valid. A valid signature means
it represents a valid, non-identity elliptic curve point in the correct subgroup.
Signatures that are the identity element mean any signature would pass a call to verify.
Verify checks signatures for non-identity elements in the correct subgroup before checking
for a valid signature.

### Mitigating Rogue Key Attacks

A rogue key attacks can only happen to multisignature or aggregated signature.
A rogue key attack is where at least one party produces a valid but malicious public key such that the multisignature requires less than the threshold to verify a signature.
There are two ways to mitigate rogue key attacks: Guarantee all signed messages are unique or validate each public key before use. This library offers both solutions.

## Comparison to other BLS implementations and integrations

This library has been tested to be compatible with the following implementations
by randomly generating millions of keys and signatures and importing and verifying
between the two libraries.

1. Ethereum's [py_ecc](https://github.com/ethereum/py_ecc)
1. PhoreProject [Go BLS](https://github.com/phoreproject/bls)
1. Herumi's [BLS](https://github.com/herumi/bls-eth-go-binary)
1. Algorand's [Rust BLS Sig](https://crates.io/crates/bls_sigs_ref)
1. Miracl's [Rust and Go BLS sig](https://github.com/miracl/core)

The most common and high risk failures that can occur with library implementations
are low entropy secret keys, malformed public keys, and invalid signature generation.

Low entropy secret keys are a problem since this means an attacker can more easily guess
the value and now can impersonate the key holder.

Malformed public keys and signatures result in invalid addresses and no ability to withdraw funds.

To check for these problems, We tested millions of keys/signatures (vs say thousands or hundreds) to prove that 

1. The odds of producing an invalid key/signature is already theoretically low 2<sup>-255</sup>
1. The results of running millions of checks shows that nothing bad happened in 10M attempts

In other words, keys and signatures generated from these libraries can be consumed by this library
and visa-versa.

Some of the libraries implementations for hash to curve were either out of date
or not compliant with the [IETF Spec](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/).
This meant that signatures generated by this library would not validate with others and visa-versa.
However, public keys were found to be compatible in all libraries.

This library is compliant with the latest version (10 as of this writing).