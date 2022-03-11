# Kryptology
Coinbase's advanced cryptography library

## Quickstart
Use the latest version of this library:
```$xslt
go get github.com/coinbase/kryptology
```

Pin a specific release of this library:
```$xslt
go get github.com/coinbase/kryptology@v1.6.0
```

## Documentation

Public documentations can be found at https://pkg.go.dev/github.com/coinbase/kryptology

To access the documentation of the local version, run `godoc -http=:6060` and open
the following url in your browser.

http://localhost:6060/pkg/github.com/coinbase/kryptology/

## Developer Setup
**Prerequisites**: `golang 1.17`, `make`

```$xslt
git clone git@github.com/coinbase/kryptology.git && make 
``` 

## Components

The following is the list of primitives and protocols that are implemented in this repository.

### Curves

The curve abstraction code can be found at [pkg/core/curves/curve.go](pkg/core/curves/curve.go)

The curves that implement this abstraction are as follows.

- [BLS12377](pkg/core/curves/bls12377_curve.go)
- [BLS12381](pkg/core/curves/bls12381_curve.go)
- [Ed25519](pkg/core/curves/ed25519_curve.go)
- [Secp256k1](pkg/core/curves/k256_curve.go)
- [P256](pkg/core/curves/p256_curve.go)
- [Pallas](pkg/core/curves/pallas_curve.go)

### Protocols

The generic protocol interface [pkg/core/protocol/protocol.go](pkg/core/protocol/protocol.go).
This abstraction is currently only used in DKLs18 implementation.

- [Cryptographic Accumulators](pkg/accumulator)
- [Bulletproof](pkg/bulletproof)
- Oblivious Transfer
  - [Verifiable Simplest OT](pkg/ot/base/simplest)
  - [KOS OT Extension](pkg/ot/extension/kos)
- Threshold ECDSA Signature
  - [DKLs18 - DKG and Signing](pkg/tecdsa/dkls/v1)
  - [GG20 - DKG](pkg/dkg/gennaro)
  - [GG20 - Signing](pkg/tecdsa/gg20)
- Threshold Schnorr Signature
  - [FROST threshold signature - DKG](pkg/dkg/frost)
  - [FROST threshold signature - Signing](pkg/ted25519/frost)
- [Paillier encryption system](pkg/paillier)
- Secret Sharing Schemes
  - [Shamir's secret sharing scheme](pkg/sharing/shamir.go)
  - [Pedersen](pkg/sharing/pedersen.go)
  - [Feldman](pkg/sharing/feldman.go)
- [Verifiable encryption](pkg/verenc)
- [ZKP Schnorr](pkg/zkp/schnorr)


## Contributing
- [Versioning](https://blog.golang.org/publishing-go-modules): `vMajor.Minor.Patch`
    - Major revision indicates breaking API change or significant new features
    - Minor revision indicates no API breaking changes and may include significant new features or documentation
    - Patch indicates no API breaking changes and may include only fixes
 
 
## [References](docs/)
- [[GG20] _One Round Threshold ECDSA with Identifiable Abort._](https://eprint.iacr.org/2020/540.pdf)
- [[specV5] _One Round Threshold ECDSA for Coinbase._](docs/Coinbase_Pseudocode_v5.pdf)
- [[EL20] _Eliding RSA Group Membership Checks._](docs/rsa-membership.pdf) [src](https://www.overleaf.com/project/5f9c3b0624a9a600012037a3)
- [[P99] _Public-Key Cryptosystems Based on Composite Degree Residuosity Classes._](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
