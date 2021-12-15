# Kryptology
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/github.com/coinbase/kryptology)

Coinbase's advanced cryptography library

## Quickstart
Use the latest version of this library:
```$xslt
go get github.com/coinbase/kryptology
```

Pin a specific release of this library:
```$xslt
go get github.com/coinbase/kryptology@v1.5.1
```

## Components
- [Shamir's secret sharing scheme](pkg/sharing)
- Threshold ECDSA
    - [GG20](pkg/tecdsa/gg20)
    - [DKLs18](pkg/tecdsa/dkls)
- [Distributed key generation](pkg/dkg/gennaro) 
    - [BLS DKG](test/dkg/bls)
    - [ed25119 DKG](test/dkg/ed25519)
- [Verifiable encryption](pkg/verenc)
    
## Developer Setup
**Prerequisites**: `golang 1.16`, `make`

```$xslt
git clone git@github.com:coinbase/kryptology.git && make 
``` 

## Contributing
- [Versioning](https://blog.golang.org/publishing-go-modules): `vMajor.Minor.Patch`
    - Major revision indicates breaking API changes or significant new features
    - Minor revision indicates no API breaking changes and may include significant new features or documentation
    - Patch indicates no API breaking changes and may include only fixes
 
 
## [References](docs/)
- [[GG20] _One Round Threshold ECDSA with Identifiable Abort._](https://eprint.iacr.org/2020/540.pdf)
- [[specV5] _One Round Threshold ECDSA for Coinbase._](docs/Coinbase_Pseudocode_v5.pdf)
- [[EL20] _Eliding RSA Group Membership Checks._](docs/rsa-membership.pdf) [src](https://www.overleaf.com/project/5f9c3b0624a9a600012037a3)
- [[P99] _Public-Key Cryptosystems Based on Composite Degree Residuosity Classes._](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
