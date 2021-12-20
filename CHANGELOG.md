# Changelog

All notable changes to this repo will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v1.5.4
- Export Value in ElGamal Public Keys

## v1.5.3
- Address Alpha-Rays attack on GG20 DKG https://eprint.iacr.org/2021/1621.pdf

## v1.5.2
- Export Verifiable Encryption ECC ciphertext values
- Update to GO 1.17

## v1.5.1
- Export tBLS signature Value
- Negate the DKLs signature V value

## v1.5.0
- Add BLS12-381 curve
- Add BLS signatures
- Update to always produce DKLS low-s form

## v1.4.1
- Update accumulator implementation to use alias-ing instead of one field structs
- Update accumulator implementation marshaling implementation

## v1.4.0
- Update verifiable encryption API

## v1.3.0
- Add Accumulator
- Update for new curve abstraction
- Update verifiable encryption API 

## v1.2.0

- Add Verifiable Encryption
- Add FROST DKG
- Add DKLS threshold signing 
- Add curve abstraction
- Pasta Curves: Pallas and Vesta
- BBS+ signatures

## v1.1.0

- Add recovery id to output of tECDSA signatures in Round 6
- Add Neg and Bytes to EcScalar
- Add SubFieldOrder to Field struct

## v1.0.0
### Added

- This document and other meta-information
- tECDSA dealered and distributed key generations
- tECDSA based on [GG20](https://eprint.iacr.org/2020/540.pdf) signing
- Gennaro [DKG07](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.134.6445&rep=rep1&type=pdf) usable for Ed25519 and BLS keys.
- Shamir Secret Sharing
- Feldman Verifiable Secret Sharing
- Pedersen Verifiable Secret Sharing
- Paillier Encryption Scheme
