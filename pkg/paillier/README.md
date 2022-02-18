# Paillier Cryptosystem


Package paillier contains [Paillier's cryptosystem (1999)](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf).
All routines here from pseudocode §2.5. Fig 1: The Paillier Cryptosystem.

This module provides APIs for:

- generating a safe keypair
- encryption and decryption
- adding two encrypted values, `Enc(a)` and `Enc(b)`, and obtaining `Enc(a + b)`, and
- multiplying a plain value, `a`, and an encrypted value `Enc(b)`, and obtaining `Enc(a * b)`.

The encrypted values are represented as `big.Int` and are serializable.
This module also provides JSON serialization for the PublicKey and the SecretKey.
