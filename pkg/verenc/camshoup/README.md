# Verifiable encryption

Verifiable encryption addresses a problem about proving statements for encrypted data. Verifiable encryption allows a prover to convince a verifier that a given ciphertext is an encryption under a given public key. A verifiable encryption scheme proves that a ciphertext encrypts a plaintext satisfying a certain relation. Our implementation is a non-interactive zero-knowledge proof (NIZK) i.e. the prover creates the proof and sends it to the verifier with no further interaction.
A verifiable encryption is transferred to a verifier and possibly to a trusted party for decryption. It does not need to be stored at the prover’s side as it usually is not repeatedly needed.

## Why?
Think of scenarios that allow signers or provers to remain anonymous but where some information about the prover needs to be known and is put into escrow. The escrow service can be a trusted third party or the verifier themselves. The prover encrypts an attribute to a specific public key and creates a NIZK proof of knowledge of the attribute for the resulting ciphertext. To recover the attribute, the opener simply decrypts the ciphertext. It is recommended that a trusted escrow service serve this purpose and not the verifier such that only the trusted authority can actually recover the attribute. The attribute can be anything including a secret key. Another term for this can be a Verifiable Escrow Service.

Note that a key escrow scheme cannot prevent parties from double-encrypting messages under a non-escrowed key, or applying steganography to hide the fact that they are communicating altogether. The goal, therefore, is rather to prevent “dishonest” usage of public-key infrastructures, e.g., by using it to certify non-escrowed keys.

## How it works

Camenisch-Shoup Verifiable encryption is similar to RSA and based on
Paillier's Decision Composite Residuosity http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf. A group of unknown order is created from two safe primes p, q where p = 2p'+1, q = 2q'+1 and p', q' are also prime and p &ne; q.

The group parameters are computed as follows:

    1. Set n = p * q
    2. Sample a random g' < n^2
    3. Set g = g'^2n
    4. Set h = n + 1

Secret keys are computed as follows

1. Sample three random values x_1,x_2,x_3 < n^2/4
2. The secret key is {x_1,x_2,x_3}

Public keys are computed as follows

    1. Compute y_1 = g^x1
    2. Compute y_2 = g^x2
    3. Compute y_3 = g^x3
    4. The public key is {y_1, y_2, y_3}

The group parameters can be stored separate or together with each key.

Proving

Verifiable encryption not only produces a ciphertext that can be decrypted, but also yields a proof that the plaintext is encrypted to a specific public key.
The ciphertext is represented as the triplet {u, e, v}, the proof is represented as the Schnorr proof challenge c with responses m, r.

## References

Practical Verifiable Encryption and Decryption of Discrete Logarithms - Jan Camenisch and Victor Shoup 2003. https://eprint.iacr.org/2002/161.pdf

Specification of the Identity Mixer Cryptographic Library - IBM Zurich 2009. https://dominoweb.draco.res.ibm.com/reports/rz3730_revised.pdf

Public-Key Cryptosystems Based on Composite Degree Residuosity Classes - Pascall Paillier 1999. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf
