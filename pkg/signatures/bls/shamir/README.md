# Shamir Secret Sharing from Hashicorp

This package is kept here for legacy reasons, for our implementation of shamir secret sharing,
check "pkg/sharing/shamir.go"

## The original reasoning for this package
Package shamir is a port of the hashicorp/vault implementation of Shamir's Secret Sharing which has been modified to work with a finite field rather than arbitrary length content.

Their implementation splits every byte independently into shares and transposes the output together to form a single secret. For our purposes, we expect to be able to combine secrets using addition and then reconstruct a shared polynomial which doesn't work with the byte wise sharing.

This implementation IS NOT constant time as it leverages math/big for big number operations through the finitefield package.
