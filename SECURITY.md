# Coinbase Security Policy

## Reporting a Security Bug

If you think you have discovered a security issue within any part of this codebase, please let us know. We take security bugs seriously; upon investigating and confirming one, we will patch it within a reasonable amount of time, and ultimately release a public security bulletin, in which we discuss the impact and credit the discoverer.

There are two ways to report a security bug. The easiest is to submit a report to [HackerOne](https://hackerone.com/coinbase) which includes a description of the flaw and any related information (e.g. steps to reproduce, version, etc.).

You can also file a confidential security bug in [GitHub](https://github.com/coinbase/kryptology/security/advisories).

## Cryptographic Vulnerabilities

It can conceivably happen that a flaw is found in  a cryptographic protocol which kryptology implements as written. In this case, kryptology's code would likewise become vulnerable. In this circumstance, we will endeavor to discern and implement a fix as soon as possible. In any case, we will disclose the vulnerability, as well as any measures we're taking to fix it, in the protocol's `SECURITY.md` file. We will collect links to all such documents immediately below.

 - [Vulnerabilities in [GG20].](/pkg/tecdsa/gg20/SECURITY.md)