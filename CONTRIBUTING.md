# Contributing to Kryptology

Kryptology is Apache 2.0 licensed and accepts contributions via
GitHub pull requests.

# Ways to contribute to Kryptology

- Bugs or issues: Report problems or defects as github issues
- Features and enhancements: Provide expanded capabilities or optimizations
- Documentation: Improve existing documentation or create new information
- Tests for events and results:
    - Functional
    - Performance
    - Usability
    - Security
    - Localization
    - Recovery 
    - Deployability
  
# Code guidelines

Use go style comments for all public functions, structs, and constants.
Export only what is absolutely necessary.

# The Commit Process

When contributing code, please follow these guidelines:

- Fork the repository and make your changes in a feature branch
- Include unit and integration tests for any new features and updates to existing tests
- Ensure that the unit and integration tests run successfully.
- Check that the lint tests pass

## Important
Use `git rebase origin/master` to limit creating merge commits.
Kryptology accepts single commits. If you have more than one, they will be
squashed when merged.

## Commit Email Address
Your commit email address must match your GitHub or GitLab email address. For more information, see https://help.github.com/articles/setting-your-commit-email-address-in-git/.

## Commit messages

Each commit message consists of a header, a body, and a footer.

The header includes a type, a scope and a subject:

```markdown
<type>(<scope>): <subject>
<BLANK LINE>
<body>
<BLANK LINE>
<footer>
```

`<subject>` *required*, must not be longer than 100 characters.

`<type` *required*, must be lower case and have one of the following values:

- `build:` changes that affect the build system or external dependencies. Kryptology uses buildkite.
- `chore:` some minor change that doesn't fall in any of the other types
- `ci:` changes to the continuous integration configuration files
- `docs:` documentation only change
- `feat:` new feature
- `fix:` a bug fix

`<scope>` *optional*, must be lower case and have a tag about which primitive it affects like 'tecdsa/dkls', 'paillier', 'verenc'.  

`<subject>` *optional*, must be lower case and not end in a period describing changes in the imperative-mood.

`<body>` *optional*, characters no more 100 wide, must have a blank line above it describing changes in the imperative-mood.

`<footer>` *optional*, must not be longer than 100 characters.

For more information see [here](https://gist.github.com/joshbuchea/6f47e86d2510bce28f8e7f42ae84c716)

**Kryptology requires that all commits are signed by a PGP key.** 

## Issues and Bugs

If you find a bug in the source code, help us by submitting an issue to the repository. Even better, submit a Pull Request with a fix.

Before submitting an issue search the archive, maybe your question is already answered.

If the issue is a bug, and hasn't been reported, open a new issue. Help us to maximize the effort we can spend fixing issues and adding new features, by not reporting duplicate issues.

For security bugs see the security [policy](SECURITY.md).

In general, providing the following information will increase the chances of the issue being handled quickly:

**Expected Behavior** - Is there documentation or an example that represents the discrepancy?

**Actual Behavior** - Be sure to explain why this is a bug for you.

**Steps to Reproduce the Problem** - Code snippets and screen shots are always helpful.

**Environment** - What hardware, OS, and versions are you using?

**Suggest a Fix** - if you can't fix the bug yourself, perhaps you can point to what might cause the problem (line of code or commit)

## Referencing

When contributing a new protocol or cryptosystem please include references, page numbers and equations.
Document any deviations from the protocol and include an updated security proof if needed.

## Hashing functions

When using hash functions in protocols, use the following guidelines when

32-byte output - SHA3-256
\*-byte output - SHAKE-256

Sigma protocols use [Merlin](https://merlin.cool/) transcripts.

## Constant time

We make every effort to make code cryptographically constant time. All contributions to cryptography related code
should be constant time unless explicitly stated and why.

Below are some algorithms for computing constant time operations that can be used and are meant to be examples.

```go
// conditionalMove returns x when i == 0 and y when i == 1
func conditionalMove(x, y *[4]uint64, i int) {
    b := uint64(-i)
    x[0] ^= (x[0] ^ y[0]) & b
    x[1] ^= (x[1] ^ y[1]) & b
    x[2] ^= (x[2] ^ y[2]) & b
    x[3] ^= (x[3] ^ y[3]) & b
}
```

```go
// conditionalNegate negates x if i == 1, otherwise x is untouched
func conditionalNegate(x *[4]uint64, i int) {
    b := uint64(-i)
    x[0] = (x[0] ^ b) - b
    x[1] = (x[1] ^ b) - b
    x[2] = (x[2] ^ b) - b
    x[3] = (x[3] ^ b) - b
}
```

```go
// conditionalAdd computes x+=y if i == 1, otherwise x is untouched
func conditionalAdd(x, y *[4]uint64, i int) {
    b := uint64(-i)
    x[0] += y[0] & b
    x[1] += y[1] & b
    x[2] += y[2] & b
    x[3] += y[3] & b
}
```

```go
// conditionalSub computes x-=y if i == 1, otherwise x is untouched
func conditionalSub(x, y *[4]uint64, i int) {
    b := uint64(-i)
    x[0] -= y[0] & b
    x[1] -= y[1] & b
    x[2] -= y[2] & b
    x[3] -= y[3] & b
}
```

```go
// isZero returns 1 if x is zero or 0 if non-zero
func isZero(x *[4]uint64) int {
    t := x[0]
    t |= x[1]
    t |= x[2]
    t |= x[3]
    return int(((int64(t) | int64(-t)) >> 63) + 1)
}
```

```go
// isNonZero returns 1 if x is non-zero, 0 otherwise
func isNonZero(x *[4]uint64) int {
    t := x[0]
    t |= x[1]
    t |= x[2]
    t |= x[3]
    return int(-((int64(t) | int64(-t)) >> 63))
}
```
