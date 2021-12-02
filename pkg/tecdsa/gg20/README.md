# Threshold ECDSA

```go
import "github.com/coinbase/kryptology/pkg/tecdsa/gg20"
```

Package tecdsa contains the implementation of threshold ECDSA (tECDSA) pseudocode for Coinbase [[specV5]](docs/Coinbase_Pseudocode_v5.pdf). 
It supports tECDSA with two different key generation approaches: (1). key generation with a trusted dealer and (2). distributed key generation.
We introduce them separately in the following context.
## KeyGenType
KeyGenType is designed to determine which key generation mode a tECDSA participant should use. The corresponding interfaces and functions are defined in `tecdsa/dealer/keygentype.go`.

```go
type KeyGenType interface {
	IsTrustedDealer() bool
	GetProofParams(id uint32) *ProofParams
}
```
KeyGenType encapsulates the different methods that tecdsa can generate keys. Currently TrustedDealer or Distributed Key Generation

```go
type TrustedDealerKeyGenType struct {
	ProofParams *ProofParams
}
```
`TrustedDealerKeyGenType` is used when we generate keys using a trusted dealer. It 
means the same proof parameters will be used by all participants and be distributed by the trusted dealer.

```go
type DistributedKeyGenType struct {
	ProofParams map[uint32]*ProofParams
}
```
`DistributedKeyGenType` is used when we use distributed key generation. It 
means each participant has their own proof params that were distributed to each other
participant.

### Usage
```go
func (td TrustedDealerKeyGenType) IsTrustedDealer() bool 
```
`IsTrustedDealer` returns true if in trusted dealer mode.

```go
func (td TrustedDealerKeyGenType) GetProofParams(_ uint32) *ProofParams
```
`GetProofParams` returns the proof params specified by the participant id in trusted dealer mode.

```go
func (dkg DistributedKeyGenType) IsTrustedDealer() bool
```
`IsTrustedDealer` returns false if in distributed key generation mode

```go
func (dkg DistributedKeyGenType) GetProofParams(id uint32) *ProofParams
```
`GetProofParams` returns the proof params specified by the participant id in distributed key generation mode.

## Participant
tECDSA is run by multiple participants and these participants create a signature together. We define different types of participants and 
corresponding functions in `tecdsa/participant/participant.go`. 

### type DkgParticipant
```go
type DkgParticipant struct {
	Curve elliptic.Curve
	state *dkgstate
	id    uint32
	Round uint
}
```
`DkgParticipant` is a DKG player that contains information needed to perform DKG rounds and finally get info for signing rounds.

### type dkgstate
```go
type dkgstate struct {
	// Round 1 variables
	D  *crypto.Witness
	Sk *paillier.SecretKey
	Pk *paillier.PublicKey
	N  *big.Int
	H1 *big.Int
	H2 *big.Int
	// This participants verifiers from FeldmanShare
	V []*sharing.ShareVerifier
	// This participants shares from FeldmanShare
	X         []*sharing.ShamirShare
	Y         *crypto.EcPoint
	Threshold uint32
	Limit     uint32
	// Commitments and paillier public keys received from other participants
	otherParticipantData map[uint32]*dkgParticipantData
	// xi returned from Round 3
	Xi *big.Int
	// X1,...,Xn returned from Round 3
	PublicShares []*crypto.EcPoint
}
```
`dkgstate` encapsulates all the values used in the dkg rounds state machine

### type dkgParticipantData
```go
type dkgParticipantData struct {
	PublicKey   *paillier.PublicKey
	ProofParams *dealer.ProofParams
	Commitment  crypto.Commitment
}
```
`dkgParticipantData` encapsulates all the values that need to be stored in `dkgstate`

### type Participant
```go
type Participant struct {
	dealer.Share
	sk *paillier.SecretKey
}
```
`Participant` is a tECDSA player. Note that `Participant` is not already a 
co-signer of tECDSA. If it is in trusted dealer mode, it receives information from the 
trusted dealer. If it is in distributed key generation mode, the participant generates 
or receives those information via the distributed key generation protocol. 

### type Signer
```go
type Signer struct {
	sk              *paillier.SecretKey            // paillier secret key assigned to this signer
	share           *sharing.ShamirShare           // secret signing share for this signer
	publicSharesMap map[uint32]*dealer.PublicShare // public shares of our cosigners
	id              uint32                         // The ID assigned to this signer's shamir share
	// This is minimum number of signers required to produce a valid signature,
	// not the security threshold (as specified in [spec][GG20])
	threshold uint
	PublicKey *crypto.EcPoint
	Curve     elliptic.Curve
	Round     uint   // current signing round in our linear state machine
	state     *state // Accumulated intermediate values associated with signing
}
```
`Signer` is a tECDSA player that holds the additive shares needed for performing the signing operation. 
`Signer` is the actual participant joining tECDSA signing operations. 

### type EcdsaSignature
```go
type EcdsaSignature struct {
	R, S *big.Int
}
```
`EcdsaSignature` represents a (composite) digital signature

### type EcdsaVerify
```go
type EcdsaVerify func(pubKey *crypto.EcPoint, hash []byte, signature *EcdsaSignature) bool
```
`EcdsaVerify` runs a curve- or algorithm-specific ECDSA verification function on input
an ECDSA public (verification) key, a message digest, and an ECDSA signature.
It must return true if all the parameters are sane and the ECDSA signature is valid, 
and false otherwise

### func (*Signer) verifyStateMap
```go
func (signer *Signer) verifyStateMap(round uint, in interface{}) error
```
`verifyStateMap` verifies the round is the expected round number and
that the set of signers from `in.keys()` exactly matches the set
in `state.cosigners`.

### func (*Signer) setCosigners
```go
func (signer *Signer) setCosigners(in []uint32) error
```
`setCosigners` establishes the list of cosigner IDs. This may or may not include self ID.

### func (*Signer) resetSignRound
```go
func (signer *Signer) resetSignRound()
```
`resetSignRound` sets the signer to a pre-round1 state.

### func (Participant) convertToAdditive
```go
func (p Participant) convertToAdditive(curve elliptic.Curve, publicSharesMap map[uint32]*dealer.PublicShare) (*Signer, error)
```
`convertToAdditive` takes all the publicShares and changes them to their additive form
for this participant. Only t shares are needed for this step. See fig.6 in [[specV5]](docs/Coinbase_Pseudocode_v5.pdf).

### func (Participant) PrepareToSign
```go
func (p Participant) PrepareToSign(pubKey *crypto.EcPoint,
	verify EcdsaVerify,
	curve elliptic.Curve,
	keyGenType dealer.KeyGenType,
	publicSharesMap map[uint32]*dealer.PublicShare,
	pubKeys map[uint32]*paillier.PublicKey) (*Signer, error)
```
`PrepareToSign` creates a `Signer` out of a `Participant`. The expected co-signers for the signing rounds are
expected to be exactly those included in the `publicSharesMap`

### func makeXMap
```go
func makeXMap(curve elliptic.Curve, publicSharesMap map[uint32]*dealer.PublicShare) (map[uint32]*sharing.Element, error)
```
`makeXMap` creates a map of polynomial x-coordinates that are field elements.

### func (*DkgParticipant) verifyDkgRound
```go
func (dp *DkgParticipant) verifyDkgRound(dkground uint) error
```
`verifyDkgRound` checks DKG round number is valid. 

## Trusted Dealer Mode
Recall that our tECDSA can work with two key generation modes. One is the trusted dealer mode
and another one is the distributed key generation mode. In trusted dealer mode, the dealer is responsible to prepare input values for 
all participants to run tECDSA. The output of the key generation (using trusted dealer)
should contain the following
- A public ECDSA signing key, 
- Private key shares for each signer corresponding to the public signing key.
- Paillier key pairs for each player
- Trusted parameters for instantiating the zero-knowledge proofs that
will be employed during the signing protocol. 

The types and functions defined for the trusted dealer are defined in `tecdsa/dealer/dealer.go`

### type ParticipantData
```go
type ParticipantData struct {
	Id             uint32
	DecryptKey     *paillier.SecretKey
	SecretKeyShare *Share
	// Public values set to all signing participants
	EcdsaPublicKey *crypto.EcPoint
	KeyGenType     KeyGenType
	PublicShares   map[uint32]*PublicShare
	EncryptKeys    map[uint32]*paillier.PublicKey
}
```
`ParticipantData` represents all data to be sent to a participant after the dealer is finished

### type ParticipantDataJson
```go
type ParticipantDataJson struct {
	Id             uint32
	DecryptKey     *paillier.SecretKey
	SecretKeyShare *Share
	// Public values set to all signing participants
	EcdsaPublicKey    *crypto.EcPoint
	DealerParams      *ProofParams
	ParticipantParams map[uint32]*ProofParams
	PublicShares      map[uint32]*PublicShare
	EncryptKeys       map[uint32]*paillier.PublicKey
}
```
`ParticipantDataJson` encapsulates the data that is serialized to JSON used internally and not for external use. Public so other pieces can use for serialization

### func (ParticipantData) MarshalJSON
```go
func (pd ParticipantData) MarshalJSON() ([]byte, error)
```
`MarshalJSON` converts `ParticipantData` into json format

### func (*ParticipantData) UnmarshalJSON
```go
func (pd *ParticipantData) UnmarshalJSON(bytes []byte) error
```
`UnmarshalJSON` converts json format data into this `ParticipantData`

### type ProofParams
```go
type ProofParams struct {
	// n is the modulus for the signing rounds, product of two safe primes
	N *big.Int
	// h1 random value quadratic residue in n
	H1 *big.Int
	// h2 is a random modular power of h1
	H2 *big.Int
}
```
`ProofParams` is the modulus and generators used when constructing keys and completing the signing rounds

### type PublicShare
```go
type PublicShare struct {
	Point *crypto.EcPoint
}
```
`PublicShare` can be sent to a Participant as a part of `ParticipantData` so it can be used to convert Share to its additive form.

### type Share
```go
type Share struct {
	*sharing.ShamirShare
	Point *crypto.EcPoint
}
```
`Share` represents a piece of the tECDSA private key and a commitment to the share.

### type ShareJson
```go
type ShareJson struct {
	Identifier uint32   // x-coordinate
	Value      *big.Int // y-coordinate
	Point      *crypto.EcPoint
}
```
`ShareJson` encapsulates the data that is serialized to JSON
used internally and not for external use. Public so other pieces
can use for serialization

### func (Share) MarshalJSON
```go
func (s Share) MarshalJSON() ([]byte, error)
```
`MarshalJSON` converts `Share` into json format

### func (*Share) UnmarshalJSON
```go
func (s *Share) UnmarshalJSON(bytes []byte) error
```
`UnmarshalJSON` converts json format data into this `Share`

### func NewProofParams
```go
func NewProofParams() (*ProofParams, error)
```
`NewProofParams` creates new ProofParams with "bits" sized values

### func NewProofParamsWithPrimes
```go
func NewProofParamsWithPrimes(p, q *big.Int) (*ProofParams, error)
```
`NewProofParamsWithPrimes` creates new ProofParams using the parameters as safe primes

### func PreparePublicShares
```go
func PreparePublicShares(sharesMap map[uint32]*Share) (map[uint32]*PublicShare, error)
```
`PreparePublicShares` makes public shares that can be sent to the participant to compute their additive shares and participate in signing rounds

### func NewSecret
```go
func NewSecret(curve elliptic.Curve) (*big.Int, error)
```
`NewSecret` generates a new (randomly sampled) secret key.

### func DerivePublicKey
```go
func DerivePublicKey(curve elliptic.Curve, secretKey *big.Int) (*crypto.EcPoint, error)
```
`DerivePublicKey` generates a public key by taking input a secret key. 

### func NewDealerShares
```go
func NewDealerShares(curve elliptic.Curve, threshold, total uint32, ikm *big.Int) (*crypto.EcPoint, map[uint32]*Share, error)
```
`NewDealerShares` generates the Secp256k1 private key shares and public key. if the parameter `ikm=nil`, a new
private key will be generated, otherwise using `ikm` as the private key. 

### func genProofParams
```go
func genProofParams(genSafePrime func(uint) (*big.Int, error), genRandInMod func(*big.Int) (*big.Int, error), bits uint) (*ProofParams, error)
```
`genProofParams` creates all the values needed for ProofParams using the specified genSafePrime function, genRandInMod function, and number of bits.

## Distributed Key Generation (DKG) Mode
Another approach to generate tECDSA input values is using the DKG mode.
Unlike the trusted dealer mode in which the trusted dealer generates input values
for all tECDSA participants, all participants in the DKG mode run a 4-round distributed 
key generation protocol to generate their own input values without a trusted
dealer. The output of the DKG mode should contain the following

- A public ECDSA signing key,
- Private key shares for each signer corresponding to the public signing key.
- Paillier key pairs for each player
- Per-player parameters for instantiating the zero-knowledge proofs that will be employed during the
  signing protocol.
  
### DKG Round 1
#### type DkgRound1Bcast
```go
type DkgRound1Bcast struct {
    Identifier       uint32
    Ci               crypto.Commitment
    Pki              *paillier.PublicKey
    H1i, H2i, Ni     *big.Int
    Proof1i, Proof2i *proof.CdlProof
}
```
`DkgRound1Bcast` contains values to be broadcast to all players after the completion of DKG round 1.

#### func (*DkgParticipant) DkgRound1
```go
func (dp *DkgParticipant) DkgRound1(threshold, total uint32) (*DkgRound1Bcast, error)
```
`DkgRound1` performs round 1 distributed key generation operation. See fig.5 - DistKeyGenRound1 in [[specV5]](docs/Coinbase_Pseudocode_v5.pdf).

### DKG Round 2
#### type DkgRound2Bcast
```go
type DkgRound2Bcast struct {
	Di *crypto.Witness
}
```
`DkgRound2Bcast` contains value that will be echo broadcast to all other players after DKG round 2.

#### type DkgRound2P2PSend
```go
type DkgRound2P2PSend struct {
	xij *sharing.ShamirShare
}
```
`DkgRound2P2PSend` contains value that will be P2PSend to all other player Pj after Dkg round 2.

#### func (*DkgParticipant) DkgRound2
```go
func (dp *DkgParticipant) DkgRound2(params map[uint32]*DkgRound1Bcast) (*DkgRound2Bcast, map[uint32]*DkgRound2P2PSend, error)
```
`DkgRound2` implements distributed key generation round 2. See fig.5 - DistKeyGenRound2 in [[specV5]](docs/Coinbase_Pseudocode_v5.pdf)

### DKG Round 3

#### func (*DkgParticipant) DkgRound3
```go
func (dp *DkgParticipant) DkgRound3(d map[uint32]*crypto.Witness, x map[uint32]*sharing.ShamirShare) (proof.PsfProof, error)
```
DkgRound3 computes dkg round 3 as shown in [[specV5]](docs/Coinbase_Pseudocode_v5.pdf) fig. 5 - DistKeyGenRound3.

#### func unmarshalFeldmanVerifiers
```go
func unmarshalFeldmanVerifiers(curve elliptic.Curve, msg []byte, verifierSize, threshold int) ([]*sharing.ShareVerifier, error)
```
### DKG Round 4
#### type DkgResult
```go
type DkgResult struct {
	PublicShares    []*crypto.EcPoint
	VerificationKey *crypto.EcPoint
	SigningKeyShare *big.Int
	EncryptionKey   *paillier.SecretKey
	ParticipantData map[uint32]*DkgParticipantData
}
```
`DkgResult` contains all the data generated from the DKG.

#### type DkgParticipantData
```go
type DkgParticipantData struct {
	PublicKey   *paillier.PublicKey
	ProofParams *dealer.ProofParams
}
```
`DkgParticipantData` contains values that should be output as a part of `DkgResult`.

#### func (*DkgParticipant) DkgRound4
```go
func (dp *DkgParticipant) DkgRound4(psfProof map[uint32]proof.PsfProof) (*DkgResult, error)
```
`DkgRound4` implements DKG round 4. See fig.5 - DistKeyGenRound4 in [[specV5]](docs/Coinbase_Pseudocode_v5.pdf).

## tECDSA Signing Rounds
After the key generation phase either via the trusted dealer mode or the DKG mode. tECDSA co-signers
have obtained their input values and they are ready to run the 6-round signing protocol to create a valid signature.

### Sign Round 1
#### type Round1Bcast
```go
type Round1Bcast struct {
	Identifier uint32
	C          crypto.Commitment
	Ctxt       *big.Int
	Proof      *proof.Range1Proof
}
```
`Round1Bcast` contains values to be broadcast to all players after the completion of singing round 1.

#### type Round1P2PSend
```go
type Round1P2PSend = proof.Range1Proof
```
`Round1P2PSend` contains the value to be P2P send to all other players Pj after the completion of signing round 1.

#### func (*Signer) SignRound1
```go
func (signer *Signer) SignRound1() (*Round1Bcast, map[uint32]*Round1P2PSend, error)
```
`SignRound1` performs round 1 signing operation.
See [[specV5]](docs/Coinbase_Pseudocode_v5.pdf) for details:
- If in the trusted dealer mode, see fig.7 - SignRound1
- If in the DKG mode, see fig.8 - SignRound1

NOTE: Pseudocode shows N~, h1, h2, the curve's g, q, and signer's public key as inputs.
Since `signer` already knows the paillier secret and public keys, this input is not necessary here
`participant.PrepareToSign` receives the other inputs and stores them as state variables.

### Sign Round 2
#### type P2PSend
```go
type P2PSend struct {
	Proof2, Proof3 proof.ResponseFinalizer
}
```
`P2PSend` is all the values that need to be sent to each player after completion of signing round 2.

#### func (*P2PSend) UnmarshalJSON
```go
func (p2ps *P2PSend) UnmarshalJSON(bytes []byte) error
```
`UnmarshalJSON` explicitly unmarshals into ResponseProofs instead of ResponsFinalizer interface.

#### func (*Signer) SignRound2
```go
func (signer *Signer) SignRound2(params map[uint32]*Round1Bcast, p2p map[uint32]*Round1P2PSend) (map[uint32]*P2PSend, error)
```
SignRound2 performs round 2 signing operations for a single signer.
See [[specV5]](docs/Coinbase_Pseudocode_v5.pdf) for details:
- If in the trusted dealer mode, see fig.7 - SignRound2
- If in the DKG mode, see fig.8 - SignRound2

### Sign Round 3
#### type Round3Bcast and Round3BcastJSON
```go
type (
	Round3Bcast struct {
		// Note that deltaElement is some element of the entire δ vector.
		// In this round, it's δ_i. For the recepients of this message in the next round
		// this will be δ_j
		deltaElement *big.Int
		// The reason we can't do something straightforward like `type BetterRound3Bcast *big.int`
		// is that although `big.int` has some methods implementing marshaler,
		// they won't be accessible to `BetterRound3Bcast`. So the json.Marhsal uses the default methods
		// and since the two fields of `big.int` are not exported, the data of `BetterRound3Bcast`
		// won't actually be serialized and its deserialization results in nil.
	}

	Round3BcastJSON struct {
		DeltaElement *big.Int
	}
)
```
`Round3Bcast` represents the value to be broadcast to all players at the conclusion of round 3.
`Round3BcastJSON` represents the json format of `Round3Bcast`.

#### func (Round3Bcast) MarshalJSON
```go
func (r3b Round3Bcast) MarshalJSON() ([]byte, error)
```
`MarshalJSON` converts `Round3Bcast` to its json format. 

#### func (*Round3Bcast) UnmarshalJSON
```go
func (r3b *Round3Bcast) UnmarshalJSON(data []byte) error
```
`UnmarshalJSON` converts the input json format data into this `Round3Bcast`.

#### func (*Signer) SignRound3
```go
func (s *Signer) SignRound3(in map[uint32]*P2PSend) (*Round3Bcast, error)
```
SignRound3 performs the round 3 signing operation according to [[specV5]](docs/Coinbase_Pseudocode_v5.pdf).
- If in the trusted dealer mode, see fig.7 - SignRound3.
- If in the DKG mode, see fig.8 - SignRound3.

### Sign Round 4
#### type Round4Bcast
```go
type Round4Bcast struct {
	Witness *crypto.Witness
}
```
`Round4Bcast` are the values to be broadcast to the other players at the conclusion of signing round 4.

#### func (*Signer) SignRound4
```go
func (s *Signer) SignRound4(deltas map[uint32]*Round3Bcast) (*Round4Bcast, error)
```
`SignRound4` performs the round 4 signing operation. It takes input the delta_j values broadcast from signers at the conclusion of round 3.
See [[specV5]](docs/Coinbase_Pseudocode_v5.pdf) for details:
- If in the trusted dealer mode, see fig.7 - SignRound4.
- If in the DKG mode, see fig.8 - SignRound4.

### Sign Round 5
#### type Round5Bcast
```go
type Round5Bcast struct {
	Rbar  *crypto.EcPoint
	Proof *proof.PdlProof
}
```
`Round5Bcast` are the values to be broadcast to the other players at the conclusion of signing round 5.

#### type Round5P2PSend
```go
type Round5P2PSend = proof.PdlProof
```
`Round5P2PSend` are the values sent to each participant at the conclusion of signing round 5.

#### func (*Signer) SignRound5
```go
func (signer *Signer) SignRound5(witnesses map[uint32]*Round4Bcast) (*Round5Bcast, map[uint32]*Round5P2PSend, error)
```
`SignRound5` performs the round 5 signing operation. It takes input
the Witness values broadcast from signers at the conclusion of
round 4.
- If in the trusted dealer mode, see fig.7 - SignRound5.
- If in the DKG mode, see fig.8 - SignRound5.

### Sign Round 6
#### type Round6FullBcast and Round6FullBcastJSON
```go
type (
	Round6FullBcast struct {
		// Note that sElement is some element of the entire s vector.
		// In this round, it's s_i. For the recipients of this message in the final
		// sign output round, this will be s_j
		sElement *big.Int
		// The reason we can't do something straightforward like `type BetterRound6FullBcast *big.int`
		// is that although `big.int` has some methods implementing marshaler,
		// they won't be accessible to `BetterRound6FullBcast`. So the json.Marhsal uses the default methods
		// and since the two fields of `big.int` are not exported, the data of `BetterRound6FullBcast`
		// won't actually be serialized and its deserialization results in nil.
	}

	Round6FullBcastJSON struct {
		SElement *big.Int
	}
)
```
`Round6FullBcast` are the values to be broadcast to the other players. 
This is the s_i value from [[specV5]](docs/Coinbase_Pseudocode_v5.pdf) - fig 7.SignRound6.step 9.

#### func (Round6FullBcast) MarshalJSON
```go
func (r6b Round6FullBcast) MarshalJSON() ([]byte, error)
```
`MarshalJSON` converts `Round6FullBcast` to its json format.

#### func (*Round6FullBcast) UnmarshalJSON
```go
func (r6b *Round6FullBcast) UnmarshalJSON(data []byte) error
```
`UnmarshalJSOn` converts the input json format data to this `Round6FullBcast`.

#### func (*Signer) SignRound6Full
```go
func (signer *Signer) SignRound6Full(hash []byte, in map[uint32]*Round5Bcast, p2p map[uint32]*Round5P2PSend) (*Round6FullBcast, error)
```
`SignRound6Full` performs the round 6 signing operation according to
[[specV5]](docs/Coinbase_Pseudocode_v5.pdf).
- If in the trusted dealer mode, see fig.7 - SignRound6.
- If in the DKG mode, see fig.8 - SignRound6.

#### func (*Signer) signRound6Offline
```go
func (signer *Signer) signRound6Offline(in map[uint32]*Round5Bcast, p2p map[uint32]*Round5P2PSend) error
```
`signRound6Offline` performs the round 6 signing operation according to
[[specV5]](docs/Coinbase_Pseudocode_v5.pdf) - fig.9 - SignRound6Offline. 

#### func (*Signer) signRound6Online
```go
func (signer *Signer) signRound6Online(hash []byte) (*Round6FullBcast, error)
```
`SignRound6Online` performs the round 6 signing operation according to
[[specV5]](docs/Coinbase_Pseudocode_v5.pdf) - fig.9 - SignRound6Online.

#### func (*Signer) SignOutput
```go
func (signer *Signer) SignOutput(in map[uint32]*Round6FullBcast) (*EcdsaSignature, error)
```
`SignOutput` performs the signature aggregation step according to [[specV5]](docs/Coinbase_Pseudocode_v5.pdf).
- If in the trusted dealer mode, see fig.7 - SignOutput.
- If in the DKG mode, see fig.8 - SignOutput.

#### func (Signer) normalize
```go
func (signer Signer) normalizeS(s *big.Int) *big.Int
```
Normalize the signature to a "low S" form. In ECDSA, signatures are
of the form (r, s) where r and s are numbers lying in some finite
field. The verification equation will pass for (r, s) iff it passes
for (r, -s), so it is possible to ``modify'' signatures in transit
by flipping the sign of s. This does not constitute a forgery since
the signed message still cannot be changed, but for some applications,
changing even the signature itself can be a problem. Such applications
require a "strong signature". It is believed that ECDSA is a strong
signature except for this ambiguity in the sign of s, so to accommodate
these applications we will only produce signatures for which
s is in the lower half of the field range. This eliminates the
ambiguity.

However, for some systems, signatures with high s-values are considered
valid. (For example, parsing the historic Bitcoin blockchain requires
this.) We normalize to the low S form which ensures that the s value
lies in the lower half of its range.
See <https://en.bitcoin.it/wiki/BIP_0062#Low_S_values_in_signatures>.
  
