# Distributed Key Generation

```go
import "github.com/coinbase/kryptology/pkg/dkg"
```

Package `dkg` is intended to contain implementations of distributed key generation (DKG) protocols. 
Besides the DKG protocol we introduced in `github.com/coinbase/kryptology/pkg/tecdsa/README.md`, currently
package `dkg` contains the following distributed key generation implementations. 

- Gennaro DKG: an adapted version [[overleaf]](https://www.overleaf.com/project/60915c0df1d6917f5cde6657) of 
DKG by Gennaro et al. [[GennaroDKG]](https://link.springer.com/content/pdf/10.1007/s00145-006-0347-3.pdf). (We call it
GennaroDKG for convenience in the following context.)
  
- FROST DKG: the distributed key generation protocol used in [FROST tSchnorr signature](https://tools.ietf.org/pdf/draft-komlo-frost-00.pdf). We also 
have its [pseudocode write-up](https://www.overleaf.com/read/nvmyjwsnbrwj). We call it FROST DKG in the following context.  

## GennaroDKG
### Participant
Gennaro DKG is run by multiple participants distributedly. We define necessary types and 
functions used by each participant under `dkg/gennaro/participant.go`.

#### type Participant
```go
type Participant struct {
    round                  int
    curve                  elliptic.Curve
    scalar                 crypto.EcScalar
    otherParticipantShares map[uint32]*dkgParticipantData
    id                     uint32
    skShare                *sharing.Element
    verificationKey        *sharing.ShareVerifier
    feldman                *sharing.Feldman
    pedersen               *sharing.Pedersen
    pedersenResult         *sharing.PedersenResult
}
```
`Participant` is a DKG player that contains information needed to perform DKG rounds
and yield a secret key share and public key when finished.

#### dkgParticipantData
```go
type dkgParticipantData struct {
	Id        uint32
	Share     *sharing.ShamirShare
	Verifiers []*sharing.ShareVerifier
}
```
`dkgParticipantData` contains values that need to be stored by each participant in
the `otherParticipantShares` field. 

#### func NewParticipant
```go
func NewParticipant(id, threshold uint32, generator *crypto.EcPoint, scalar crypto.EcScalar, otherParticipants ...uint32) (*Participant, error)
```
`NewParticipant` creates a participant ready to perform a DKG.
- `id` is the integer value identifier for this participant
- `threshold` is the minimum bound for the secret sharing scheme
- `generator` is the blinding factor generator used by pedersen's verifiable secret sharing
- `otherParticipants` is the integer value identifiers for the other participants

### DKG Round 1
#### type Round1Bcast
```go
type Round1Bcast = []*sharing.ShareVerifier
```
`Round1Bcast` are the values that are broadcast to all other participants
after round1 completes.

#### type Round1P2PSend
```go
type Round1P2PSend = map[uint32]*Round1P2PSendPacket
```
`Round1P2PSend` are the values that are sent to individual participants based
on the id.

#### type Round1P2PSendPacket
```go
type Round1P2PSendPacket struct {
	secretShare   *sharing.ShamirShare
	blindingShare *sharing.ShamirShare
}
```
`Round1P2PSendPacket` are the shares generated from the secret for a specific participant.

#### func (*Participant) Round1
```go
func (dp *Participant) Round1(secret []byte) (Round1Bcast, Round1P2PSend, error)
```
`Round1` computes the first round for the Gennaro DKG. 

NOTE: if `secret` is nil, a new secret is generated which creates a new key
if `secret` is set, then this performs key resharing aka proactive secret sharing update.

### DKG Round 2
#### type Round2Bcast
```go
type Round2Bcast = []*sharing.ShareVerifier
```
`Round2Bcast` contains the values that will be broadcast to other participants
after completion of DKG Round 2. 

#### func (*Participant) Round2
```go
func (dp *Participant) Round2(bcast map[uint32]Round1Bcast, p2p map[uint32]*Round1P2PSendPacket) (Round2Bcast, error)
```
Round2 computes the second round for Gennaro DKG. See Algorithm 3 - Gennaro DKG Round 2 in [[overleaf]](https://www.overleaf.com/project/60915c0df1d6917f5cde6657).
- `bcast` contains all Round1 broadcast from other participants to this participant.
- `p2p` contains all Round1 P2P send message from other participants to this participant.

### DKG Round 3
#### type Round3Bcast
```go
type Round3Bcast struct {
	VerificationKey *sharing.ShareVerifier
	Success         bool
}
```
`Round3Bcast` contains values that will be broadcast to other participants.

#### func (*Participant) Round3
```go
func (dp *Participant) Round3(bcast map[uint32]Round2Bcast) (*Round3Bcast, *sharing.ShamirShare, error)
```
`Round3` computes the third round for Gennaro DKG. See Algorithm 4 - Gennaro DKG Round 3 in [[overleaf]](https://www.overleaf.com/project/60915c0df1d6917f5cde6657).
- `bcast` contains all Round2 broadcast from other participants to this participant.

### DKG Round 4
#### func (*Participant) Round4
```go
func (dp *Participant) Round4() (map[uint32]*crypto.EcPoint, error)
```
`Round4` computes the public shares used by tECDSA during signing
that are converted to additive shares once the signing participants
are known. This function is idempotent. See Algorithm 5 - Gennaro DKG Round 4 in [[overleaf]](https://www.overleaf.com/project/60915c0df1d6917f5cde6657).

## FROST DKG
### Participant
FROST DKG is run by multiple participants distributedly. We define necessary types and functions used by
each participant under `dkg/frost/participant.go`

#### type DkgParticipant
```go
type DkgParticipant struct {
	round                  int
	curve                  elliptic.Curve
	scalar                 core.EcScalar
	otherParticipantShares map[uint32]*dkgParticipantData
	id                     uint32
	SkShare                *sharing.Element
	verificationKey        *sharing.ShareVerifier
	vkShare                *sharing.ShareVerifier
	feldman                *sharing.Feldman
	verifiers              []*sharing.ShareVerifier
	secretShares           []*sharing.ShamirShare
	ctx                    byte
}
```
`DkgParticipant` is a FROST DKG player that contains information needed to perform DKG rounds and yield
a secret key share and public key when finished. 

#### dkgParticipantData
```go
type dkgParticipantData struct {
	Id        uint32
	Share     *sharing.ShamirShare
	Verifiers []*sharing.ShareVerifier
}
```
`dkgParticipantData` contains values that need to be stored by each participant in
the `otherParticipantShares` field. 

#### var Ctx
```go
Ctx = "fixed context string"
```
`Ctx` is simply a fixed context string that will be used in FROST DKG. It can be any fixed context string. 

#### func NewDkgParticipant
```go
func NewDkgParticipant(id, threshold uint32, ctx string, generator *core.EcPoint, scalar core.EcScalar, otherParticipants ...uint32) (*DkgParticipant, error)
```
`NewDkgParticipant` creates a participant ready to perform FROST DKG.
- `id` is the integer value identifier for this participant.
- `threshold` is the minimum bound for the underlying secret sharing scheme. 
- `ctx` is the fixed context string. 
- `generator` is the blinding factor generator used by Feldman's VSS
- `otherParticipants` is the integer value identifiers for the other participants. 

### DKG Round 1
#### type Round1Bcast
```go
type Round1Bcast struct {
	verifiers []*sharing.ShareVerifier
	wi        *big.Int
	ci        *big.Int
}
```
`Round1Bcast` are the values that are broadcast to all other participants after round 1 completes.

#### type Round1P2PSend
```go
type Round1P2PSend = map[uint32]*sharing.ShamirShare
```
`Round1P2PSend` are the values that are sent to individual participants based on the id. 

#### func (*DkgParticipant) Round1
```go
func (dp *DkgParticipant) Round1(secret []byte) (*Round1Bcast, Round1P2PSend, error)
```
`Round1` computes the first round for the FROST DKG.

NOTE: if `secret` is nil, a new secret is generated which creates a new key. If `secret` is set, then 
this performs key resharing a.k.a, proactive secret sharing update. 

### DKG Round 2
#### type Round2Bcast
```go
type Round2Bcast struct {
	VerificationKey *sharing.ShareVerifier
	VkShare         *sharing.ShareVerifier
}
```
`Round2Bcast` contains the values that will be broadcast to other participants after completion of DKG Round 2. 

#### func (*DkgParticipant) Round2
```go
func (dp *DkgParticipant) Round2(bcast map[uint32]*Round1Bcast, p2psend map[uint32]*sharing.ShamirShare) (*Round2Bcast, error)
```
Round2 computes the second round for FROST DKG. 