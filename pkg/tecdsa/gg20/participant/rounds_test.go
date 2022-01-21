//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"math/big"
	"testing"

	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/btcsuite/btcd/btcec"
	tt "github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
)

var (
	dealerParams = &dealer.ProofParams{
		N:  tt.B10("135817986946410153263607521492868157288929876347703239389804036854326452848342067707805833332721355089496671444901101084429868705550525577068432132709786157994652561102559125256427177197007418406633665154772412807319781659630513167839812152507439439445572264448924538846645935065905728327076331348468251587961"),
		H1: tt.B10("130372793360787914947629694846841279927281520987029701609177523587189885120190605946568222485341643012763305061268138793179515860485547361500345083617939280336315872961605437911597699438598556875524679018909165548046362772751058504008161659270331468227764192850055032058007664070200355866555886402826731196521"),
		H2: tt.B10("44244046835929503435200723089247234648450309906417041731862368762294548874401406999952605461193318451278897748111402857920811242015075045913904246368542432908791195758912278843108225743582704689703680577207804641185952235173475863508072754204128218500376538767731592009803034641269409627751217232043111126391"),
	}
	testPrimes = []*big.Int{
		tt.B10("186141419611617071752010179586510154515933389116254425631491755419216243670159714804545944298892950871169229878325987039840135057969555324774918895952900547869933648175107076399993833724447909579697857041081987997463765989497319509683575289675966710007879762972723174353568113668226442698275449371212397561567"),
		tt.B10("94210786053667323206442523040419729883258172350738703980637961803118626748668924192069593010365236618255120977661397310932923345291377692570649198560048403943687994859423283474169530971418656709749020402756179383990602363122039939937953514870699284906666247063852187255623958659551404494107714695311474384687"),
		tt.B10("130291226847076770981564372061529572170236135412763130013877155698259035960569046218348763182598589633420963942796327547969527085797839549642610021986391589746295634536750785366034581957858065740296991986002552598751827526181747791647357767502200771965093659353354985289411489453223546075843993686648576029043"),
		tt.B10("172938910323633442195852028319756134734590277522945546987913328782597284762767185925315797321999389252040294991952361905020940252121762387957669654615602135429944435719699091344247805645764550860505536884031064967454028383404046221898300153428182409080298694828920944094158777327533157774919783417586902830043"),
		tt.B10("135841191929788643010555393808775051922265083622266098277752143441294911675705272940799534437169053045878247274810449617960047255023823301284034559807472662111224710158898548617194658983006262996831617082584649612602010680423107108651221824216065228161009680618243402116924511141821829055830713600437589058643"),
		tt.B10("179677777376220950493907657233669314916823596507009854134559513388779535023958212632715646194917807302098015450071151245496651913873851032302340489007561121851068326577148680474495447007833318066335149850926605897908761267606415610900931306044455332084757793630487163583451178807470499389106913845684353833379"),
		tt.B10("62649985409697862206708027961094957171873130708493280862148817115812710388878279240372941307490519941098268192630359164091992515623574326498710952492586770923230983753287493884398990474917756375654842939939940915963324175552421981212594421823752854754541693709434365609636589761589816398869727328798680335583"),
		tt.B10("196576931859098680370388202020086631604584490828609819764890020064880575503817891126703473215983239396058738287255240835101797315137072822716923594188151190460588551553676484461393180135097616711975997391550414447010491794087888246885960280296709672609456539741162207414899687167396008233995214434586323322859"),
		tt.B10("271336420864746369701165973306090650688066226258594853124089876839120277465060891854507381090238664515950686049792387028144049076707224579184820539700879884119579186284072404459682082855184644444282438298561112002507411996589407330801765394106772460665497195944412067027079123717579308322520985921886949051399"),
		tt.B10("147653127360336844448178027222853805809444645720500374788954343695331927468524513989671450440433430392339037667457657655958027740671071573403925974795764987870476118984896439440386146680643457835633462311776946902713168513155240275028008685964121441954481847113848701823211862974120297600518927026940189810103"),
		tt.B10("61539010433774119199101441060312213379096965116494840834113311373246794436251480454630309900106802555812462300777026043563820643373439814989443964169335227347638731691284339678436222951965582264570176875078394338903074717434072995072121221264531723385013005031614327462206339323414428493321384497439106152163"),
		tt.B10("311771090987243597109711542316907830756641693311804000593662622484722315782429237915515708860530841821213561483232298821623675096481796856960171671330638042763441430256097782130268494276848432981045602236986861083392706904041234926428759947857376161689191720483868111001987710383245853931937989224732484206639"),
		tt.B10("348545239501897032367950520763624245702184225360238826931782856428685149253861325854706825698843098817604431561258712026020688621010635185480321876001016614912927680387840531641703966894322797491484955817022624047355473480912508041252361257911175397626575812830091471419378132244146077774966527307225203863239"),
		tt.B10("167562983031509383478485987630533113343120902430985961468758712448125734458812918541051012669749885569679178971612428577288632429606851871845164719448590160530844833425628143996971699662729056519326776907622035340086832629206691942750594912221135787534670122007438859975313187460872690748138136170080913902203"),
		tt.B10("151715609132228776595716500435665208768897792993205818803431003524953811539898459230192282642811956896879836518212758893685104146944932088195466999437630114129887975508715417094019351746027667352287673763064246395392591213231796089814648654152625331299642171758052545451706130433176935280325874961374276589763"),
		tt.B10("281712498774102170277967098381151873986368736986748325672760355775943894718315925237789122870763991635031524237638254080973752419302437870447849091185409669906909828874532209010547976564209374430136988588219470076527433259993640332285914706329187116209118972038509278879237122949265824264856530096167843589043"),
		tt.B10("86882427063713590116032012033991745733440719961931885774819345297872782432110706546175706398857226544896860987721577779470479838062106788873559026307646871133570915480684987993282364698928926188640576189281202695899665555602891606955025957497645420156315890379148794822782242384167644977894987285630058930123"),
		tt.B10("83303406464212917441403726886711948278716398972782717472384580707071541544369912289531948826578557956123897261910116726555850408667234850301141318443154703778225305104540324875867615851047711871915209458107086347063530255813116254895432804373554367035028329996279513893337862177371103671113527972705508417219"),
		tt.B10("290829612093510969863838578444630131194824970528125429399090307997156531200557462531776190769158191441614466855963164356672434851525764502180873524299787560160992955274777477308009367164212073773611071813219472273292916120276721541591451163160398750751633065097434700462944540404208636130411713202759646572187"),
		tt.B10("48881643615473281990659967689574873112454227417010573158578046287415357392674453353386274403945930212163960526780980360358370255117866064326375672959460785974850231208253282115124348836379470403659096433419030132737534978624170609788431758477453270578400762995584298785082853409573009591146163658067217132999"),
		tt.B10("47818664065019136841944639898604168570191742429107462510943153778085167306149797958497736138014922106778177497683417470713996340979203175236987691632152128071256018368891463388744514315997309312144264057334961479235114340091423812710466596081259537323405527816634204224641066174554915788023121121924554823463"),
		tt.B10("229695065817346126758526483359337260282925372883465036895664320607569899180246065431164369223444026964554195802821338287119074827091354255558249504915527499047398698041873875019622138440848556549357174461846992529556315682586788137744896985847052668283284231628825924370859640129811142861116994552829398428647"),
		tt.B10("100501115016957347491693508757253443864758446032047524096020585354104983606736759639044367167134409576092528219013168507381959241052976704837620234061351712684500077849808223040972825725745511581504906610633548112115513604053190610668096089811015493012026572475283305559529666099836493252485826156659750294903"),
		tt.B10("164941338210872461448879529698900150056451305424623398039343691654768566536491493438826728710972441042226712374570117138883019423322602098706113298908005378303473844839971995715847918643285222217768344335264383514921181158565529236124115589719970140511822410990649549555047928093673140752570788415674868532299"),
		tt.B10("277037199251333188171108034082127252450960810846571117481542098050121457972964006392527344163695411986229107011168411232117984760439307440561490229321182283823299859836750264962218540927582605520434969388646847458788766216835350519741512353041653865564337457599778511921159510170311560556844284028160928114623"),
		tt.B10("194450633495795999995837828580097111229016136925345956148788562473415774074431957758705067019578300241653926511426134047652491974620284426575921711048247821582093564387999309993254763749991516361193554847964638949731507356038181346481870018202492098453036116472375750355687853028597643560794156133662678349939"),
		tt.B10("351287943170075259292767465687447861777186026969543801283411356809391771346213158326614410370157474105344692424346410925411240089238093158848815209147605381454294661108047095253146499393310219242924552687094316959878415907497273176683394122976929775532753961555304244867490393116346360677109958055297215711587"),
		tt.B10("329970582937843908299463472795994928703202360293919677760100619380642134736439176597341134222679061949935544692834943628667398294307004076774417457697130314341974849843695836050603685013468031012892094273233016929045028941716224648802422408386216033754532303003405690778077639489173685122357063674177077611499"),
		tt.B10("67751546105580063387575764356375682499165422473383503143930633584920975946879807021875353514236996076344028719391905234977223693643926924731304657199486141030504275775023186923364159168130612275534168246529309247449138607249407760246378829338068736888203134857601657561860157938495777271164458736576560502603"),
		tt.B10("276043923868350639738966705196129285523536747369492013710841410915407411458158268634302674024358477700030814139419613881758439643092328709376796555454484423864587139181985503560495790018232370315219082876142282958894264284344738294415199758590186234114829175455336589153989920707778566032047921277945163061363"),
		tt.B10("62028909880050184794454820320289487394141550306616974968340908736543032782344593292214952852576535830823991093496498970213686040280098908204236051130358424961175634703281821899530101130244725435470475135483879784963475148975313832483400747421265545413510460046067002322131902159892876739088034507063542087523"),
		tt.B10("321804071508183671133831207712462079740282619152225438240259877528712344129467977098976100894625335474509551113902455258582802291330071887726188174124352664849954838358973904505681968878957681630941310372231688127901147200937955329324769631743029415035218057960201863908173045670622969475867077447909836936523"),
		tt.B10("52495647838749571441531580865340679598533348873590977282663145916368795913408897399822291638579504238082829052094508345857857144973446573810004060341650816108578548997792700057865473467391946766537119012441105169305106247003867011741811274367120479722991749924616247396514197345075177297436299446651331187067"),
		tt.B10("118753381771703394804894143450628876988609300829627946826004421079000316402854210786451078221445575185505001470635997217855372731401976507648597119694813440063429052266569380936671291883364036649087788968029662592370202444662489071262833666489940296758935970249316300642591963940296755031586580445184253416139"),
	}
	dummyVerifier = func(pubKey *curves.EcPoint, hash []byte, signature *curves.EcdsaSignature) bool {
		return false
	}
	ecdsaVerifier = func(verKey *curves.EcPoint, hash []byte, sig *curves.EcdsaSignature) bool {
		pk := &ecdsa.PublicKey{
			Curve: verKey.Curve,
			X:     verKey.X,
			Y:     verKey.Y,
		}
		return ecdsa.Verify(pk, hash, sig.R, sig.S)
	}
	k256Verifier = func(pubKey *curves.EcPoint, hash []byte, sig *curves.EcdsaSignature) bool {
		btcPk := &btcec.PublicKey{
			Curve: btcec.S256(),
			X:     pubKey.X,
			Y:     pubKey.Y,
		}
		btcSig := btcec.Signature{
			R: sig.R,
			S: sig.S,
		}
		return btcSig.Verify(hash, btcPk)
	}
)

func genPrimesArray(count int) []struct{ p, q *big.Int } {
	primesArray := make([]struct{ p, q *big.Int }, 0, count)
	for len(primesArray) < count {
		for i := 0; i < len(testPrimes) && len(primesArray) < count; i++ {
			for j := 0; j < len(testPrimes) && len(primesArray) < count; j++ {
				if i == j {
					continue
				}
				keyPrime := struct {
					p, q *big.Int
				}{
					testPrimes[i], testPrimes[j],
				}
				primesArray = append(primesArray, keyPrime)
			}
		}
	}
	return primesArray
}

// Creates a set of signers that are usable for testing
func setupSignersMap(t *testing.T, curve elliptic.Curve, playerThreshold, playerCnt int,
	addRound1 bool, verify curves.EcdsaVerify, useDistributed bool) (*curves.EcPoint, map[uint32]*Signer) {

	if playerThreshold > playerCnt {
		t.Errorf("threshold cannot be larger than count")
		t.FailNow()
	}

	pk, sharesMap, err := dealer.NewDealerShares(curve, uint32(playerThreshold), uint32(playerCnt), nil)
	tt.AssertNoError(t, err)

	// TODO: After the map refactor, we should be able to delete arbitrary signers,
	// however, for now, the signers' identifiers need to be predictable in array form
	// Remove non-signers from the shares map
	for len(sharesMap) > playerThreshold {
		delete(sharesMap, uint32(len(sharesMap)))
	}

	// Create public shares
	pubSharesMap, err := dealer.PreparePublicShares(sharesMap)
	tt.AssertNoError(t, err)

	// Create player paillier pubkeys
	playerKeysMap := make(map[uint32]*paillier.SecretKey, playerThreshold)
	pubkeys := make(map[uint32]*paillier.PublicKey, playerThreshold)

	primesCnt := playerThreshold
	var proofParams dealer.KeyGenType
	if useDistributed {
		primesCnt *= 2
	}

	primesArray := genPrimesArray(primesCnt)
	distributedProofParams := make(map[uint32]*dealer.ProofParams, playerCnt)
	for i := range sharesMap {
		playerKeysMap[i], err = paillier.NewSecretKey(primesArray[i-1].p, primesArray[i-1].q)
		tt.AssertNoError(t, err)
		pubkeys[i] = &playerKeysMap[i].PublicKey
		if useDistributed {
			pp := primesArray[int(i)+playerThreshold-1]
			params, _ := dealer.NewProofParamsWithPrimes(pp.p, pp.q)
			distributedProofParams[i] = params
		}
	}

	if useDistributed {
		proofParams = &dealer.DistributedKeyGenType{
			ProofParams: distributedProofParams,
		}
	} else {
		proofParams = &dealer.TrustedDealerKeyGenType{
			ProofParams: dealerParams,
		}
	}

	// Create participants and signers
	signersMap := make(map[uint32]*Signer, playerThreshold)
	for i := range playerKeysMap {
		p := Participant{*sharesMap[i], playerKeysMap[i]}
		signersMap[i], err = p.PrepareToSign(pk, verify, curve, proofParams, pubSharesMap, pubkeys)
		tt.AssertNoError(t, err)

		signersMap[i].threshold = uint(playerThreshold)

		// Add the round 1 values if requested
		if addRound1 {
			signersMap[i].state = &state{
				keyGenType: proofParams,
			}
		}
	}

	return pk, signersMap
}

func TestSignerSignRound1Works(t *testing.T) {
	curve := btcec.S256()
	playerCnt := 5
	playerMin := 3
	for _, useDistributed := range []bool{false, true} {
		_, signers := setupSignersMap(t, curve, playerMin, playerCnt, false, dummyVerifier, useDistributed)

		// Sign Round 1 with each player
		for _, signer := range signers {
			signerIOut, p2p, err := signer.SignRound1()
			require.NoError(t, err)

			if signer.state.keyGenType == nil {
				t.Errorf("dealerParams is nil")
			}
			if signer.Curve == nil {
				t.Errorf("curve is nil")
			}
			if signer.state.Gammai == nil {
				t.Errorf("Gammai is nil")
			}
			if signer.state.Di == nil {
				t.Errorf("Di is nil")
			}
			if signer.Round != 2 {
				t.Errorf("Expected round to be 2, found: %d", signer.Round)
			}
			require.NotNil(t, signer.state.ki)
			require.NotNil(t, signer.state.gammai)
			require.NotNil(t, signer.state.ci)
			require.NotNil(t, signer.state.ri)

			if signerIOut.Proof != nil {
				err = signerIOut.Proof.Verify(&proof.Proof1Params{
					Curve:        curve,
					Pk:           &signer.sk.PublicKey,
					DealerParams: dealerParams,
					C:            signerIOut.Ctxt,
				})
				require.NoError(t, err)
			} else {
				for id, pf := range p2p {
					err = pf.Verify(&proof.Proof1Params{
						Curve:        curve,
						Pk:           &signer.sk.PublicKey,
						DealerParams: signer.state.keyGenType.GetProofParams(id),
						C:            signerIOut.Ctxt,
					})
					require.NoError(t, err)
				}
			}
		}
	}
}

func TestSignerSignRound1RepeatCall(t *testing.T) {
	curve := btcec.S256()
	playerCnt := 5
	playerMin := 3
	_, signers := setupSignersMap(t, curve, playerMin, playerCnt, false, dummyVerifier, false)
	_, _, err := signers[1].SignRound1()
	tt.AssertNoError(t, err)
	_, _, err = signers[1].SignRound1()
	tt.AssertSomeError(t, err)
}

func TestSignerSignRound2Works(t *testing.T) {
	var err error
	curve := btcec.S256()
	playerCnt := 5
	playerMin := 3
	for _, useDistributed := range []bool{false, true} {
		_, signers := setupSignersMap(t, curve, playerMin, playerCnt, false, dummyVerifier, useDistributed)

		// Run round 1 with all signers
		signerOut := make(map[uint32]*Round1Bcast, playerMin)
		p2pOut := make(map[uint32]map[uint32]*Round1P2PSend, playerMin)
		for i, s := range signers {
			signerOut[i], p2pOut[i], err = s.SignRound1()
			tt.AssertNoError(t, err)
		}

		// run signing round 2 with player index 0
		signer := signers[1]
		require.NoError(t, err)
		otherSigners := make(map[uint32]*Round1Bcast)
		otherSigners[2] = signerOut[2]
		otherSigners[3] = signerOut[3]
		otherP2p := make(map[uint32]*Round1P2PSend)
		otherP2p[2] = p2pOut[2][1]
		otherP2p[3] = p2pOut[3][1]
		p2pi, err := signer.SignRound2(otherSigners, otherP2p)
		require.NoError(t, err)

		// Verify the outputs
		if len(p2pi) != 2 {
			t.Errorf("expected %d proofs, found %d", 2, len(p2pi))
		}
		if signer.Round != 3 {
			t.Errorf("signer round should be 3, found: %d", signer.Round)
		}
		if len(signer.state.betaj) != 2 {
			t.Errorf("state.betaj should have 2, found: %d", len(signer.state.betaj))
		}
		if len(signer.state.vuj) != 2 {
			t.Errorf("state.vuj should have 2, found: %d", len(signer.state.vuj))
		}
		if len(signer.state.cj) != 2 {
			t.Errorf("state.cj should have 2, found: %d", len(signer.state.cj))
		}
		if len(signer.state.Cj) != 2 {
			t.Errorf("state.Cj should have 2, found: %d", len(signer.state.Cj))
		}

		// Check that the return values can be finalized without error
		_, err = p2pi[2].Proof2.Finalize(&proof.ResponseVerifyParams{
			Curve:        curve,
			DealerParams: signer.state.keyGenType.GetProofParams(2),
			Sk:           signers[2].sk,
			C1:           signers[2].state.ci,
		})
		require.NoError(t, err)

		_, err = p2pi[3].Proof2.Finalize(&proof.ResponseVerifyParams{
			Curve:        curve,
			DealerParams: signer.state.keyGenType.GetProofParams(3),
			Sk:           signers[3].sk,
			C1:           signers[3].state.ci,
		})
		require.NoError(t, err)

		_, err = p2pi[2].Proof3.FinalizeWc(&proof.ResponseVerifyParams{
			Curve:        curve,
			DealerParams: signer.state.keyGenType.GetProofParams(2),
			Sk:           signers[2].sk,
			C1:           signers[2].state.ci,
			// pubkey of the proof creator which in this case is signer = signers[0]
			B: signer.publicSharesMap[1].Point,
		})
		require.NoError(t, err)

		_, err = p2pi[3].Proof3.FinalizeWc(&proof.ResponseVerifyParams{
			Curve:        curve,
			DealerParams: signer.state.keyGenType.GetProofParams(3),
			Sk:           signers[3].sk,
			C1:           signers[3].state.ci,
			B:            signer.publicSharesMap[1].Point,
		})
		require.NoError(t, err)
	}
}

func TestSignerSignRound2RepeatCall(t *testing.T) {
	curve := btcec.S256()
	playerCnt := 5
	playerMin := 3
	for _, useDistributed := range []bool{false, true} {
		_, signers := setupSignersMap(t, curve, playerMin, playerCnt, false, dummyVerifier, useDistributed)
		_, _, err := signers[1].SignRound1()
		tt.AssertNoError(t, err)
		out1, p2p1, err := signers[2].SignRound1()
		tt.AssertNoError(t, err)
		out2, p2p2, err := signers[3].SignRound1()
		tt.AssertNoError(t, err)

		tt.AssertNoError(t, err)
		otherSigners := make(map[uint32]*Round1Bcast)
		otherP2PSend := make(map[uint32]*Round1P2PSend)
		otherSigners[2] = out1
		otherSigners[3] = out2
		otherP2PSend[2] = p2p1[1]
		otherP2PSend[3] = p2p2[1]

		_, err = signers[1].SignRound2(otherSigners, otherP2PSend)
		tt.AssertNoError(t, err)
		_, err = signers[1].SignRound2(otherSigners, otherP2PSend)
		assert.Error(t, err)
	}
}

// Mocks for response proof
type responseProofMock struct {
	finalizeResult, finalizeWcResult *big.Int
}

// Have the compiler ensure we're meeting our interface requirements
var _ proof.ResponseFinalizer = (*responseProofMock)(nil)

func (m *responseProofMock) Finalize(vp *proof.ResponseVerifyParams) (*big.Int, error) {
	return m.finalizeResult, nil
}

func (m *responseProofMock) FinalizeWc(vp *proof.ResponseVerifyParams) (*big.Int, error) {
	return m.finalizeWcResult, nil
}

func TestSignRound3(t *testing.T) {
	for _, useDistributed := range []bool{false, true} {
		// Reasonably valid setup for testing round 3
		_, signers := setupSignersMap(t, btcec.S256(), 3, 5, true, dummyVerifier, useDistributed)

		for _, s := range signers {
			// Set variables that are expected to be present at the end of round 2
			s.state.ki = core.One
			s.state.gammai = core.One
			s.state.betaj = make(map[uint32]*big.Int)
			s.state.vuj = make(map[uint32]*big.Int)
			p2p := make(map[uint32]*P2PSend)
			th13een := big.NewInt(13)
			for j := range signers {
				s.state.betaj[j] = core.One
				s.state.vuj[j] = core.One
				p2p[j] = &P2PSend{&responseProofMock{th13een, th13een},
					&responseProofMock{th13een, th13een},
				}
			}

			// Test that invalid signing rounds states are rejected
			invalid := []uint{0, 1, 2, 5}
			for _, round := range invalid {
				t.Run("invalid signing round states are rejected", func(t *testing.T) {
					s.Round = round
					_, err := s.SignRound3(p2p)
					tt.AssertSomeError(t, err)
				})
			}

			// Sign
			s.Round = 3
			err := s.setCosigners([]uint32{1, 2, 3})
			tt.AssertNoError(t, err)

			// signing round 3 completes without error
			bcast, err := s.SignRound3(p2p)
			if err != nil {
				t.Errorf("unexpected failure: %v", err)
				t.FailNow()
			}

			t.Run("state vars are set", func(t *testing.T) {
				tt.AssertNotNil(t, s.state.deltai)
				tt.AssertNotNil(t, s.state.sigmai)
			})

			t.Run("return value matches state", func(t *testing.T) {
				tt.AssertBigIntEq(t, bcast.deltaElement, s.state.deltai)
			})

			t.Run("round variable is updated", func(t *testing.T) {
				if s.Round != 4 {
					t.Errorf("round variable != 4")
				}
			})

			t.Run("round variable is updated", func(t *testing.T) {
				if s.Round != 4 {
					t.Errorf("round variable != 4")
				}
			})
		}
	}
}

func TestSignRound4(t *testing.T) {
	// Reasonably valid setup for testing round 4
	_, signers := setupSignersMap(t, btcec.S256(), 3, 5, true, dummyVerifier, false)

	for _, s := range signers {
		// Set variables that are expected to be present at the end of round 3
		ones := make(map[uint32]*Round3Bcast, 2)
		s.state.cosigners = make(map[uint32]bool, 2)
		for j := range signers {
			if s.id == j {
				continue
			}
			ones[j] = &Round3Bcast{core.One}
			s.state.cosigners[j] = true
		}
		s.state.ki = core.One
		s.state.gammai = core.One
		s.state.deltai = core.One
		s.state.sigmai = core.One
		s.state.Di = &core.Witness{}

		// Test that invalid signing rounds states are rejected
		invalid := []uint{0, 1, 2, 3, 5, 6}
		for _, round := range invalid {
			t.Run("invalid signing round states are rejected", func(t *testing.T) {
				s.Round = round
				_, err := s.SignRound4(ones)
				tt.AssertSomeError(t, err)
			})
		}

		// Sign
		s.Round = 4
		bcast, err := s.SignRound4(ones)

		// signing round 4 completes without error
		if err != nil {
			t.Errorf("unexpected failure: %v", err)
			t.FailNow()
		}
		if bcast == nil {
			t.Errorf("bcast should not be nil")
		}

		t.Run("state vars are set", func(t *testing.T) {
			tt.AssertNotNil(t, s.state.delta)
		})
	}
}

func TestSignerSignRound5Works(t *testing.T) {
	var err error
	curve := btcec.S256()
	playerCnt := 5
	playerMin := 3
	for _, useDistributed := range []bool{false, true} {
		_, signers := setupSignersMap(t, curve, playerMin, playerCnt, false, dummyVerifier, useDistributed)

		// Sign Round 1
		round2In := make(map[uint32]*Round1Bcast, playerCnt)
		r1p2p := make(map[uint32]map[uint32]*Round1P2PSend, playerCnt)
		for id, s := range signers {
			round2In[id], r1p2p[id], err = s.SignRound1()
			if !assert.NoError(t, err) {
				t.FailNow()
			}
		}

		// Sign Round 2
		err = signers[1].setCosigners([]uint32{1, 2, 3})
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		p2p := make(map[uint32]map[uint32]*P2PSend)
		if useDistributed {
			_, err = signers[1].SignRound2(round2In, nil)
			// check for required P2P round1 params
			require.Error(t, err)
			p2pR2In := make(map[uint32]*Round1P2PSend, playerMin)
			_, err = signers[1].SignRound2(round2In, p2pR2In)
			require.Error(t, err)

			p2pR2In[2] = r1p2p[2][1]
			p2pR2In[3] = r1p2p[3][1]
			p2p[1], err = signers[1].SignRound2(round2In, p2pR2In)
		} else {
			p2p[1], err = signers[1].SignRound2(round2In, nil)
		}

		if !assert.NoError(t, err) {
			t.FailNow()
		}

		err = signers[2].setCosigners([]uint32{1, 2, 3})
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if useDistributed {
			_, err = signers[2].SignRound2(round2In, nil)
			// check for required P2P round1 params
			require.Error(t, err)
			p2pR2In := make(map[uint32]*Round1P2PSend, playerMin)
			_, err = signers[2].SignRound2(round2In, p2pR2In)
			require.Error(t, err)

			p2pR2In[1] = r1p2p[1][2]
			p2pR2In[3] = r1p2p[3][2]
			p2p[2], err = signers[2].SignRound2(round2In, p2pR2In)
		} else {
			p2p[2], err = signers[2].SignRound2(round2In, nil)
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		err = signers[3].setCosigners([]uint32{1, 2, 3})
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		if useDistributed {
			_, err = signers[3].SignRound2(round2In, nil)
			// check for required P2P round1 params
			require.Error(t, err)
			p2pR2In := make(map[uint32]*Round1P2PSend, playerMin)
			_, err = signers[3].SignRound2(round2In, p2pR2In)
			require.Error(t, err)

			p2pR2In[1] = r1p2p[1][3]
			p2pR2In[2] = r1p2p[2][3]
			p2p[3], err = signers[3].SignRound2(round2In, p2pR2In)
		} else {
			p2p[3], err = signers[3].SignRound2(round2In, nil)
		}
		require.NoError(t, err)

		// Sign Round 3
		round3Bcast := make(map[uint32]*Round3Bcast, playerMin)
		round3Bcast[1], err = signers[1].SignRound3(map[uint32]*P2PSend{2: p2p[2][1], 3: p2p[3][1]})
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		round3Bcast[2], err = signers[2].SignRound3(map[uint32]*P2PSend{1: p2p[1][2], 3: p2p[3][2]})
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		round3Bcast[3], err = signers[3].SignRound3(map[uint32]*P2PSend{1: p2p[1][3], 2: p2p[2][3]})
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		// Sign Round 4
		round4Bcast := make(map[uint32]*Round4Bcast, playerMin)
		round4Bcast[1], err = signers[1].SignRound4(round3Bcast)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		round4Bcast[2], err = signers[2].SignRound4(round3Bcast)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		round4Bcast[3], err = signers[3].SignRound4(round3Bcast)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		// Sign Round 5
		round5Bcast := make(map[uint32]*Round5Bcast, playerMin)
		round5P2P := make(map[uint32]map[uint32]*Round5P2PSend, playerMin)
		round5Bcast[1], round5P2P[1], err = signers[1].SignRound5(round4Bcast)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		if signers[1].state.Rbari == nil {
			t.Errorf("Expected Rbari to be set but is nil")
		}
		if signers[1].state.r == nil {
			t.Errorf("Expected Rbari to be set but is nil")
		}
		if signers[1].state.R == nil {
			t.Errorf("Expected R to be set")
		}
		if signers[1].state.r.Cmp(signers[1].state.R.X) != 0 {
			t.Errorf("Expected r == Rx")
		}

		round5Bcast[2], round5P2P[2], err = signers[2].SignRound5(round4Bcast)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		round5Bcast[3], round5P2P[3], err = signers[3].SignRound5(round4Bcast)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		if useDistributed {
			require.True(t, len(round5P2P[1]) == 2)
			require.True(t, len(round5P2P[2]) == 2)
			require.True(t, len(round5P2P[3]) == 2)
		}
	}
}

func TestSignerSignRound6WorksK256(t *testing.T) {
	curve := btcec.S256()
	msg := make([]byte, 32)
	hash, err := core.Hash(msg, curve)
	tt.AssertNoError(t, err)
	fullroundstest3Signers(t, curve, hash.Bytes(), k256Verifier)
}

func TestSignerSignRound6WorksP256(t *testing.T) {
	curve := elliptic.P256()
	msg := make([]byte, 32)
	hash, err := core.Hash(msg, curve)
	assert.NoError(t, err)
	fullroundstest3Signers(t, curve, hash.Bytes(), ecdsaVerifier)
}

func fullroundstest3Signers(t *testing.T, curve elliptic.Curve, msg []byte, verify curves.EcdsaVerify) {
	var err error
	playerCnt := 5
	playerMin := 3
	for _, useDistributed := range []bool{false, true} {
		pk, signers := setupSignersMap(t, curve, playerMin, playerCnt, false, verify, useDistributed)

		sk := signers[1].share.Value.Add(signers[2].share.Value).Add(signers[3].share.Value)
		_, ppk := btcec.PrivKeyFromBytes(curve, sk.Bytes())

		if ppk.X.Cmp(pk.X) != 0 || ppk.Y.Cmp(pk.Y) != 0 {
			t.Errorf("Invalid shares")
			t.FailNow()
		}

		// Sign Round 1
		signerOut := make(map[uint32]*Round1Bcast, playerCnt)
		r1P2P := make(map[uint32]map[uint32]*Round1P2PSend, playerCnt)
		for i, s := range signers {
			signerOut[i], r1P2P[i], err = s.SignRound1()
			require.NoError(t, err)
		}
		// Sign Round 2

		err = signers[1].setCosigners([]uint32{2, 3})
		require.NoError(t, err)
		p2p := make(map[uint32]map[uint32]*P2PSend)
		var r1P2pIn map[uint32]*Round1P2PSend
		if useDistributed {
			r1P2pIn = make(map[uint32]*Round1P2PSend, 3)
			r1P2pIn[2] = r1P2P[2][1]
			r1P2pIn[3] = r1P2P[3][1]
		}
		p2p[1], err = signers[1].SignRound2(map[uint32]*Round1Bcast{
			2: signerOut[2],
			3: signerOut[3],
		}, r1P2pIn)
		require.NoError(t, err)

		err = signers[2].setCosigners([]uint32{1, 3})
		require.NoError(t, err)
		if useDistributed {
			r1P2pIn = make(map[uint32]*Round1P2PSend, 3)
			r1P2pIn[1] = r1P2P[1][2]
			r1P2pIn[3] = r1P2P[3][2]
		}
		p2p[2], err = signers[2].SignRound2(map[uint32]*Round1Bcast{
			1: signerOut[1],
			3: signerOut[3],
		}, r1P2pIn)
		require.NoError(t, err)

		err = signers[3].setCosigners([]uint32{1, 2})
		require.NoError(t, err)
		if useDistributed {
			r1P2pIn = make(map[uint32]*Round1P2PSend, 3)
			r1P2pIn[1] = r1P2P[1][3]
			r1P2pIn[2] = r1P2P[2][3]
		}
		p2p[3], err = signers[3].SignRound2(map[uint32]*Round1Bcast{
			1: signerOut[1],
			2: signerOut[2],
		}, r1P2pIn)
		require.NoError(t, err)

		// Sign Round 3
		round3Bcast := make(map[uint32]*Round3Bcast, playerMin)
		round3Bcast[1], err = signers[1].SignRound3(map[uint32]*P2PSend{2: p2p[2][1], 3: p2p[3][1]})
		require.NoError(t, err)

		round3Bcast[2], err = signers[2].SignRound3(map[uint32]*P2PSend{1: p2p[1][2], 3: p2p[3][2]})
		require.NoError(t, err)

		round3Bcast[3], err = signers[3].SignRound3(map[uint32]*P2PSend{1: p2p[1][3], 2: p2p[2][3]})
		require.NoError(t, err)

		// Sign Round 4
		round4Bcast := make(map[uint32]*Round4Bcast, playerMin)
		round4Bcast[1], err = signers[1].SignRound4(map[uint32]*Round3Bcast{2: round3Bcast[2], 3: round3Bcast[3]})
		require.NoError(t, err)

		round4Bcast[2], err = signers[2].SignRound4(map[uint32]*Round3Bcast{1: round3Bcast[1], 3: round3Bcast[3]})
		require.NoError(t, err)

		round4Bcast[3], err = signers[3].SignRound4(map[uint32]*Round3Bcast{1: round3Bcast[1], 2: round3Bcast[2]})
		require.NoError(t, err)

		// Sign Round 5
		round5Bcast := make(map[uint32]*Round5Bcast, playerMin)
		r5P2p := make(map[uint32]map[uint32]*Round5P2PSend, playerMin)
		round5Bcast[1], r5P2p[1], err = signers[1].SignRound5(map[uint32]*Round4Bcast{2: round4Bcast[2], 3: round4Bcast[3]})
		require.NoError(t, err)

		round5Bcast[2], r5P2p[2], err = signers[2].SignRound5(map[uint32]*Round4Bcast{1: round4Bcast[1], 3: round4Bcast[3]})
		require.NoError(t, err)

		round5Bcast[3], r5P2p[3], err = signers[3].SignRound5(map[uint32]*Round4Bcast{1: round4Bcast[1], 2: round4Bcast[2]})
		require.NoError(t, err)

		Rbark, err := signers[1].state.Rbark.Add(signers[2].state.Rbark)
		require.NoError(t, err)

		Rbark, err = Rbark.Add(signers[3].state.Rbark)
		require.NoError(t, err)

		Rbark.Y, err = core.Neg(Rbark.Y, curve.Params().P)
		require.NoError(t, err)
		Rbark, err = Rbark.Add(pk)
		require.NoError(t, err)

		if !Rbark.IsIdentity() {
			t.Errorf("%v != %v", Rbark.X, pk.X)
			t.FailNow()
		}

		// Sign Round 6
		var r6P2pin map[uint32]*Round5P2PSend
		if useDistributed {
			// Check failure cases, first with nil input
			// then with missing participant data
			_, err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)
			require.Error(t, err)

			r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)
			_, err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)

			require.Error(t, err)

			r6P2pin[2] = r5P2p[2][1]
			_, err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)
			require.Error(t, err)

			r6P2pin[3] = r5P2p[3][1]
		}
		round6FullBcast := make([]*Round6FullBcast, playerMin)
		round6FullBcast[0], err = signers[1].SignRound6Full(msg, map[uint32]*Round5Bcast{2: round5Bcast[2], 3: round5Bcast[3]}, r6P2pin)
		assert.Nil(t, err)
		if useDistributed {
			r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)
			r6P2pin[1] = r5P2p[1][2]
			r6P2pin[3] = r5P2p[3][2]
		}
		round6FullBcast[1], err = signers[2].SignRound6Full(msg, map[uint32]*Round5Bcast{1: round5Bcast[1], 3: round5Bcast[3]}, r6P2pin)
		assert.Nil(t, err)
		if useDistributed {
			r6P2pin = make(map[uint32]*Round5P2PSend, playerMin)
			r6P2pin[1] = r5P2p[1][3]
			r6P2pin[2] = r5P2p[2][3]
		}
		round6FullBcast[2], err = signers[3].SignRound6Full(msg, map[uint32]*Round5Bcast{1: round5Bcast[1], 2: round5Bcast[2]}, r6P2pin)
		assert.Nil(t, err)
		tt.AssertNoError(t, err)

		sigs := make([]*curves.EcdsaSignature, 3)
		sigs[0], err = signers[1].SignOutput(map[uint32]*Round6FullBcast{
			2: round6FullBcast[1],
			3: round6FullBcast[2],
		})
		tt.AssertNoError(t, err)

		sigs[1], err = signers[2].SignOutput(map[uint32]*Round6FullBcast{
			1: round6FullBcast[0],
			3: round6FullBcast[2],
		})
		tt.AssertNoError(t, err)
		sigs[2], err = signers[3].SignOutput(map[uint32]*Round6FullBcast{
			1: round6FullBcast[0],
			2: round6FullBcast[1],
		})
		tt.AssertNoError(t, err)
	}
}

// Ensures that marshal-unmarshal Round1Bcast is the identity function
func TestMarshalRound1BcastRoundTrip(t *testing.T) {
	expected := Round1Bcast{
		Identifier: 1337,
		C:          []byte("Your name's Lebowski, Lebowski."),
		Ctxt:       tt.B10("1979"),
		Proof:      &proof.Range1Proof{},
	}

	// Marshal and test
	jsonBytes, err := json.Marshal(expected)
	assert.NoError(t, err)
	assert.NotNil(t, jsonBytes)

	// Unmarshal and test
	var actual Round1Bcast
	err = json.Unmarshal(jsonBytes, &actual)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}

// Ensures that marshal-unmarshal Round3Bcast is the identity function
func TestMarshalRound3BcastRoundTrip(t *testing.T) {
	expected := Round3Bcast{
		deltaElement: tt.B10("22963319250927626464432314334264998185524558636490611781390004531598870711554"),
	}
	// Marshal and test
	jsonBytes, err := json.Marshal(expected)
	assert.NoError(t, err)
	assert.NotNil(t, jsonBytes)

	// Unmarshal and test
	var actual Round3Bcast
	err = json.Unmarshal(jsonBytes, &actual)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

// Ensures that marshal-unmarshal Round4Bcast is the identity function
func TestMarshalRound4BcastRoundTrip(t *testing.T) {
	// This is the same test as TestWitnessMarshalRoundTrip
	expected := Round4Bcast{
		Witness: &core.Witness{
			Msg: []byte("test"),
		},
	}
	// Marhal and test
	jsonBytes, err := json.Marshal(expected)
	assert.NoError(t, err)
	assert.NotNil(t, jsonBytes)

	// Unmarshal and test
	var actual Round4Bcast
	assert.NoError(t, json.Unmarshal(jsonBytes, &actual))
	assert.Equal(t, expected, actual)
}

// Ensures that marshal-unmarshal Round5Bcast is the identity function
func TestMarshalRound5BcastRoundTrip(t *testing.T) {
	expected := Round5Bcast{
		Rbar: &curves.EcPoint{
			Curve: btcec.S256(),
			X:     tt.B10("22963319250927626464432314334264998185524558636490611781390004531598870711554"),
			Y:     tt.B10("5554841823708042459730720811862682529836762867109252962559124452631448728441"),
		},
		Proof: &proof.PdlProof{},
	}

	// Marshal and test
	jsonBytes, err := json.Marshal(expected)
	assert.NoError(t, err)
	assert.NotNil(t, jsonBytes)

	// Unmarshal and test
	var actual Round5Bcast
	err = json.Unmarshal(jsonBytes, &actual)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}

// Ensures that marshal-unmarshal Round3Bcast is the identity function
func TestMarshalRound6FullBcast(t *testing.T) {
	expected := Round6FullBcast{
		sElement: tt.B10("22963319250927626464432314334264998185524558636490611781390004531598870711554"),
	}
	// Marshal and test
	jsonBytes, err := json.Marshal(expected)
	assert.NoError(t, err)
	assert.NotNil(t, jsonBytes)

	// Unmarshal and test
	var actual Round6FullBcast
	err = json.Unmarshal(jsonBytes, &actual)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}
