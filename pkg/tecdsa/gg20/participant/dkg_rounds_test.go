//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"crypto/elliptic"
	"github.com/coinbase/kryptology/pkg/core/curves"
	"github.com/coinbase/kryptology/pkg/sharing/v1"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	tt "github.com/coinbase/kryptology/internal"
	"github.com/coinbase/kryptology/pkg/core"
	"github.com/coinbase/kryptology/pkg/paillier"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/dealer"
	"github.com/coinbase/kryptology/pkg/tecdsa/gg20/proof"
	"github.com/stretchr/testify/require"
)

func setupDkgRound3ParticipantMap(curve elliptic.Curve, t, n int) map[uint32]*DkgParticipant {
	feldman, _ := v1.NewFeldman(uint32(t), uint32(n), curve)
	participants := make(map[uint32]*DkgParticipant, n)
	prime1Idx := 0
	pIds := make(map[uint32]*dkgParticipantData, n)
	for j := 1; j <= n; j++ {
		pIds[uint32(j)] = &dkgParticipantData{}
	}

	for i := 0; i < n; i++ {
		u, _ := core.Rand(curve.Params().N)
		v, x, _ := feldman.Split(u.Bytes())
		sk, _ := paillier.NewSecretKey(testPrimes[prime1Idx], testPrimes[prime1Idx+1])
		id := uint32(i + 1)
		pIds[id].PublicKey = &sk.PublicKey
		pIds[id].ProofParams = &dealer.ProofParams{}
		participants[id] = &DkgParticipant{
			Curve: curve,
			id:    id,
			Round: 3,
			state: &dkgstate{
				Sk:                   sk,
				Pk:                   &sk.PublicKey,
				Threshold:            uint32(t),
				Limit:                uint32(n),
				X:                    x,
				V:                    v,
				otherParticipantData: pIds,
			},
		}
		prime1Idx++
	}

	return participants
}

func setupDkgRound3Commitments(t *testing.T, participants map[uint32]*DkgParticipant, playerCnt int) map[uint32]*core.Witness {
	var err error
	// Setup commitments for each player so they can be passed as inputs
	// normally received from echo broadcast
	commitments := make(map[uint32]core.Commitment, playerCnt)
	decommitments := make(map[uint32]*core.Witness, playerCnt)
	for id, p := range participants {
		commitments[id], decommitments[id], err = commitVerifiers(participants[id].state.V)
		p.state.otherParticipantData[id].Commitment = commitments[id]
		require.NoError(t, err)
	}

	return decommitments
}

func commitVerifiers(v []*v1.ShareVerifier) (core.Commitment, *core.Witness, error) {
	var bytes []byte
	for _, vi := range v {
		bytes = append(bytes, vi.Bytes()...)
	}
	return core.Commit(bytes)
}

func TestDkgRound3Works(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	// Actual test
	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.NoError(t, err)
	require.NotNil(t, res1)
	res2, err := participants[2].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[1],
		2: participants[2].state.X[1],
		3: participants[3].state.X[1],
	})
	require.NoError(t, err)
	require.NotNil(t, res2)
	res3, err := participants[3].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[2],
		2: participants[2].state.X[2],
		3: participants[3].state.X[2],
	})
	require.NoError(t, err)
	require.NotNil(t, res3)
	field := curves.NewField(curve.Params().N)
	shamir, _ := v1.NewShamir(playerMin, playerCnt, field)

	// Check that they all generated the same public key
	require.Equal(t, participants[1].state.Y, participants[2].state.Y)
	require.Equal(t, participants[1].state.Y, participants[3].state.Y)

	// Check that they all generated the same public shares
	for i, e := range participants[1].state.PublicShares {
		require.Equal(t, e, participants[2].state.PublicShares[i])
		require.Equal(t, e, participants[3].state.PublicShares[i])
	}
	share1 := v1.NewShamirShare(1, participants[1].state.Xi.Bytes(), field)
	share2 := v1.NewShamirShare(2, participants[2].state.Xi.Bytes(), field)
	share3 := v1.NewShamirShare(3, participants[3].state.Xi.Bytes(), field)
	secret12, err := shamir.Combine(share1, share2)
	require.NoError(t, err)
	secret13, err := shamir.Combine(share1, share3)
	require.NoError(t, err)
	secret23, err := shamir.Combine(share2, share3)
	require.NoError(t, err)

	require.Equal(t, secret12, secret13)
	require.Equal(t, secret12, secret23)
	pk, err := curves.NewScalarBaseMult(curve, new(big.Int).SetBytes(secret12))
	require.NoError(t, err)
	require.True(t, participants[1].state.Y.Equals(pk))
}

func TestDkgRound3RepeatCall(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	// Actual test
	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.NoError(t, err)
	require.NotNil(t, res1)
	res2, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.Error(t, err)
	require.Nil(t, res2)
}

func TestDkgRound3InvalidWitnesses(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	decommitments[2].Msg[0] ^= decommitments[1].Msg[0]
	decommitments[2].Msg[1] ^= decommitments[1].Msg[1]

	// Actual test
	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.Error(t, err)
	require.Nil(t, res1)

	// corrupt 2nd participant
	decommitments[2].Msg[0] ^= decommitments[1].Msg[0]
	decommitments[2].Msg[1] ^= decommitments[1].Msg[1]

	// corrupt 3rd participant
	decommitments[3].Msg[0] ^= decommitments[1].Msg[0]
	decommitments[3].Msg[1] ^= decommitments[1].Msg[1]
	res2, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.Error(t, err)
	require.Nil(t, res2)
}

func TestDkgRound3InvalidShares(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	// corrupt 2nd participant share
	temp := participants[2].state.X[0].Value
	participants[2].state.X[0].Value = curves.NewField(curve.Params().N).NewElement(big.NewInt(1))

	// Actual test
	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.Error(t, err)
	require.Nil(t, res1)

	// restore 2nd participant share
	participants[2].state.X[0].Value = temp

	// corrupt 3rd participant share
	participants[3].state.X[0].Value = curves.NewField(curve.Params().N).NewElement(big.NewInt(1))

	res2, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.Error(t, err)
	require.Nil(t, res2)
}

func TestDkgRound1Works(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	curve := btcec.S256()
	total := 3
	threshold := 2

	// Initiate a DKG participant
	dkgParticipant := &DkgParticipant{
		Curve: curve,
		id:    uint32(1),
		Round: 1,
		state: &dkgstate{
			Threshold: uint32(threshold),
			Limit:     uint32(total),
		},
	}

	// Run DKG round 1
	dkgParticipantOut, err := dkgParticipant.DkgRound1(uint32(threshold), uint32(total))
	tt.AssertNoError(t, err)

	// Checking DkgParticipant's items and stored values
	if dkgParticipant.Curve == nil {
		t.Errorf("dkgParticipant curve is nil")
	}

	if dkgParticipant.id == 0 {
		t.Errorf("dkgParticipant id is zero")
	}

	if dkgParticipant.Round != 2 {
		t.Errorf("Expected round to be 2, found: %d", dkgParticipant.Round)
	}

	if dkgParticipant.state.D == nil {
		t.Errorf("dkgstate D is nil")
	}

	if dkgParticipant.state.Sk == nil {
		t.Errorf("dkgstate Sk is nil")
	}

	if dkgParticipant.state.Pk == nil {
		t.Errorf("dkgstate Pk is nil")
	}

	tt.AssertNotNil(t, dkgParticipant.state.N)
	tt.AssertNotNil(t, dkgParticipant.state.H1)
	tt.AssertNotNil(t, dkgParticipant.state.H2)

	if dkgParticipant.state.V == nil {
		t.Errorf("dkgstate V is nil")
	}

	if dkgParticipant.state.X == nil {
		t.Errorf("dkgstate X is nil")
	}

	if dkgParticipant.state.Threshold != uint32(threshold) {
		t.Errorf("dkgstate Threshold mismatch")
	}

	if dkgParticipant.state.Limit != uint32(total) {
		t.Errorf("dkgstate Limit mismatch")
	}

	// Check DKG Round 1 output
	if dkgParticipantOut.Ci == nil {
		t.Errorf("DkgRound1Bcast Ci is nil")
	}

	if dkgParticipantOut.Pki == nil {
		t.Errorf("DkgRound1Bcast Pki is nil")
	}

	tt.AssertNotNil(t, dkgParticipantOut.H1i)
	tt.AssertNotNil(t, dkgParticipantOut.H2i)
	tt.AssertNotNil(t, dkgParticipantOut.Ni)

	if dkgParticipantOut.Proof1i == nil {
		t.Errorf("DkgRound1Bcast Proof1i is nil")
	}

	if dkgParticipantOut.Proof2i == nil {
		t.Errorf("DkgRound1Bcast Proof2i is nil")
	}
}

// Test repeat call for DKG Round 1. There should be some error after repeat call
func TestDkgRound1RepeatCall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	curve := btcec.S256()
	total := 3
	threshold := 2
	dkgParticipant := &DkgParticipant{
		Curve: curve,
		id:    uint32(1),
		Round: 1,
		state: &dkgstate{
			Threshold: uint32(threshold),
			Limit:     uint32(total),
		},
	}

	// Test repeat call
	_, err := dkgParticipant.DkgRound1(uint32(threshold), uint32(total))
	tt.AssertNoError(t, err)
	_, err = dkgParticipant.DkgRound1(uint32(threshold), uint32(total))
	tt.AssertSomeError(t, err)
}

/*
Tests for DKG Round 2
*/
// Setup DKG Round2 parameters for 3 parties.
func setupDkgRound2Params(curve elliptic.Curve, threshold, total int) (map[uint32]*DkgParticipant, map[uint32]*DkgRound1Bcast) {
	dkgParticipants := make(map[uint32]*DkgParticipant, total)
	dpOutputs := make(map[uint32]*DkgRound1Bcast, total)
	feldman, _ := v1.NewFeldman(uint32(threshold), uint32(total), curve)

	// Setup parameters for player 1
	u1, _ := core.Rand(curve.Params().N)
	v1, x1, _ := feldman.Split(u1.Bytes())
	c1, d1, _ := commitVerifiers(v1)
	sk1, _ := paillier.NewSecretKey(testPrimes[0], testPrimes[1])
	pk1 := &sk1.PublicKey
	p1 := tt.B10("82762378445241041785597416507146490924447650731139897784752935952615188889635739493260515391609009395512012510709694417682987650969620502923818755809286104031313081465573622419369705445472375093283434921189190872945878407680529264737835792880592698668922695556861850401038676208972765968600517704143107930939")
	q1 := tt.B10("69984280963080064677800727110502274842099368563604158420066520063922637818395160287343267480348823052616167329961701614168083898925612364204117254926526013551734867336492773207372540967720859662663438793769658958121285041708356176137310878638419197674131049677486047662703715583824220317748400146581518805651")
	N1 := tt.B10("23168262185138042086985251479966140367473901735462054883904158802899264898691745453544888260128845593494180271821344835446388187526575974414101963091834292189789300379762157838980851815082897653013412610189597921830744654589452349113217726909094907934886602336832701591827947839296008075387481044145203853001040451482685799793720746884491540403980953810998121611944634910546812395244563473672734584566589265151370354163653553724356278901340380622401163641562474726319566531912584399552348312976911765268861745938301120268844120841005241592287730934409073936996169212424570979999552686559812737873042697608781537218337")
	alpha1 := tt.B10("15700848461280380865453593955761108710562895414247363097072882828466191790916811503316377080013948938072225007516727823198461336870478274783583845926904074063193546765645477855455273258274150739378394943431150849983293677107578668862239783392036575043145101427760350638472037576829352497038388585737650687025976060296433989815102965583016771823595419876353838074154404831501616992756987140969613192813913996292033706748510041393036246923312030419247298071079496294307995794672335020365605673661246459738777446284403765226964816958599530935710152502359977024900546418123107827630153113273622448646563626731524890158451")
	beta1 := tt.B10("4445879341351807551209439241920588140685341448529417529966129370975387582547328611790463864985523049818186588579898273930075299257729508047763338871424268681977630441148158141892066821441561729492103026410192844346284104817705886190143212900488394256716287705027856018936240395625790280151981634907904864178490159409363504387136507125542627454380016748558057005637225625481246654258853972871702501872856487903999341616690584954898272433078686327089310861915148328259913401109993699884551105056353404107220173983671620298275738982057963556561810371192793230372490607557673240894790572775163623912821853064509864539001")
	h11 := tt.B10("20655589105424284731130950222365942513635708110950343104368669683186013800106942421524347648458254016225036450934479227664921498785561364595133998161005944291950359490505065673829287124165328608814740981967547208784457369473849019618903667437471918601627601044509671230680260942658093024204790610273965477549218656620684879208070965028279550643411998341767974100272557335380738716438934690826564692745348318822199802416149976761047532756651975957242217027025407351894263261364922859598069540698965816588058759437732436981028926328047363612699976563290609364678354605271871488415744707392237965701195336114850923722797")
	h12 := tt.B10("5496074424480326456967307779978137640059660693996954490061656724729243248263235164326034392211487428145642035897732902987019830534770657265806433471056048721413319683923174766405888321053057575584689236687181096491031182941541387466426725040271572300593534197768598345205731705003156108961982545733171941969970689906713317136842479008121330098952126720386613744001301998221850208337277017663694634040173073680721828995733047624361263114536685654886828447330526802851522697283703748194422611303519895796695954647757152041586980035268266906531329254312878479944233983358807551831572963272582468808462893198641903856921")

	dkgParticipants[1] = &DkgParticipant{
		Curve: curve,
		state: &dkgstate{
			D:         d1,
			Sk:        sk1,
			Pk:        pk1,
			N:         N1,
			H1:        h11,
			H2:        h12,
			V:         v1,
			X:         x1,
			Threshold: uint32(threshold),
			Limit:     uint32(total),
		},
		id:    uint32(1),
		Round: 2,
	}

	cdlParams11 := proof.CdlProofParams{
		Curve:   curve,
		Pi:      p1,
		Qi:      q1,
		H1:      h11,
		H2:      h12,
		ScalarX: alpha1,
		N:       N1,
	}

	cdlParams12 := proof.CdlProofParams{
		Curve:   curve,
		Pi:      p1,
		Qi:      q1,
		H1:      h12,
		H2:      h11,
		ScalarX: beta1,
		N:       N1,
	}

	proof11, _ := cdlParams11.Prove()
	proof12, _ := cdlParams12.Prove()

	dpOutputs[1] = &DkgRound1Bcast{
		Identifier: uint32(1),
		Ci:         c1,
		Pki:        pk1,
		H1i:        h11,
		H2i:        h12,
		Ni:         N1,
		Proof1i:    proof11,
		Proof2i:    proof12,
	}

	// Setup parameters for player 2
	u2, _ := core.Rand(curve.Params().N)
	v2, x2, _ := feldman.Split(u2.Bytes())
	c2, d2, _ := commitVerifiers(v2)
	sk2, _ := paillier.NewSecretKey(testPrimes[1], testPrimes[2])
	pk2 := &sk1.PublicKey
	p2 := tt.B10("80835583194913519255227175491027534116323858942133804957873380964125769952153722872767395985807182088879137751973737195611736535673308039044731251312798604370125595953965575058201727000947562582634872106737658889028847062612351664088766417932577222262750095599375976992110180518474405571076375447630197402683")
	q2 := tt.B10("69210064501097857725048553909160987839131798505582280831015356795143548214286337962509303315200340351978784326318311835136991907096681964505529171491850250428938993794552587102107113717157628550696163063380650545271668730646004879534943159254419759086140189236571989463830596906364636114340509119890275606391")
	N2 := tt.B10("22378543707615306836182422597086174059399103708656614542204375941627776221585838908498318709084953151230965854544463050621828248405138252834708522307450445556723033074493621883193914559018381068514705602518576848505473239373873163089017151419401575132561803936035907582328999663685768377599926812681660506565947765011705274480316011005378618472210395471633060565141691029027315925435485138015621760349367644867362058194502904616776430082646477391555516713467661564007827039040130177584810996845324575709856975050152799234612346180661626644267859546152830340382918108278013986195106643466879089206972260629605087406361")
	alpha2 := tt.B10("8747809298656078157114989950041580286626590365412031159633038987400223139122802354043389770093812959933384823884800254545895685397561553107528285733907902692147578830663267889623620419654128177892824386197392899719125115336150424159662997613720657468185455852362111552218248733267188584474338310030535392696941542304627485792649727961749526294440265425869039626150858630065641704957845214905134230348454532342863016686973803114811617354792880686738003360654735024192014095577237597827622102153977484388829956549425633334294348127208872226835724222353398872450805386968650925346794454105303144753420375228918197233593")
	beta2 := tt.B10("2176139841560966477022156779585373977084793770032865716611721076366510042072757393725554689134042997574346080091862079219885406368886527384471502222447681728053956990594598338683296079141837969515744306817198519923794261948389920085503550175806501862554903010097757202296695916608707138517580767801026927471661226104627834436167025248795975530399204624851613982839790026616531533724496017750091049160213747834420322575228605441197854900387941711504209396818854405944049291123654264161208369287697015498157320659403403958742767733621289282236149735088305802788340120427685904560051631430226452469729196005350071038518")
	h21 := tt.B10("20764671747204185805546844344412835044481927072125473833045065236747774267349721315389519959224111151333812652954644659437452036737962436105131388300631676148138552826539738766476333351400257979985612117861193564814347204651099040729052610123152900373393988655139065773685343172546701895310185998055572542743050440648428933844288312054936095897180901779311613028652390789016218147769551951586322205607557428325588069148780794645970025270442590369880171353631398974136157137932221009218128183651414251492625811774178862987122067289458907794177679420398930552955065418080976552272653430571577633578476287756522428963268")
	h22 := tt.B10("2991008902201630200117440742333338885856080655411619980514782500763526876709985991258228481606315867770547971678709881862150747984560670352917493320985965538437116820977692577161175862284036913093370195901175312261015557101569791088996256635738918121630482035458153294890744961588474194182996060717185759857085915200708530029348920315889833519026946814499142812753189562082593905483951134885775180934941075664930676658614552989873075474332334764420169918779728208107142868874929816807285246855695166118730354329507679528778713169223069037702719361468552001788414665308334859311395962549949565511540980897385271371982")

	dkgParticipants[2] = &DkgParticipant{
		Curve: curve,
		state: &dkgstate{
			D:         d2,
			Sk:        sk2,
			Pk:        pk2,
			N:         N2,
			H1:        h21,
			H2:        h22,
			V:         v2,
			X:         x2,
			Threshold: uint32(threshold),
			Limit:     uint32(total),
		},
		id:    uint32(2),
		Round: 2,
	}

	cdlParams21 := proof.CdlProofParams{
		Curve:   curve,
		Pi:      p2,
		Qi:      q2,
		H1:      h21,
		H2:      h22,
		ScalarX: alpha2,
		N:       N2,
	}

	cdlParams22 := proof.CdlProofParams{
		Curve:   curve,
		Pi:      p2,
		Qi:      q2,
		H1:      h22,
		H2:      h21,
		ScalarX: beta2,
		N:       N2,
	}

	proof21, _ := cdlParams21.Prove()
	proof22, _ := cdlParams22.Prove()

	dpOutputs[2] = &DkgRound1Bcast{
		Identifier: uint32(2),
		Ci:         c2,
		Pki:        pk2,
		H1i:        h21,
		H2i:        h22,
		Ni:         N2,
		Proof1i:    proof21,
		Proof2i:    proof22,
	}

	// Setup parameters for player 3
	u3, _ := core.Rand(curve.Params().N)
	v3, x3, _ := feldman.Split(u3.Bytes())
	c3, d3, _ := commitVerifiers(v3)
	sk3, _ := paillier.NewSecretKey(testPrimes[2], testPrimes[3])
	pk3 := &sk1.PublicKey
	p3 := tt.B10("82762378445241041785597416507146490924447650731139897784752935952615188889635739493260515391609009395512012510709694417682987650969620502923818755809286104031313081465573622419369705445472375093283434921189190872945878407680529264737835792880592698668922695556861850401038676208972765968600517704143107930939")
	q3 := tt.B10("69984280963080064677800727110502274842099368563604158420066520063922637818395160287343267480348823052616167329961701614168083898925612364204117254926526013551734867336492773207372540967720859662663438793769658958121285041708356176137310878638419197674131049677486047662703715583824220317748400146581518805651")
	N3 := tt.B10("23168262185138042086985251479966140367473901735462054883904158802899264898691745453544888260128845593494180271821344835446388187526575974414101963091834292189789300379762157838980851815082897653013412610189597921830744654589452349113217726909094907934886602336832701591827947839296008075387481044145203853001040451482685799793720746884491540403980953810998121611944634910546812395244563473672734584566589265151370354163653553724356278901340380622401163641562474726319566531912584399552348312976911765268861745938301120268844120841005241592287730934409073936996169212424570979999552686559812737873042697608781537218337")
	alpha3 := tt.B10("15700848461280380865453593955761108710562895414247363097072882828466191790916811503316377080013948938072225007516727823198461336870478274783583845926904074063193546765645477855455273258274150739378394943431150849983293677107578668862239783392036575043145101427760350638472037576829352497038388585737650687025976060296433989815102965583016771823595419876353838074154404831501616992756987140969613192813913996292033706748510041393036246923312030419247298071079496294307995794672335020365605673661246459738777446284403765226964816958599530935710152502359977024900546418123107827630153113273622448646563626731524890158451")
	beta3 := tt.B10("4445879341351807551209439241920588140685341448529417529966129370975387582547328611790463864985523049818186588579898273930075299257729508047763338871424268681977630441148158141892066821441561729492103026410192844346284104817705886190143212900488394256716287705027856018936240395625790280151981634907904864178490159409363504387136507125542627454380016748558057005637225625481246654258853972871702501872856487903999341616690584954898272433078686327089310861915148328259913401109993699884551105056353404107220173983671620298275738982057963556561810371192793230372490607557673240894790572775163623912821853064509864539001")
	h31 := tt.B10("20655589105424284731130950222365942513635708110950343104368669683186013800106942421524347648458254016225036450934479227664921498785561364595133998161005944291950359490505065673829287124165328608814740981967547208784457369473849019618903667437471918601627601044509671230680260942658093024204790610273965477549218656620684879208070965028279550643411998341767974100272557335380738716438934690826564692745348318822199802416149976761047532756651975957242217027025407351894263261364922859598069540698965816588058759437732436981028926328047363612699976563290609364678354605271871488415744707392237965701195336114850923722797")
	h32 := tt.B10("5496074424480326456967307779978137640059660693996954490061656724729243248263235164326034392211487428145642035897732902987019830534770657265806433471056048721413319683923174766405888321053057575584689236687181096491031182941541387466426725040271572300593534197768598345205731705003156108961982545733171941969970689906713317136842479008121330098952126720386613744001301998221850208337277017663694634040173073680721828995733047624361263114536685654886828447330526802851522697283703748194422611303519895796695954647757152041586980035268266906531329254312878479944233983358807551831572963272582468808462893198641903856921")

	dkgParticipants[3] = &DkgParticipant{
		Curve: curve,
		state: &dkgstate{
			D:         d3,
			Sk:        sk3,
			Pk:        pk3,
			N:         N3,
			H1:        h31,
			H2:        h32,
			V:         v3,
			X:         x3,
			Threshold: uint32(threshold),
			Limit:     uint32(total),
		},
		id:    uint32(3),
		Round: 2,
	}

	cdlParams31 := proof.CdlProofParams{
		Curve:   curve,
		Pi:      p3,
		Qi:      q3,
		H1:      h31,
		H2:      h32,
		ScalarX: alpha3,
		N:       N3,
	}

	cdlParams32 := proof.CdlProofParams{
		Curve:   curve,
		Pi:      p3,
		Qi:      q3,
		H1:      h32,
		H2:      h31,
		ScalarX: beta3,
		N:       N3,
	}

	proof31, _ := cdlParams31.Prove()
	proof32, _ := cdlParams32.Prove()

	dpOutputs[3] = &DkgRound1Bcast{
		Identifier: uint32(3),
		Ci:         c3,
		Pki:        pk3,
		H1i:        h31,
		H2i:        h32,
		Ni:         N3,
		Proof1i:    proof31,
		Proof2i:    proof32,
	}

	return dkgParticipants, dpOutputs
}

func TestDkgRound2Works(t *testing.T) {
	curve := btcec.S256()
	total := 3
	threshold := 2
	dkgParticipants, dpOutputs := setupDkgRound2Params(curve, threshold, total)

	// Test
	participant := dkgParticipants[1]
	bcast, p2psend, err := participant.DkgRound2(dpOutputs)
	require.NoError(t, err)

	// Verify the outputs
	// Check echo broadcast
	if bcast == nil {
		t.Errorf("DkgRound2Bcast cannot be nil")
	}

	// Check P2P send
	if p2psend == nil {
		t.Errorf("DkgRound2P2PSend cannot be nil")
	}

	if len(p2psend) != 2 {
		t.Errorf("DkgRound2P2PSend should have length 2, found: %d", len(p2psend))
	}

	// Check participant
	if participant.Round != 3 {
		t.Errorf("dkg round should be 3, found: %d", participant.Round)
	}
}

// Test when the broadcast of Round 1 is tampered
func TestDkgRound2Tampered(t *testing.T) {
	curve := btcec.S256()
	total := 3
	threshold := 2
	dkgParticipants, dpOutputs := setupDkgRound2Params(curve, threshold, total)

	participant := dkgParticipants[1]

	// Tampering player 2 on Ni
	dpOutputs[2].Ni.Add(dpOutputs[2].Ni, core.One)
	_, _, err := participant.DkgRound2(dpOutputs)
	tt.AssertSomeError(t, err)

	// Restore player 2
	dpOutputs[2].Ni.Sub(dpOutputs[2].Ni, core.One)
	participant.Round = 2

	// Tamper player 3 on Ni
	dpOutputs[3].Ni.Add(dpOutputs[3].Ni, core.One)
	_, _, err = participant.DkgRound2(dpOutputs)
	tt.AssertSomeError(t, err)

	// Restore player 3
	dpOutputs[3].Ni.Sub(dpOutputs[3].Ni, core.One)
	participant.Round = 2

	// Tamper player 2 on h1
	dpOutputs[2].H1i.Add(dpOutputs[2].H1i, core.One)
	_, _, err = participant.DkgRound2(dpOutputs)
	tt.AssertSomeError(t, err)
}

// Test repeat call of DKG round 2
func TestDkgRound2RepeatCall(t *testing.T) {
	curve := btcec.S256()
	total := 3
	threshold := 2
	dkgParticipants, dpOutputs := setupDkgRound2Params(curve, threshold, total)

	participant := dkgParticipants[1]

	// Actual test
	bcast, p2psend, err := participant.DkgRound2(dpOutputs)
	require.NoError(t, err)
	require.NotNil(t, bcast)
	require.NotNil(t, p2psend)

	// Repeat
	bcast, p2psend, err = participant.DkgRound2(dpOutputs)
	require.Error(t, err)
	require.Nil(t, bcast)
	require.Nil(t, p2psend)
}

// Test the case when the number of received broadcast messages is not enough
func TestDkgRound2NotEnoughParties(t *testing.T) {
	curve := btcec.S256()
	total := 3
	threshold := 2
	dkgParticipants, dpOutputs := setupDkgRound2Params(curve, threshold, total)

	participant := dkgParticipants[1]

	// Remove player 2's broadcast
	dpOutputs[2] = nil

	// Actual test
	bcast, p2psend, err := participant.DkgRound2(dpOutputs)
	require.Error(t, err)
	require.Nil(t, bcast)
	require.Nil(t, p2psend)
}

func TestDkgRound4Works(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.NoError(t, err)
	require.NotNil(t, res1)
	res2, err := participants[2].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[1],
		2: participants[2].state.X[1],
		3: participants[3].state.X[1],
	})
	require.NoError(t, err)
	require.NotNil(t, res2)
	res3, err := participants[3].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[2],
		2: participants[2].state.X[2],
		3: participants[3].state.X[2],
	})
	require.NoError(t, err)
	require.NotNil(t, res3)

	// Actual test
	out1, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{
		2: res2,
		3: res3,
	})
	require.NoError(t, err)
	require.NotNil(t, out1)
	out2, err := participants[2].DkgRound4(map[uint32]paillier.PsfProof{
		1: res1,
		3: res3,
	})
	require.NoError(t, err)
	require.NotNil(t, out2)
	out3, err := participants[3].DkgRound4(map[uint32]paillier.PsfProof{
		1: res1,
		2: res2,
	})
	require.NoError(t, err)
	require.NotNil(t, out3)

	// check that the shares result in valid secret key and public key
	field := curves.NewField(curve.Params().N)

	shamir, _ := v1.NewShamir(playerMin, playerCnt, field)
	share1 := v1.NewShamirShare(1, out1.SigningKeyShare.Bytes(), field)
	share2 := v1.NewShamirShare(2, out2.SigningKeyShare.Bytes(), field)
	share3 := v1.NewShamirShare(3, out3.SigningKeyShare.Bytes(), field)
	secret12, err := shamir.Combine(share1, share2)
	require.NoError(t, err)
	secret13, err := shamir.Combine(share1, share3)
	require.NoError(t, err)
	secret23, err := shamir.Combine(share2, share3)
	require.NoError(t, err)

	require.Equal(t, secret12, secret13)
	require.Equal(t, secret12, secret23)
	pk, err := curves.NewScalarBaseMult(curve, new(big.Int).SetBytes(secret12))
	require.NoError(t, err)
	require.True(t, participants[1].state.Y.Equals(pk))
}

func TestDkgRound4RepeatCall(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.NoError(t, err)
	require.NotNil(t, res1)
	res2, err := participants[2].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[1],
		2: participants[2].state.X[1],
		3: participants[3].state.X[1],
	})
	require.NoError(t, err)
	require.NotNil(t, res2)
	res3, err := participants[3].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[2],
		2: participants[2].state.X[2],
		3: participants[3].state.X[2],
	})
	require.NoError(t, err)
	require.NotNil(t, res3)

	// Actual test
	out1, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{
		2: res2,
		3: res3,
	})
	require.NoError(t, err)
	require.NotNil(t, out1)

	out2, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{
		2: res2,
		3: res3,
	})
	require.NoError(t, err)
	require.Equal(t, out1, out2)
}

func TestDkgRound4NotEnoughProofs(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.NoError(t, err)
	require.NotNil(t, res1)
	res2, err := participants[2].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[1],
		2: participants[2].state.X[1],
		3: participants[3].state.X[1],
	})
	require.NoError(t, err)
	require.NotNil(t, res2)
	res3, err := participants[3].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[2],
		2: participants[2].state.X[2],
		3: participants[3].state.X[2],
	})
	require.NoError(t, err)
	require.NotNil(t, res3)

	// Actual test
	out1, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{
		2: res2,
	})
	require.Error(t, err)
	require.Nil(t, out1)
	out2, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{
		3: res3,
	})
	require.Error(t, err)
	require.Nil(t, out2)
}

func TestDkgRound4NoProofs(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.NoError(t, err)
	require.NotNil(t, res1)

	// Actual test
	out1, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{})
	require.Error(t, err)
	require.Nil(t, out1)
}

func TestDkgRound4WrongProofs(t *testing.T) {
	// Setup
	curve := btcec.S256()
	playerCnt := 3
	playerMin := 2
	participants := setupDkgRound3ParticipantMap(curve, playerMin, playerCnt)
	decommitments := setupDkgRound3Commitments(t, participants, playerCnt)

	res1, err := participants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[0],
		2: participants[2].state.X[0],
		3: participants[3].state.X[0],
	})
	require.NoError(t, err)
	require.NotNil(t, res1)
	res2, err := participants[2].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[1],
		2: participants[2].state.X[1],
		3: participants[3].state.X[1],
	})
	require.NoError(t, err)
	require.NotNil(t, res2)
	res3, err := participants[3].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: participants[1].state.X[2],
		2: participants[2].state.X[2],
		3: participants[3].state.X[2],
	})
	require.NoError(t, err)
	require.NotNil(t, res3)

	// Actual test
	out1, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{
		2: res2,
		3: res1,
	})
	require.Error(t, err)
	require.Nil(t, out1)
	out2, err := participants[1].DkgRound4(map[uint32]paillier.PsfProof{
		2: res3,
		3: res3,
	})
	require.Error(t, err)
	require.Nil(t, out2)
}

func TestDkgFullRoundsWorks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	curve := btcec.S256()
	total := 3
	threshold := 2
	var err error

	// Initiate 3 parties for DKG
	dkgParticipants := make(map[uint32]*DkgParticipant, total)
	for i := 1; i <= total; i++ {
		dkgParticipants[uint32(i)] = &DkgParticipant{
			Curve: curve,
			id:    uint32(i),
			Round: 1,
			state: &dkgstate{
				Threshold: uint32(threshold),
				Limit:     uint32(total),
			},
		}
	}

	// Run Dkg Round 1
	dkgR1Out := make(map[uint32]*DkgRound1Bcast, total)
	for i := 1; i <= total; i++ {
		dkgR1Out[uint32(i)], err = dkgParticipants[uint32(i)].DkgRound1(uint32(threshold), uint32(total))
		require.NoError(t, err)
	}

	// Run Dkg Round 2
	dkgR2Bcast := make(map[uint32]*DkgRound2Bcast, total)
	dkgR2P2PSend := make(map[uint32]map[uint32]*DkgRound2P2PSend, total)
	for i := 1; i <= total; i++ {
		dkgR2Bcast[uint32(i)], dkgR2P2PSend[uint32(i)], err = dkgParticipants[uint32(i)].DkgRound2(dkgR1Out)
		require.NoError(t, err)
	}

	// Run Dkg Round 3
	decommitments := make(map[uint32]*core.Witness, total)
	dkgR3Out := make(map[uint32]paillier.PsfProof)
	decommitments[1] = dkgR2Bcast[1].Di
	decommitments[2] = dkgR2Bcast[2].Di
	decommitments[3] = dkgR2Bcast[3].Di

	dkgR3Out[1], err = dkgParticipants[1].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: dkgParticipants[1].state.X[0],
		2: dkgParticipants[2].state.X[0],
		3: dkgParticipants[3].state.X[0],
	})
	require.NoError(t, err)

	dkgR3Out[2], err = dkgParticipants[2].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: dkgParticipants[1].state.X[1],
		2: dkgParticipants[2].state.X[1],
		3: dkgParticipants[3].state.X[1],
	})
	require.NoError(t, err)

	dkgR3Out[3], err = dkgParticipants[3].DkgRound3(decommitments, map[uint32]*v1.ShamirShare{
		1: dkgParticipants[1].state.X[2],
		2: dkgParticipants[2].state.X[2],
		3: dkgParticipants[3].state.X[2],
	})
	require.NoError(t, err)

	// Run Dkg Round 4
	dkgR4Out := make(map[uint32]*DkgResult, total)
	for i := 1; i <= total; i++ {
		dkgR4Out[uint32(i)], err = dkgParticipants[uint32(i)].DkgRound4(dkgR3Out)
		require.NoError(t, err)
	}

	// Check that the shares result in valid secret key and public key
	field := curves.NewField(curve.Params().N)

	shamir, _ := v1.NewShamir(threshold, total, field)
	share1 := v1.NewShamirShare(1, dkgR4Out[1].SigningKeyShare.Bytes(), field)
	share2 := v1.NewShamirShare(2, dkgR4Out[2].SigningKeyShare.Bytes(), field)
	share3 := v1.NewShamirShare(3, dkgR4Out[3].SigningKeyShare.Bytes(), field)
	secret12, err := shamir.Combine(share1, share2)
	require.NoError(t, err)
	secret13, err := shamir.Combine(share1, share3)
	require.NoError(t, err)
	secret23, err := shamir.Combine(share2, share3)
	require.NoError(t, err)

	require.Equal(t, secret12, secret13)
	require.Equal(t, secret12, secret23)

	// Check the relationship of verification key and signing key is valid
	pk, err := curves.NewScalarBaseMult(curve, new(big.Int).SetBytes(secret12))
	require.NoError(t, err)
	require.True(t, dkgParticipants[1].state.Y.Equals(pk))

	// Check every participant has the same verification key
	require.Equal(t, dkgParticipants[1].state.Y, dkgParticipants[2].state.Y)
	require.Equal(t, dkgParticipants[1].state.Y, dkgParticipants[3].state.Y)

	// Testing validity of paillier public key and secret key
	// Check every participant receives equal paillier public keys from other parties
	require.Equal(t, dkgParticipants[1].state.otherParticipantData[2].PublicKey, dkgParticipants[3].state.otherParticipantData[2].PublicKey)
	require.Equal(t, dkgParticipants[1].state.otherParticipantData[3].PublicKey, dkgParticipants[2].state.otherParticipantData[3].PublicKey)
	require.Equal(t, dkgParticipants[2].state.otherParticipantData[1].PublicKey, dkgParticipants[3].state.otherParticipantData[1].PublicKey)

	// Testing validity of paillier keys of participant 1
	pk1 := dkgParticipants[2].state.otherParticipantData[1].PublicKey
	sk1 := dkgParticipants[1].state.Sk
	msg1, _ := core.Rand(pk1.N)
	c1, r1, err := pk1.Encrypt(msg1)
	require.NoError(t, err)
	require.NotNil(t, c1, r1)
	m1, err := sk1.Decrypt(c1)
	require.Equal(t, m1, msg1)
	require.NoError(t, err)

	// Testing validity of paillier keys of participant 2
	pk2 := dkgParticipants[1].state.otherParticipantData[2].PublicKey
	sk2 := dkgParticipants[2].state.Sk
	msg, _ := core.Rand(pk2.N)
	c, r, err := pk2.Encrypt(msg)
	require.NoError(t, err)
	require.NotNil(t, c, r)
	m, err := sk2.Decrypt(c)
	require.Equal(t, m, msg)
	require.NoError(t, err)

	// Testing validity of paillier keys of participant 3
	pk3 := dkgParticipants[1].state.otherParticipantData[3].PublicKey
	sk3 := dkgParticipants[3].state.Sk
	msg3, _ := core.Rand(pk3.N)
	c3, r3, err := pk3.Encrypt(msg3)
	require.NoError(t, err)
	require.NotNil(t, c3, r3)
	m3, err := sk3.Decrypt(c3)
	require.Equal(t, m3, msg3)
	require.NoError(t, err)

	// Checking public shares are equal
	require.Equal(t, dkgParticipants[1].state.PublicShares, dkgParticipants[2].state.PublicShares)
	require.Equal(t, dkgParticipants[1].state.PublicShares, dkgParticipants[3].state.PublicShares)

	// Checking proof params are equal
	require.Equal(t, dkgR4Out[1].ParticipantData[2].ProofParams, dkgR4Out[3].ParticipantData[2].ProofParams)
	require.Equal(t, dkgR4Out[1].ParticipantData[3].ProofParams, dkgR4Out[2].ParticipantData[3].ProofParams)
	require.Equal(t, dkgR4Out[2].ParticipantData[1].ProofParams, dkgR4Out[3].ParticipantData[1].ProofParams)
}
