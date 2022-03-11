//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package paillier

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	tt "github.com/coinbase/kryptology/internal"
	crypto "github.com/coinbase/kryptology/pkg/core"
)

var (
	x         = tt.B10("7146643783615963513942641287213372249533955323510461217840179896547799100626220786140425637990097431")
	y         = tt.B10("1747698065194620177681258504464368264357359841192790848951902311522815739310792522712583635858354245")
	N         = tt.B10("85832751158419329546684678412285185885848111422509523329716452068504806021136687603399722116388773253")
	NminusOne = new(big.Int).Sub(N, crypto.One)
	NplusOne  = new(big.Int).Add(N, crypto.One)
	hundoN    = new(big.Int).Mul(N, big.NewInt(100))

	NN         = new(big.Int).Mul(N, N)
	NNminusOne = new(big.Int).Sub(NN, crypto.One)
	NNplusOne  = new(big.Int).Add(NN, crypto.One)
)

func Example_encryptDecrypt() {
	// Skip this example if -short parameter is passed.
	if testing.Short() {
		// Printing the expected output so that the test succeeds.
		fmt.Println("Succeeded in encrypting and decrypting the input message: Hello World!")
		return
	}
	hexMessage := hex.EncodeToString([]byte("Hello World!"))
	mappedMessage, ok := new(big.Int).SetString(hexMessage, 16)
	if !ok {
		panic("Error mapping message to scalar point.")
	}
	pub, sec, err := NewKeys()
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	// Ignoring the random value that was generated internally by `Encrypt`.
	cipher, _, err := pub.Encrypt(mappedMessage)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	// Now decrypt using the secret key.
	decrypted, err := sec.Decrypt(cipher)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}

	decoded := string(decrypted.Bytes())
	fmt.Println("Succeeded in encrypting and decrypting the input message:", decoded)

	// Output:
	// Succeeded in encrypting and decrypting the input message: Hello World!
}

func Example_homomorphicAddition() {
	// Skip this example if -short parameter is passed.
	if testing.Short() {
		// Printing the expected output so that the test succeeds.
		fmt.Println("Encrypting 123 and 456 separately.")
		fmt.Println("Adding their encrypted versions together.")
		fmt.Println("Succeeded in decrypting 579")
		return
	}
	pub, sec, err := NewKeys()
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := tt.B10("123")
	msg2 := tt.B10("456")
	fmt.Printf("Encrypting %s and %s separately.\n", msg1, msg2)

	cipher1, _, err := pub.Encrypt(msg1)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}
	cipher2, _, err := pub.Encrypt(msg2)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	fmt.Println("Adding their encrypted versions together.")
	cipher3, err := pub.Add(cipher1, cipher2)
	if err != nil {
		log.Fatalf("Error in adding the two ciphertexts: %v", err)
	}
	decrypted3, err := sec.Decrypt(cipher3)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}
	fmt.Println("Succeeded in decrypting", decrypted3)

	// Output:
	// Encrypting 123 and 456 separately.
	// Adding their encrypted versions together.
	// Succeeded in decrypting 579
}

func Example_homomorphicMultiplication() {
	// Skip this example if -short parameter is passed.
	if testing.Short() {
		// Printing the expected output so that the test succeeds.
		fmt.Println("Encrypting 10.")
		fmt.Println("Multiplying plain 5 with the encrypted 10.")
		fmt.Println("Succeeded in decrypting 50.")
		return
	}
	pub, sec, err := NewKeys()
	if err != nil {
		log.Fatalf("Error in generating keypair: %v", err)
	}

	msg1 := tt.B10("10")
	msg2 := tt.B10("5")
	fmt.Printf("Encrypting %s.\n", msg1)

	cipher1, _, err := pub.Encrypt(msg1)
	if err != nil {
		log.Fatalf("Error in Encrypting the message: %v", err)
	}

	fmt.Printf("Multiplying plain %s with the encrypted %s.\n", msg2, msg1)
	cipher3, err := pub.Mul(msg2, cipher1)
	if err != nil {
		log.Fatalf("Error in adding the two ciphertexts: %v", err)
	}
	decrypted3, err := sec.Decrypt(cipher3)
	if err != nil {
		log.Fatalf("Error in Decrypting the ciphertext: %v", err)
	}
	fmt.Printf("Succeeded in decrypting %s.\n", decrypted3)

	// Output:
	// Encrypting 10.
	// Multiplying plain 5 with the encrypted 10.
	// Succeeded in decrypting 50.
}

func TestGenerateSafePrimes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TestGenerateSafePrimes")
	}
	p, err := crypto.GenerateSafePrime(32)
	if err != nil {
		t.Errorf("GenerateSafePrime failed: %v", err)
	}
	if !p.ProbablyPrime(8) {
		t.Errorf("GenerateSafePrime didn't return a prime number: %v", p)
	}
	p, err = crypto.GenerateSafePrime(3)
	if err != nil {
		t.Errorf("GenerateSafePrime failed: %v", err)
	}
	if !p.ProbablyPrime(8) {
		t.Errorf("GenerateSafePrime didn't return a prime number: %v", p)
	}
}

func TestGenerateSafePrimesLong(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TestGenerateSafePrimesLong")
	}
	p, err := crypto.GenerateSafePrime(1024)
	if err != nil {
		t.Errorf("GenerateSafePrime failed: %v", err)
	}
	if !p.ProbablyPrime(8) {
		t.Errorf("GenerateSafePrime didn't return a prime number: %v", p)
	}
	if p.BitLen() != 1024 {
		t.Errorf("GenerateSafePrime didn't return a prime number with the exact bits")
	}
}

func TestGenerateSafePrimesTooLow(t *testing.T) {
	_, err := crypto.GenerateSafePrime(2)
	require.Error(t, err)
}

type lcmTest struct {
	x        *big.Int
	y        *big.Int
	err      error
	expected *big.Int
}

func runTestLcm(t *testing.T, testArgs []lcmTest) {
	for _, arg := range testArgs {
		a, err := lcm(arg.x, arg.y)
		if err != nil && arg.err == nil {
			t.Errorf("lcm failed: %v", err)
		}
		if a == nil && arg.expected != nil || a.Cmp(arg.expected) != 0 {
			t.Errorf("lcm failed. Expected %v, found: %v", arg.expected, a)
		}
	}
}

func TestLcm(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        big.NewInt(4),
			y:        big.NewInt(6),
			err:      nil,
			expected: big.NewInt(12),
		},
		{
			x:        big.NewInt(10),
			y:        big.NewInt(22),
			err:      nil,
			expected: big.NewInt(110),
		},
		{
			x:        big.NewInt(1),
			y:        big.NewInt(3),
			err:      nil,
			expected: big.NewInt(3),
		},
		{
			x:        big.NewInt(5),
			y:        big.NewInt(7),
			err:      nil,
			expected: big.NewInt(35),
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmCommutative(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        big.NewInt(11),
			y:        big.NewInt(7),
			err:      nil,
			expected: big.NewInt(77),
		},
		{
			x:        big.NewInt(7),
			y:        big.NewInt(11),
			err:      nil,
			expected: big.NewInt(77),
		},
		{
			x:        big.NewInt(13),
			y:        big.NewInt(23),
			err:      nil,
			expected: big.NewInt(299),
		},
		{
			x:        big.NewInt(23),
			y:        big.NewInt(13),
			err:      nil,
			expected: big.NewInt(299),
		},
		{
			x:        big.NewInt(-23),
			y:        big.NewInt(17),
			err:      nil,
			expected: big.NewInt(391),
		},
		{
			x:        big.NewInt(23),
			y:        big.NewInt(-17),
			err:      nil,
			expected: big.NewInt(391),
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmNegNums(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        big.NewInt(-5),
			y:        big.NewInt(-7),
			err:      nil,
			expected: big.NewInt(35),
		},
		{
			x:        big.NewInt(-5),
			y:        big.NewInt(7),
			err:      nil,
			expected: big.NewInt(35),
		},
		{
			x:        big.NewInt(3),
			y:        big.NewInt(-11),
			err:      nil,
			expected: big.NewInt(33),
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmNil(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        nil,
			y:        big.NewInt(1),
			err:      errors.New("arguments cannot be nil"),
			expected: nil,
		},
		{
			x:        big.NewInt(1),
			y:        nil,
			err:      errors.New("arguments cannot be nil"),
			expected: nil,
		},
		{
			x:        nil,
			y:        nil,
			err:      errors.New("arguments cannot be nil"),
			expected: nil,
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmZero(t *testing.T) {
	testArgs := []lcmTest{
		{
			x:        big.NewInt(0),
			y:        big.NewInt(1),
			err:      nil,
			expected: big.NewInt(0),
		},
		{
			x:        big.NewInt(0),
			y:        big.NewInt(0),
			err:      nil,
			expected: big.NewInt(0),
		},
	}
	runTestLcm(t, testArgs)
}

func TestLcmBigPrimes(t *testing.T) {
	x := new(big.Int)
	y := new(big.Int)
	// Generated by OpenSSL
	x.SetString("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367", 10)
	y.SetString("121400263190232595456200749546561304956161672968687911935494950378721768184159069938532869288284686583150658925255722159156454219960265942696166947144912738151554579878178746701374346180640493532962639632666540478486867810588884360492830920363713588684509182704981665082591486786717530494254613085570321507623", 10)
	expected := new(big.Int)
	expected.SetString("16241940578082201531943448855852277578391761356628379864603641922876623601321625229339135653813019543205064366507109899018615521640687222340376734033815591736764469510811142260074144789284382858541066390183237904579674336717818949214144339382239132186500111594251680147962383065732964214151653795512167674648653475620307856642151695559944756719719799945193072239010815330021803557074201060705849949820706127488164694762724694756011467249889383401729777382247223470577114290663770295230883950621358271613200219512401437571399087878832070221157976750549142719310423012055140771277730139053532825828483343855582012877641", 10)

	x2 := new(big.Int)
	x2.SetString("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367", 10)

	x3 := new(big.Int)
	y3 := new(big.Int)
	x3.SetString("199624032515728289045241179631920514454939035695180729995055822158745789192452713406851424173447485774951354235728394322982696160719973464933778580097775959312681723073700577658531340015313241640799019163953248377211698591166024389845418771351325354733438115315318038016037617205770677410860231617155107859183", 10)
	y3.SetString("142249905617339142091532152811520246816977809135348639617427185924289265672711180486386239769195440660717504105473521478033326628103915862155595134226885191558983128407247227273401068113332266238311624168954823649558019882800072911119616964386221647824743035538953625688976296691147616508925455607033114354959", 10)
	expected2 := new(big.Int)
	expected2.SetString("28396499784314989096609919418127345447157066075586506422680304338142086939236798450800279134642308338458035596559017626154823247809313781525454242216477721507296693149109832139024597927259443182893280359146077724553052468871051438675286719817790943900280362711254811533504902741179161752948522341835287769530110541739921633871308290020066875307078092554117637608375242902999872137629980200197702760214658136789637368191031173973090138816890631056194895911511193868568337270184231814553242352572122713100022187023932306383784997785740075483768764231396924369937421906728046753885386778340930941242102624489916449738497", 10)
	testArgs := []lcmTest{
		{
			x, y, nil, expected,
		},
		{
			x:        x2,
			y:        big.NewInt(1),
			err:      nil,
			expected: x2,
		},
		{
			x:        x3,
			y:        y3,
			err:      nil,
			expected: expected2,
		},
	}
	runTestLcm(t, testArgs)
}

func TestLKnownCases(t *testing.T) {
	// test multiples of 5 for L
	pk, err := NewPubkey(big.NewInt(5))
	require.NoError(t, err)
	tests := []struct {
		in, expected *big.Int
	}{
		{big.NewInt(6), big.NewInt(1)},
		{big.NewInt(11), big.NewInt(2)},
		{big.NewInt(16), big.NewInt(3)},
		{big.NewInt(21), big.NewInt(4)},
	}

	for _, test := range tests {
		r, err := pk.l(test.in)
		require.NoError(t, err)
		require.Equal(t, r, test.expected)
	}
}

func TestLFailureCases(t *testing.T) {
	pk, err := NewPubkey(big.NewInt(5))
	require.NoError(t, err)
	tests := []*big.Int{
		pk.N,                // u = N should fail
		big.NewInt(25),      // u = NN should fail
		big.NewInt(51),      // u > NN should fail
		big.NewInt(9),       // u ≢ 1 (mod 5) should fail
		big.NewInt(12),      // u ≢ 1 (mod 5) should fail
		big.NewInt(22),      // u ≢ 1 (mod 5) should fail
		big.NewInt(-1),      // negative N should fail
		big.NewInt(-100000), // negative N should fail
		nil,                 // nil should fail
	}

	for _, test := range tests {
		_, err := pk.l(test)
		require.Error(t, err)
	}
}

type keygenTest struct {
	bits                        uint
	p, q, n, lambda, totient, u *big.Int
}

func TestKeyGen(t *testing.T) {
	testValues := []*keygenTest{
		// Small values
		{
			bits:    32,
			p:       tt.B10("4294967387"),
			q:       tt.B10("8589936203"),
			n:       tt.B10("36893495848295611561"),
			lambda:  tt.B10("18446747917705353986"),
			totient: tt.B10("36893495835410707972"),
			u:       tt.B10("30227647593197281524"),
		},
		{
			bits:    32,
			p:       tt.B10("2404778303"),
			q:       tt.B10("2907092159"),
			n:       tt.B10("6990912148784626177"),
			lambda:  tt.B10("3495456071736377858"),
			totient: tt.B10("6990912143472755716"),
			u:       tt.B10("3614931622846492468"),
		},
		// Moderate values
		{
			bits:    128,
			p:       tt.B10("505119856506205319276795183398241487263"),
			q:       tt.B10("205972782400928578615836152187141707579"),
			n:       tt.B10("104040942290540895974307747626520134740467527950099359068592315888198399066277"),
			lambda:  tt.B10("52020471145270447987153873813260067369878217655596112585349842276306507935718"),
			totient: tt.B10("104040942290540895974307747626520134739756435311192225170699684552613015871436"),
			u:       tt.B10("95814396947082822381619843641016289162443592153179788942685091512428172029465"),
		},
		{
			bits:    128,
			p:       tt.B10("335833617445150372903755348587631934583"),
			q:       tt.B10("275426149345634030797050866270209482803"),
			n:       tt.B10("92497360073732512809517386349687056338889420300408887876944500444198759476149"),
			lambda:  tt.B10("46248680036866256404758693174843528169139080266809051736621847114670459029382"),
			totient: tt.B10("92497360073732512809517386349687056338278160533618103473243694229340918058764"),
			u:       tt.B10("37541288371367874015853812738289992945377756025517882548300075720005348319216"),
		},
		{
			bits:    256,
			p:       tt.B10("115645895734860215235155088728394909334688633450524492586690742412129345961183"),
			q:       tt.B10("94298418052417649431120534110853375174108454456092458684756344618179781451887"),
			n:       tt.B10("10905225022052151768592443014939079805820716955892154646109970627753805040740378163517568530133182652794506558827042053659527293884287341299235199284102321"),
			totient: tt.B10("10905225022052151768592443014939079805820716955892154646109970627753805040740168219203781252268516377171667310542533256571620676933015894212204890156689252"),
			lambda:  tt.B10("5452612511026075884296221507469539902910358477946077323054985313876902520370084109601890626134258188585833655271266628285810338466507947106102445078344626"),
			u:       tt.B10("169122108559803116345465577435019987080055058605295565203286696962456365170552011215103788832323625338104327792007096903690940420144823974727816140829004"),
		},
		{
			bits:    384,
			p:       tt.B10("36006692832910486705531921197379033634897461505036495703751117530881437756504623602114452424392242359949564580091963"),
			q:       tt.B10("36321876854655342367765793082986061200135195654801162378979445503936881469720608843798409137541849432902150243071007"),
			n:       tt.B10("1307830663020375807860069772466605443871885822612939940958802361999351292929784401772312287232210036471265772358253561264090635848856642357599288411446282200143037556882504679979558002244844355483553171478292766242112114935599016741"),
			totient: tt.B10("1307830663020375807860069772466605443871885822612939940958802361999351292929784401772312287232210036471265772358253488935520948283027569059885008046351447167485877719224421949416523183925618130251107258616730832150319263220775853772"),
			lambda:  tt.B10("653915331510187903930034886233302721935942911306469970479401180999675646464892200886156143616105018235632886179126744467760474141513784529942504023175723583742938859612210974708261591962809065125553629308365416075159631610387926886"),
			u:       tt.B10("715317338270237792745674161133027331913306953524485480270742409164181533024685207574377116318911340995248759257081568534206599002649096879000033274962046481163095418392051555090184840289513260640923181142724977346034839256290483076"),
		},
		// Large values
		{
			bits:    512,
			p:       tt.B10("13334877681824046536664719753000692481615243060546695171749157112026072862294410162436291925578885141357927002155461724765584886877402066038258074266638227"),
			q:       tt.B10("12122745362522189816168535264551355768089283231069686330301128627041958196835868405970767150401427191976786435200511843851744213149595052566013030642866907"),
			n:       tt.B10("161655326577133109177725996877941503037044267143093183990772875721980297379977570900477874093780897364088511586139843445141992295002878403748750051858500001631307112890860155944955185080369964944108396477646372269079498823545159135772467319334869864305928043113234061678778620562861360302446649667820279453889"),
			totient: tt.B10("161655326577133109177725996877941503037044267143093183990772875721980297379977570900477874093780897364088511586139843445141992295002878403748750051858499976173684068544623803111700167528321715239582104861264870218793759755514100005493898912275793883993594708399796705705210003233761333305328045396715369948756"),
			lambda:  tt.B10("80827663288566554588862998438970751518522133571546591995386437860990148689988785450238937046890448682044255793069921722570996147501439201874375025929249988086842034272311901555850083764160857619791052430632435109396879877757050002746949456137896941996797354199898352852605001616880666652664022698357684974378"),
			u:       tt.B10("143261270242335180420072816055839865064298362037063587448317467367577401621254503191376775173811231300545030557865973916661565869494495913728327166081853904903334058396967815592631415604767903602152339275761555997082956433277741333963496039496540726125762611561934388357363014028934069272035911913194424272603"),
		},
		{
			bits:    768,
			p:       tt.B10("1346090925391135119143470623782502005582449208798686393499686094146720873293257316154858443761764176763426496081748327594475673914483978883075080616518148610864446133054517784818794038700373924492201179029136162262578223994386497407"),
			q:       tt.B10("1267888740317619255987103204389173685200460862251480292534873171503916906509928280188817985770625788023592223617980306560361856737457586891910981446078699966027435065022526191471061668427090194699255004927681350300606724099539148139"),
			n:       tt.B10("1706693527747144711594288434414073474898396319145231571914859473075446769444443882426378206783148798161228984036593560566511416432995440677335990047411064284625144780381208381275798262584775575885562112174608693614583699626181565327188316266582808161080083810509077419565819105286361318424233748287133200189491965280880943430756926385486914657888021988499576975592342792662208243895780558951878131107691067112167457219510292850345325644694079605526537816712375573"),
			totient: tt.B10("1706693527747144711594288434414073474898396319145231571914859473075446769444443882426378206783148798161228984036593560566511416432995440677335990047411064284625144780381208381275798262584775575885562112174608693614583699626181565324574336600874053785949509982337401728782909034236194632389674482636495420386306368937204513898366961598468194958159387833662046323650777017676146181298931982059996933030647090822311750092046173658889141687876567042341589722786730028"),
			lambda:  tt.B10("853346763873572355797144217207036737449198159572615785957429736537723384722221941213189103391574399080614492018296780283255708216497720338667995023705532142312572390190604190637899131292387787942781056087304346807291849813090782662287168300437026892974754991168700864391454517118097316194837241318247710193153184468602256949183480799234097479079693916831023161825388508838073090649465991029998466515323545411155875046023086829444570843938283521170794861393365014"),
			u:       tt.B10("779879106968621551612916279464123438735012661607976871766884426257741506106933684516528094230394847057111517560275304735511075756729605155799199673159820709716869729022492405360829062001458468008371167876032343417620981083465124988041616116692784740773729428828021798152577117895496702246006365934433098458747623402795759758566365836593488130254049427800131843438461226605279227891251815575333006410913379796415963477224332006612563517643916428864744112156376520"),
		},
		{
			bits:    1024,
			p:       tt.B10("323048346478810234804346724288317979049543453886657577003300101860710127877799870550562838407667268404599358826513829060160504303395418566677040422188661745067470888457815635033321184439746580337024906877384167362567610372271431186610013379997212856608697550064099211785613236213633622219571487990672693003787"),
			q:       tt.B10("289955956844872723713267618282085026937397801221604643862282902289352466511076698253093993268863225914839327563609168378629851975959785812001060859728689670901677697805606458924299545852498153652948060776824445669854015488773545309215892532182626763404124068861635361632889336491051975303142403383113070034867"),
			n:       tt.B10("93669792410417391755898616958812213604373878875285824927431988118477734285768665211145268050244414695456141707631724902135831803247956851156058161652431398586664582925077157366114568914615913189006980440640666538921106871639116459047133240204886962593927223154881396777466153081835208630039047664120224812531738646998208894219436266840478325951526823776791414200683451217351791095609379048292074062880637329062218371522375097661526583290635879391529194601725476785472157424230313351359992497803391595095260449578824637692631790170131436072668730121222036510650215208397389118631464109460927478825133780143983053041329"),
			lambda:  tt.B10("46834896205208695877949308479406106802186939437642912463715994059238867142884332605572634025122207347728070853815862451067915901623978425578029080826215699293332291462538578683057284457307956594503490220320333269460553435819558229523566620102443481296963611577440698388733076540917604315019523832060112406265562821347442605630459326248953961472769941260841575989908934106600864250610251239744208615602053417371389842566126050111368113505640337506425546659904062684751504418983445628701185883755573430552643740962308012330105082154543229788421412104521098445318696794735827272606480768378120940651209944385098645001338"),
			totient: tt.B10("93669792410417391755898616958812213604373878875285824927431988118477734285768665211145268050244414695456141707631724902135831803247956851156058161652431398586664582925077157366114568914615913189006980440640666538921106871639116459047133240204886962593927223154881396777466153081835208630039047664120224812531125642694885211260918652497907922945539882521683151979817868213201728501220502479488417231204106834742779685132252100222736227011280675012851093319808125369503008837966891257402371767511146861105287481924616024660210164309086459576842824209042196890637393589471654545212961536756241881302419888770197290002676"),
			u:       tt.B10("38135949745652485811937226692116929429180649272477224483199257365577156885532690396567815884583937557608568699362433418166707048319324785327166624071125908609604488150973723257324029836008236113484260165701873141666619439620722921574373345283540196413007597899672199365492304562415424130214337263020773327553873482407654450455061737687873828877767689823341811598685374044652873284145859288532695538432223451947587392094598520855737584462011917578978549967062842845942828735580257392245879142299251014137170130879720213249399499545177941592508341271051010776972469394170182828098805388982944454017008931873419560331115"),
		},
	}

	for _, test := range testValues {
		idx := 0
		safePrimes := []*big.Int{test.p, test.q}
		f := func(bits uint) (*big.Int, error) {
			r := safePrimes[idx]
			idx = (idx + 1) % 2
			return r, nil
		}

		pub, sec, err := keyGenerator(f, test.bits)
		require.NoError(t, err)
		require.Equal(t, pub.N, test.n)
		require.Equal(t, sec.Totient, test.totient)
		require.Equal(t, sec.Lambda, test.lambda)
		require.Equal(t, sec.U, test.u)
	}
}

func TestKeyGeneratorErrorConditions(t *testing.T) {
	// Should fail if a safe prime cannot be generated.
	f := func(bits uint) (*big.Int, error) {
		return nil, fmt.Errorf("safeprime error")
	}
	_, _, err := keyGenerator(f, 1)
	require.Contains(t, err.Error(), "safeprime error")

	// Should fail if a gcd of p and q is zero.
	val := int64(0)
	oneF := func(bits uint) (*big.Int, error) {
		b := big.NewInt(val)
		val += 1
		return b, nil
	}
	_, _, err = keyGenerator(oneF, 1)
	require.Contains(t, err.Error(), "N cannot be 0")
}

func TestKeyGenSameInput(t *testing.T) {
	p := tt.B10("4294967387")
	q := tt.B10("8589936203")
	idx := 0
	safePrimes := []*big.Int{p, q}
	f := func(bits uint) (*big.Int, error) {
		r := safePrimes[idx]
		idx = (idx + 1) % 2
		return r, nil
	}
	pub1, sec1, err := keyGenerator(f, 32)
	require.NoError(t, err)
	pub2, sec2, err := keyGenerator(f, 32)
	require.NoError(t, err)
	require.Equal(t, pub1.N, pub2.N)
	require.Equal(t, sec1.Lambda, sec2.Lambda)
	require.Equal(t, sec1.Totient, sec2.Totient)
	require.Equal(t, sec1.U, sec2.U)
}

func TestNewKeysDistinct(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TestNewKeys")
	}
	pub1, sec1, err := NewKeys()
	require.NoError(t, err)
	pub2, sec2, err := NewKeys()
	require.NoError(t, err)
	// Ensure two fresh keys are distinct
	require.NotEqual(t, pub1.N, pub2.N)
	require.NotEqual(t, sec1.Totient, sec2.Totient)
	require.NotEqual(t, sec1.Lambda, sec2.Lambda)
	require.NotEqual(t, sec1.U, sec2.U)
}

// Tests the restrictions on input values for paillier.Add
func TestAddErrorConditions(t *testing.T) {
	pk, err := NewPubkey(N)
	require.NoError(t, err)

	var tests = []struct {
		x, y         *big.Int
		expectedPass bool
	}{
		// Good: 0 ≤ x,y < N²
		{crypto.Zero, crypto.One, true},
		{NminusOne, big.NewInt(1024), true}, // N-1, 1024
		{NplusOne, hundoN, true},            // N+1, 100N
		{crypto.One, NNminusOne, true},      // one, N²-1

		// Bad
		{big.NewInt(-1), crypto.One, false},       // Negative values
		{crypto.One, big.NewInt(-1), false},       // Negative values
		{big.NewInt(-1000000), crypto.One, false}, // Negative values
		{crypto.One, big.NewInt(-9993654), false}, // Negative values

		{nil, crypto.One, false}, // x nil
		{crypto.One, nil, false}, // y nil

		{NNplusOne, crypto.One, false},                // N²+1
		{NNplusOne, NNplusOne, false},                 // both bad
		{crypto.One, NNplusOne, false},                // N²+1
		{new(big.Int).Add(NN, NN), crypto.One, false}, // 2N²
		{crypto.One, new(big.Int).Add(NN, NN), false}, // 2N²
		{NN, crypto.One, false},                       // = N²
		{crypto.One, NN, false},                       // = N²

	}

	// All the tests!
	for _, test := range tests {
		_, err := pk.Add(test.x, test.y)
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}

}

// Tests for paillier addition with known answers
func TestAdd(t *testing.T) {
	z9, err := NewPubkey(big.NewInt(3))
	require.NoError(t, err)
	pk, err := NewPubkey(N)
	require.NoError(t, err)

	// Pre-compute values for testing
	NplusOne := NplusOne
	// z = 2N+1
	z := new(big.Int).Add(N, N)
	z.Add(z, crypto.One)

	var tests = []struct {
		pk             *PublicKey
		x, y, expected *big.Int
	}{
		// Small number tests: Z_9
		{z9, big.NewInt(0), big.NewInt(1), big.NewInt(0)},
		{z9, big.NewInt(1), big.NewInt(5), big.NewInt(5)},
		{z9, big.NewInt(2), big.NewInt(2), big.NewInt(4)},
		{z9, big.NewInt(5), big.NewInt(2), big.NewInt(1)},
		{z9, big.NewInt(6), big.NewInt(8), big.NewInt(3)},
		{z9, big.NewInt(7), big.NewInt(7), big.NewInt(4)},
		{z9, big.NewInt(2), big.NewInt(4), big.NewInt(8)},
		{z9, big.NewInt(8), big.NewInt(8), big.NewInt(1)},
		{z9, big.NewInt(8), big.NewInt(2), big.NewInt(7)},

		// large number tests: Z_N²
		{pk, N, crypto.Zero, crypto.Zero},
		{pk, N, N, crypto.Zero}, // N² ≡ 0 (N²)
		{pk, crypto.Zero, NplusOne, crypto.Zero},
		{pk, NplusOne, NplusOne, z}, // (N+1)² = N² + 2N + 1 ≡ 2N + 1 (N²)
		{pk, tt.B10("11659564086467828628"), tt.B10("57089538512338875950"), tt.B10("665639132951488346363609789106750696600")},
	}
	// All the tests!
	for _, test := range tests {
		actual, err := test.pk.Add(test.x, test.y)
		require.NoError(t, err)
		require.Zero(t, test.expected.Cmp(actual))
	}
}

// Tests the restrictions on input values for paillier.Mul
func TestMulErrorConditions(t *testing.T) {
	pk, err := NewPubkey(N)
	require.NoError(t, err)

	var tests = []struct {
		x, y         *big.Int
		expectedPass bool
	}{
		// Good
		{crypto.Zero, crypto.One, true},     // 0 ≤ x,y < N
		{NminusOne, big.NewInt(1024), true}, // 0 ≤ x,y < N
		{NminusOne, hundoN, true},           // N-1 < N; 100N < N²
		{crypto.One, NNminusOne, true},      // 1 < N; N²-1 < N

		// Bad
		{big.NewInt(-1), crypto.One, false},       // Negative value x
		{big.NewInt(-1000000), crypto.One, false}, // Negative values x
		{crypto.One, big.NewInt(-9993654), false}, // Negative values y
		{crypto.One, big.NewInt(-1), false},       // Negative value y
		{big.NewInt(-1), big.NewInt(-1), false},   // Negative values both

		{NplusOne, crypto.One, false},                 // x > N; y ok
		{NplusOne, NNplusOne, false},                  // both x,y bad
		{crypto.One, NNplusOne, false},                // y bad
		{new(big.Int).Add(NN, NN), crypto.One, false}, // x really bad
		{crypto.One, new(big.Int).Add(NN, NN), false}, // y bad
		{N, crypto.One, false},                        // x boundary condition
		{crypto.One, NN, false},                       // y boundary condition
		{nil, crypto.One, false},                      // x nil
		{crypto.One, nil, false},                      // y nil
	}

	// All the tests!
	for _, test := range tests {
		_, err := pk.Mul(test.x, test.y)
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

// Tests for paillier multiplication with known answers
func TestMul(t *testing.T) {
	z25, err := NewPubkey(big.NewInt(5))
	require.NoError(t, err)
	pk, err := NewPubkey(N)
	require.NoError(t, err)
	newPk, err := NewPubkey(tt.B10("66563913295148834609789506"))
	require.NoError(t, err)

	// Compute: ɑ ≡ -2N -1  (N²)
	alpha, err := crypto.Mul(N, big.NewInt(-2), NN)
	require.Nil(t, err)
	alpha.Add(alpha, crypto.One)

	var tests = []struct {
		pk *PublicKey
		// Note: these values are in reverse-order from the order passed in as args
		c, a, expected *big.Int
	}{
		// Small number tests: Z_{25}
		{z25, big.NewInt(1), big.NewInt(0), big.NewInt(1)},
		{z25, big.NewInt(5), big.NewInt(1), big.NewInt(5)},
		{z25, big.NewInt(2), big.NewInt(2), big.NewInt(4)},
		{z25, big.NewInt(2), big.NewInt(1), big.NewInt(2)},
		{z25, big.NewInt(8), big.NewInt(4), big.NewInt(21)},
		{z25, big.NewInt(7), big.NewInt(3), big.NewInt(18)},
		{z25, big.NewInt(6), big.NewInt(0), big.NewInt(1)},
		{z25, big.NewInt(4), big.NewInt(3), big.NewInt(14)},
		{z25, big.NewInt(8), big.NewInt(1), big.NewInt(8)},
		{z25, big.NewInt(2), big.NewInt(2), big.NewInt(4)},

		// large number tests
		{pk, x, crypto.Zero, crypto.One},          // x^0 = 1
		{pk, y, crypto.One, y},                    // y^1 = 1
		{pk, crypto.Zero, NminusOne, crypto.Zero}, // 0^{N-1} = 0
		{pk, NminusOne, two, alpha},               // (N-1)² = N² - 2N - 1 ≡ -2N -1 (N²)

		// large number test: WorlframAlpha test case
		{newPk,
			tt.B10("11659564086467828628"),
			tt.B10("57089538512338875950"),
			tt.B10("1487259371808822575685230766372478858208831958946972")},
	}
	// All the tests!
	for _, test := range tests {
		actual, err := test.pk.Mul(test.a, test.c)
		require.NoError(t, err)
		require.Zero(t, test.expected.Cmp(actual))
	}
}

// encrypt() is provided a nonce and must be deterministic
func TestLittleEncryptDeterministic(t *testing.T) {
	pk, err := NewPubkey(N)
	require.NoError(t, err)
	r, err := crypto.Rand(pk.N)
	require.NoError(t, err)

	msg, _ := crypto.Rand(pk.N)

	// Encrypt the same msg/nonce multiple times
	a0, err := pk.encrypt(msg, r)
	require.NoError(t, err)

	a1, err := pk.encrypt(msg, r)
	require.NoError(t, err)

	a2, err := pk.encrypt(msg, r)
	require.NoError(t, err)

	// ❄️ == bad; confirm results are identical
	require.Equal(t, a0, a1)
	require.Equal(t, a0, a2)
}

// Tests the restrictions on input values for paillier.Encrypt
func TestEncryptErrorConditions(t *testing.T) {
	pk, err := NewPubkey(N)
	require.NoError(t, err)

	var tests = []struct {
		msg, r       *big.Int
		expectedPass bool
	}{
		// Good
		{crypto.Zero, crypto.One, true}, // 0 ≤ m,r < N
		{crypto.One, NminusOne, true},   // 0 ≤ m,r < N
		{NminusOne, two, true},          // 0 ≤ m,r < N

		// Bad
		{crypto.Zero, crypto.Zero, false},         // r cannot be 0
		{big.NewInt(-1), crypto.One, false},       // Negative value m
		{big.NewInt(-1000000), crypto.One, false}, // Negative value r
		{big.NewInt(-1), big.NewInt(-1), false},   // Negative values both
		{nil, crypto.One, false},                  // m nil
		{crypto.One, nil, false},                  // r nil
		{nil, nil, false},                         // both nil
		{N, crypto.One, false},                    // m == N
		{crypto.One, N, false},                    // r == N
	}

	// All the tests!
	for _, test := range tests {
		_, err := pk.encrypt(test.msg, test.r)
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}

	// Fail if N is nil
	pk = &PublicKey{N: nil, N2: nil}
	_, _, err = pk.Encrypt(crypto.One)
	require.Contains(t, err.Error(), "arguments cannot be nil")
}

// Tests that each invocation of Encrypt() produces a distinct output
func TestEncryptIsRandomized(t *testing.T) {
	pk, err := NewPubkey(N)
	require.NoError(t, err)
	msg := crypto.One

	// Encrypt the same msg multiple times
	a0, _, err := pk.Encrypt(msg)
	require.NoError(t, err)

	a1, _, err := pk.Encrypt(msg)
	require.NoError(t, err)

	a2, _, err := pk.Encrypt(msg)
	require.NoError(t, err)

	// ❄️ ❄️ ❄️
	require.NotEqual(t, a0, a1)
	require.NotEqual(t, a0, a2)
}

// Small number tests of Encrypt()
func TestEncryptKnownAnswers(t *testing.T) {
	// N=3, NN=9
	z9, err := NewPubkey(big.NewInt(3))
	require.NoError(t, err)

	var tests = []struct {
		m, r, expected *big.Int // m,r inputs
	}{
		// All operations below mod 9
		{big.NewInt(1), big.NewInt(1), big.NewInt(4)}, // c = (3+1)^1 * (1^3) = 4*1 = 4
		{big.NewInt(0), big.NewInt(1), big.NewInt(1)}, // c = (3+1)^0 * 1^3 = 1
		{big.NewInt(2), big.NewInt(2), big.NewInt(2)}, // c = (3+1)^2 * 2^3 = 16*8 ≡ -7 ≡ 2
		{big.NewInt(1), big.NewInt(2), big.NewInt(5)}, // c = (3+1)^1 * 2^3 = 4*8 ≡ 5
	}

	// All the tests!
	for _, test := range tests {
		actual, err := z9.encrypt(test.m, test.r)
		require.NoError(t, err)
		require.Zero(t, test.expected.Cmp(actual))
	}
}

// Encrypt should succeed over a range of arbitrary, valid messages
func TestEncryptSucceeds(t *testing.T) {
	pk, err := NewPubkey(N)
	require.NoError(t, err)
	iterations := 100
	for i := 0; i < iterations; i++ {
		msg, _ := crypto.Rand(pk.N)
		c, r, err := pk.Encrypt(msg)
		require.NoError(t, err)
		require.NotNil(t, c, r)
	}
}

// Tests the restrictions on input values for paillier.Decrypt
func TestDecryptErrorConditions(t *testing.T) {
	pk, err := NewPubkey(N)
	require.NoError(t, err)
	// A fake secret key, but good enough to test parameter validation
	sk := &SecretKey{*pk, NplusOne, NplusOne, NplusOne}

	var tests = []struct {
		c            *big.Int
		expectedPass bool
	}{
		// Good: c ∈ Z_N²
		// TODO: Fix when L() param restrictions settled
		// {crypto.Zero, true},
		// {crypto.One, true},
		// {N, true},
		// {NplusOne, true},
		// {hundoN, true},
		// {NNminusOne, true},

		// Bad
		{big.NewInt(-1), false},       // Negative
		{big.NewInt(-1000000), false}, // Negative
		{NN, false},                   // c = N²
		{NNplusOne, false},            // c > N²
		{nil, false},                  // nil
	}

	// All the tests!
	for _, test := range tests {
		_, err := sk.Decrypt(test.c)
		if test.expectedPass {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}

	// nil values in the SecretKey
	sk = &SecretKey{
		PublicKey: PublicKey{N: big.NewInt(100), N2: big.NewInt(10000)},
		Lambda:    big.NewInt(200),
		Totient:   nil,
		U:         nil,
	}
	_, err = sk.Decrypt(crypto.One)
	require.Error(t, err)

	// N = 0 is pub key
	sk = &SecretKey{
		PublicKey: PublicKey{N: big.NewInt(0), N2: big.NewInt(10000)},
		Lambda:    big.NewInt(200),
		Totient:   nil,
		U:         nil,
	}
	_, err = sk.Decrypt(crypto.One)
	require.Contains(t, err.Error(), "N cannot be 0")
}

// Decrypt·Encrypt is the identity function
func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Pre-computed safe primes
	p := tt.B10("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367")
	q := tt.B10("121400263190232595456200749546561304956161672968687911935494950378721768184159069938532869288284686583150658925255722159156454219960265942696166947144912738151554579878178746701374346180640493532962639632666540478486867810588884360492830920363713588684509182704981665082591486786717530494254613085570321507623")
	n := tt.B10("16241940578082201531943448855852277578391761356628379864603641922876623601321625229339135653813019543205064366507109899018615521640687222340376734033815591736764469510811142260074144789284382858541066390183237904579674336717818949214144339382239132186500111594251680147962383065732964214151653795512167674648653475620307856642151695559944756719719799945193072239010815330021803557074201060705849949820706127488164694762724694756011467249889383401729777382247223470577114290663770295230883950621358271613200219512401437571399087878832070221157976750549142719310423012055140771277730139053532825828483343855582012877641")
	nMinusOne := new(big.Int).Sub(n, crypto.One)
	// Artbitrary value < 2^1024
	x := tt.B10("20317113632585528798845062224869200275863225217624919914930609441107430244099181911960782321973293974573717329695193847701610218076524443400374940131739854056496412361090757880543495337916419061120521895395069964501013582917510846097488944684808895337780780147474736309539340360589608026856645992290890400384")

	// Create sk, pk for testing
	sk, err := NewSecretKey(p, q)
	require.NoError(t, err)
	pk, err := NewPubkey(n)
	require.NoError(t, err)

	// Valid msgs ∈ Z_N
	msgs := []*big.Int{
		crypto.Zero,
		crypto.One,
		nMinusOne,
		x,
	}

	// All the tests!
	for _, m := range msgs {
		// Encrypt,validate
		c, _, err := pk.Encrypt(m)
		require.NoError(t, err)
		require.NotNil(t, c)

		// Decrypt-validate
		actual, err := sk.Decrypt(c)
		require.NoError(t, err)
		require.Equal(t, m, actual)
	}
}

func TestSerializePublicKeyWorks(t *testing.T) {
	n := tt.B10("16241940578082201531943448855852277578391761356628379864603641922876623601321625229339135653813019543205064366507109899018615521640687222340376734033815591736764469510811142260074144789284382858541066390183237904579674336717818949214144339382239132186500111594251680147962383065732964214151653795512167674648653475620307856642151695559944756719719799945193072239010815330021803557074201060705849949820706127488164694762724694756011467249889383401729777382247223470577114290663770295230883950621358271613200219512401437571399087878832070221157976750549142719310423012055140771277730139053532825828483343855582012877641")
	pk, err := NewPubkey(n)
	require.NoError(t, err)

	data, err := pk.MarshalJSON()
	require.NoError(t, err)

	pk2 := new(PublicKey)
	require.NoError(t, pk2.UnmarshalJSON(data))
	require.Equal(t, pk2, pk)
	require.NoError(t, pk2.UnmarshalJSON([]byte(`{"N":1251}`)))
}

func TestSerializePublicKeyIgnoreFields(t *testing.T) {
	tests := [][]byte{
		[]byte(`{}`),
		[]byte(`{"a":null}`),
		[]byte(`{"n":null}`),
		[]byte(`{"N":null}`),
	}
	pk := new(PublicKey)
	for _, test := range tests {
		require.NoError(t, pk.UnmarshalJSON(test))
	}
}

func TestSerializeSecretKeyWorks(t *testing.T) {
	p := tt.B10("133788347333574532510542341875219452703250094560184213896952738579939377079849213618116996737030817731544214409221015150233522821287955673536671953914660520267670984696713816508768479853621956967492030516224494353641551367310541202655075859386716364585825364092974073148178887544704793573033779774765431460367")
	q := tt.B10("121400263190232595456200749546561304956161672968687911935494950378721768184159069938532869288284686583150658925255722159156454219960265942696166947144912738151554579878178746701374346180640493532962639632666540478486867810588884360492830920363713588684509182704981665082591486786717530494254613085570321507623")
	sk, err := NewSecretKey(p, q)
	require.NoError(t, err)

	data, err := sk.MarshalJSON()
	require.NoError(t, err)
	sk2 := new(SecretKey)
	require.NoError(t, sk2.UnmarshalJSON(data))
	require.Equal(t, sk2, sk)
	require.NoError(t, sk2.UnmarshalJSON([]byte(`{"N":2,"Totient":1,"U":1,"Lambda":1}`)))
}

func TestSerializeSecretKeyIgnoreFields(t *testing.T) {
	tests := [][]byte{
		[]byte(`{}`),
		[]byte(`{"a":null}`),
		[]byte(`{"n":null}`),
		[]byte(`{"N":null}`),
		[]byte(`{"N":null,"U":1}`),
	}
	sk := new(SecretKey)
	for _, test := range tests {
		require.NoError(t, sk.UnmarshalJSON(test))
	}
}

func TestSerializationErrorConditions(t *testing.T) {
	pk := new(PublicKey)
	require.Error(t, pk.UnmarshalJSON([]byte(`invalid`)))

	sk := new(SecretKey)
	require.Error(t, sk.UnmarshalJSON([]byte(`invalid`)))
}

func TestNewSecretKeyErrorConditions(t *testing.T) {
	testArgs := []lcmTest{
		{
			x: nil,
			y: big.NewInt(1),
		},
		{
			x: big.NewInt(1),
			y: nil,
		},
		{
			x: nil,
			y: nil,
		},
	}
	for _, arg := range testArgs {
		_, err := NewSecretKey(arg.x, arg.y)
		require.Contains(t, err.Error(), "arguments cannot be nil")
	}
}
