//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package nem

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type KeyPair struct {
	Privkey string `json:"privateKey"`
	Pubkey  string `json:"publicKey"`
}

type TestSig struct {
	Privkey string `json:"privateKey"`
	Pubkey  string `json:"publicKey"`
	Data    string `json:"data"`
	Length  int    `json:"length"`
	Sig     string `json:"signature"`
}

// NOTE: NEM provides no test vectors for Keccak512, but has test vectors for Keccak256
// We use Keccak256 and 512 in the exact same manner, so ensuring this test passes
// gives decent confidence in our Keccak512 use as well
func TestKeccak256SanityCheck(t *testing.T) {
	data := "A6151D4904E18EC288243028CEDA30556E6C42096AF7150D6A7232CA5DBA52BD2192E23DAA5FA2BEA3D4BD95EFA2389CD193FCD3376E70A5C097B32C1C62C80AF9D710211545F7CDDDF63747420281D64529477C61E721273CFD78F8890ABB4070E97BAA52AC8FF61C26D195FC54C077DEF7A3F6F79B36E046C1A83CE9674BA1983EC2FB58947DE616DD797D6499B0385D5E8A213DB9AD5078A8E0C940FF0CB6BF92357EA5609F778C3D1FB1E7E36C35DB873361E2BE5C125EA7148EFF4A035B0CCE880A41190B2E22924AD9D1B82433D9C023924F2311315F07B88BFD42850047BF3BE785C4CE11C09D7E02065D30F6324365F93C5E7E423A07D754EB314B5FE9DB4614275BE4BE26AF017ABDC9C338D01368226FE9AF1FB1F815E7317BDBB30A0F36DC69"
	toMatch := "4E9E79AB7434F6C7401FB3305D55052EE829B9E46D5D05D43B59FEFB32E9A619"
	toMatchBytes, err := hex.DecodeString(toMatch)
	require.NoError(t, err)
	dataBytes, err := hex.DecodeString(data)
	require.NoError(t, err)
	k256 := sha3.NewLegacyKeccak256()
	_, err = k256.Write(dataBytes)
	require.NoError(t, err)
	var hashed []byte
	hashed = k256.Sum(hashed)
	require.Equal(t, hashed, toMatchBytes)
}

// Test that the pubkey can get derived correctly from privkey
func TestPrivToPubkey(t *testing.T) {
	testVectors := GetPrivToPubkeyTestCases()

	for _, pair := range testVectors {
		privkeyBytes, err := hex.DecodeString(pair.Privkey)
		require.NoError(t, err)
		pubkeyBytes, err := hex.DecodeString(pair.Pubkey)
		require.NoError(t, err)

		privKeyCalced, err := NewKeyFromSeed(privkeyBytes)
		require.NoError(t, err)

		pubKeyCalced := privKeyCalced.Public().(PublicKey)

		require.Equal(t, pubKeyCalced.Bytes(), pubkeyBytes)
	}
}

// Test that we can:
// Get pubkey from privkey
// Obtain the correct signature
// Verify the test vector provided signature
func TestSigs(t *testing.T) {
	testVectors := GetSigTestCases()

	for _, ts := range testVectors {
		// Test priv -> pubkey again
		privkeyBytes, err := hex.DecodeString(ts.Privkey)
		require.NoError(t, err)
		pubkeyBytes, err := hex.DecodeString(ts.Pubkey)
		require.NoError(t, err)

		privKeyCalced, err := NewKeyFromSeed(privkeyBytes)
		require.NoError(t, err)

		pubKeyCalced := privKeyCalced.Public().(PublicKey)

		require.True(t, bytes.Equal(pubKeyCalced.Bytes(), pubkeyBytes))

		dataBytes, err := hex.DecodeString(ts.Data)
		require.NoError(t, err)
		sigBytes, err := hex.DecodeString(ts.Sig)
		require.NoError(t, err)

		// Test sign
		sigCalced, err := Sign(privKeyCalced, dataBytes)
		require.NoError(t, err)

		require.True(t, bytes.Equal(sigCalced, sigBytes))

		// Test verify
		verified, err := Verify(pubKeyCalced, dataBytes, sigBytes)
		require.NoError(t, err)

		require.True(t, verified)
	}
}

// NOTE: Test cases were obtained from NEM
// See link: https://github.com/symbol/test-vectors
// Pulled 5 test vectors for each test case, at time of writing confirmed that all 10000 vectors passed
func GetPrivToPubkeyTestCases() []KeyPair {
	var toReturn []KeyPair

	kp1 := KeyPair{
		Privkey: "575DBB3062267EFF57C970A336EBBC8FBCFE12C5BD3ED7BC11EB0481D7704CED",
		Pubkey:  "C5F54BA980FCBB657DBAAA42700539B207873E134D2375EFEAB5F1AB52F87844",
	}

	kp2 := KeyPair{
		Privkey: "5B0E3FA5D3B49A79022D7C1E121BA1CBBF4DB5821F47AB8C708EF88DEFC29BFE",
		Pubkey:  "96EB2A145211B1B7AB5F0D4B14F8ABC8D695C7AEE31A3CFC2D4881313C68EEA3",
	}

	kp3 := KeyPair{
		Privkey: "738BA9BB9110AEA8F15CAA353ACA5653B4BDFCA1DB9F34D0EFED2CE1325AEEDA",
		Pubkey:  "2D8425E4CA2D8926346C7A7CA39826ACD881A8639E81BD68820409C6E30D142A",
	}

	kp4 := KeyPair{
		Privkey: "E8BF9BC0F35C12D8C8BF94DD3A8B5B4034F1063948E3CC5304E55E31AA4B95A6",
		Pubkey:  "4FEED486777ED38E44C489C7C4E93A830E4C4A907FA19A174E630EF0F6ED0409",
	}

	kp5 := KeyPair{
		Privkey: "C325EA529674396DB5675939E7988883D59A5FC17A28CA977E3BA85370232A83",
		Pubkey:  "83EE32E4E145024D29BCA54F71FA335A98B3E68283F1A3099C4D4AE113B53E54",
	}

	toReturn = append(toReturn, kp1, kp2, kp3, kp4, kp5)

	return toReturn
}

func GetSigTestCases() []TestSig {
	var toReturn []TestSig

	t1 := TestSig{
		Privkey: "ABF4CF55A2B3F742D7543D9CC17F50447B969E6E06F5EA9195D428AB12B7318D",
		Pubkey:  "8A558C728C21C126181E5E654B404A45B4F0137CE88177435A69978CC6BEC1F4",
		Data:    "8CE03CD60514233B86789729102EA09E867FC6D964DEA8C2018EF7D0A2E0E24BF7E348E917116690B9",
		Length:  41,
		Sig:     "D9CEC0CC0E3465FAB229F8E1D6DB68AB9CC99A18CB0435F70DEB6100948576CD5C0AA1FEB550BDD8693EF81EB10A556A622DB1F9301986827B96716A7134230C",
	}

	t2 := TestSig{
		Privkey: "6AA6DAD25D3ACB3385D5643293133936CDDDD7F7E11818771DB1FF2F9D3F9215",
		Pubkey:  "BBC8CBB43DDA3ECF70A555981A351A064493F09658FFFE884C6FAB2A69C845C6",
		Data:    "E4A92208A6FC52282B620699191EE6FB9CF04DAF48B48FD542C5E43DAA9897763A199AAA4B6F10546109F47AC3564FADE0",
		Length:  49,
		Sig:     "98BCA58B075D1748F1C3A7AE18F9341BC18E90D1BEB8499E8A654C65D8A0B4FBD2E084661088D1E5069187A2811996AE31F59463668EF0F8CB0AC46A726E7902",
	}

	t3 := TestSig{
		Privkey: "8E32BC030A4C53DE782EC75BA7D5E25E64A2A072A56E5170B77A4924EF3C32A9",
		Pubkey:  "72D0E65F1EDE79C4AF0BA7EC14204E10F0F7EA09F2BC43259CD60EA8C3A087E2",
		Data:    "13ED795344C4448A3B256F23665336645A853C5C44DBFF6DB1B9224B5303B6447FBF8240A2249C55",
		Length:  40,
		Sig:     "EF257D6E73706BB04878875C58AA385385BF439F7040EA8297F7798A0EA30C1C5EFF5DDC05443F801849C68E98111AE65D088E726D1D9B7EECA2EB93B677860C",
	}

	t4 := TestSig{
		Privkey: "C83CE30FCB5B81A51BA58FF827CCBC0142D61C13E2ED39E78E876605DA16D8D7",
		Pubkey:  "3EC8923F9EA5EA14F8AAA7E7C2784653ED8C7DE44E352EF9FC1DEE81FC3FA1A3",
		Data:    "A2704638434E9F7340F22D08019C4C8E3DBEE0DF8DD4454A1D70844DE11694F4C8CA67FDCB08FED0CEC9ABB2112B5E5F89",
		Length:  49,
		Sig:     "0C684E71B35FED4D92B222FC60561DB34E0D8AFE44BDD958AAF4EE965911BEF5991236F3E1BCED59FC44030693BCAC37F34D29E5AE946669DC326E706E81B804",
	}

	t5 := TestSig{
		Privkey: "2DA2A0AAE0F37235957B51D15843EDDE348A559692D8FA87B94848459899FC27",
		Pubkey:  "D73D0B14A9754EEC825FCB25EF1CFA9AE3B1370074EDA53FC64C22334A26C254",
		Data:    "D2488E854DBCDFDB2C9D16C8C0B2FDBC0ABB6BAC991BFE2B14D359A6BC99D66C00FD60D731AE06D0",
		Length:  40,
		Sig:     "6F17F7B21EF9D6907A7AB104559F77D5A2532B557D95EDFFD6D88C073D87AC00FC838FC0D05282A0280368092A4BD67E95C20F3E14580BE28D8B351968C65E03",
	}

	toReturn = append(toReturn, t1, t2, t3, t4, t5)

	return toReturn
}
