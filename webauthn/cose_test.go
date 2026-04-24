package webauthn

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestParseCBORCOSEPublicKey(t *testing.T) {
	t.Run("ed25519", func(t *testing.T) {
		const cosePublicKeyHex = "a40101032720062158206ec3cf7561fc5cf88ca627371e7cf6a60e79b5bdca453334bdd3b17eb394c184"
		const xHex = "6ec3cf7561fc5cf88ca627371e7cf6a60e79b5bdca453334bdd3b17eb394c184"

		cborPublicKey, _ := hex.DecodeString(cosePublicKeyHex)
		x, _ := hex.DecodeString(xHex)
		cosePublicKey, keySize, err := parseCBORCOSEPublicKey(cborPublicKey)
		if err != nil {
			t.Errorf("error: %s", err.Error())
		}
		if len(cborPublicKey) != keySize {
			t.Error("byte count match")
		}
		ed25519COSEPubicKey := cosePublicKey.(*EdDSACOSEPublicKeyStruct)
		if !bytes.Equal(ed25519COSEPubicKey.X, x) {
			t.Error("x value mismatch")
		}
	})

	t.Run("es256", func(t *testing.T) {
		const cosePublicKeyHex = "a501020326200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"
		const xHex = "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d"
		const yHex = "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"

		cborPublicKey, _ := hex.DecodeString(cosePublicKeyHex)
		x, _ := hex.DecodeString(xHex)
		y, _ := hex.DecodeString(yHex)
		cosePublicKey, keySize, err := parseCBORCOSEPublicKey(cborPublicKey)
		if err != nil {
			t.Errorf("error: %s", err.Error())
		}
		if len(cborPublicKey) != keySize {
			t.Error("byte count match")
		}
		es256COSEPubicKey := cosePublicKey.(*ES256COSEPublicKeyStruct)
		if !bytes.Equal(es256COSEPubicKey.X.Bytes(), x) {
			t.Error("x value mismatch")
		}
		if !bytes.Equal(es256COSEPubicKey.Y.Bytes(), y) {
			t.Error("y mismatch mismatch")
		}
	})

	t.Run("rs256", func(t *testing.T) {
		const cosePublicKeyHex = "A401030339010020590100A99D6D5520398AEB194A193BD101362ACF17D25FE1B9D2E3F63892F504797E82B461BD1CD21B734B1027BBFCFCAEFCC23871B7879240B5CB7A3793BC5A106187314EDCB012ABABFAFBAB025DCF296094FF0A90DECB4849ACB6EDAF0A4DABDF72963D51AA369DE31163999933C1101FD47CD5437DA84735653401932456DCA8EB90C1DF795D91311DD2C021FF78053464A5BD8D250A49CE7C0F4ADA955CBD0F17081369F6D346C8D152B6FDB18AD87BA1335640A8E42534641355963590640A9B221CDF128CDECA076666D8D327A4B347BE809C6D914452164131E609DF068C8436DB90729A4E8826A6636EF5946A83916D87EDEB80F4B2EC30965E6A68DA09592143010001"
		const nHex = "a99d6d5520398aeb194a193bd101362acf17d25fe1b9d2e3f63892f504797e82b461bd1cd21b734b1027bbfcfcaefcc23871b7879240b5cb7a3793bc5a106187314edcb012ababfafbab025dcf296094ff0a90decb4849acb6edaf0a4dabdf72963d51aa369de31163999933c1101fd47cd5437da84735653401932456dca8eb90c1df795d91311dd2c021ff78053464a5bd8d250a49ce7c0f4ada955cbd0f17081369f6d346c8d152b6fdb18ad87ba1335640a8e42534641355963590640a9b221cdf128cdeca076666d8d327a4b347be809c6d914452164131e609df068c8436db90729a4e8826a6636ef5946a83916d87edeb80f4b2ec30965e6a68da0959"
		const e = 65537

		cborPublicKey, _ := hex.DecodeString(cosePublicKeyHex)
		n, _ := hex.DecodeString(nHex)
		cosePublicKey, keySize, err := parseCBORCOSEPublicKey(cborPublicKey)
		if err != nil {
			t.Errorf("error: %s", err.Error())
		}
		if len(cborPublicKey) != keySize {
			t.Error("byte count match")
		}
		rs256COSEPubicKey := cosePublicKey.(*RS256COSEPublicKeyStruct)
		if !bytes.Equal(rs256COSEPubicKey.N.Bytes(), n) {
			t.Error("n value mismatch")
		}
		if rs256COSEPubicKey.E != e {
			t.Error("e mismatch mismatch")
		}
	})
}
