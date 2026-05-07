package webauthn

import (
	"encoding/hex"
	"testing"
)

func TestVerifyCOSEPublicKey(t *testing.T) {
	t.Run("ed25519", func(t *testing.T) {
		const cosePublicKeyHex = "a40101032720062158206ec3cf7561fc5cf88ca627371e7cf6a60e79b5bdca453334bdd3b17eb394c184"

		cosePublicKey, _ := hex.DecodeString(cosePublicKeyHex)

		publicKeySize, err := verifyCOSEPublicKey(cosePublicKey)
		if err != nil {
			t.Errorf("error: %s", err.Error())
		}
		if publicKeySize != len(cosePublicKey) {
			t.Error("public size mismatch")
		}
	})

	t.Run("es256", func(t *testing.T) {
		const cosePublicKeyHex = "a501020326200121582065eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d2258201e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c"
		cosePublicKey, _ := hex.DecodeString(cosePublicKeyHex)

		publicKeySize, err := verifyCOSEPublicKey(cosePublicKey)
		if err != nil {
			t.Errorf("error: %s", err.Error())
		}
		if publicKeySize != len(cosePublicKey) {
			t.Error("public size mismatch")
		}
	})

	t.Run("rs256", func(t *testing.T) {
		const cosePublicKeyHex = "A401030339010020590100A99D6D5520398AEB194A193BD101362ACF17D25FE1B9D2E3F63892F504797E82B461BD1CD21B734B1027BBFCFCAEFCC23871B7879240B5CB7A3793BC5A106187314EDCB012ABABFAFBAB025DCF296094FF0A90DECB4849ACB6EDAF0A4DABDF72963D51AA369DE31163999933C1101FD47CD5437DA84735653401932456DCA8EB90C1DF795D91311DD2C021FF78053464A5BD8D250A49CE7C0F4ADA955CBD0F17081369F6D346C8D152B6FDB18AD87BA1335640A8E42534641355963590640A9B221CDF128CDECA076666D8D327A4B347BE809C6D914452164131E609DF068C8436DB90729A4E8826A6636EF5946A83916D87EDEB80F4B2EC30965E6A68DA09592143010001"

		cosePublicKey, _ := hex.DecodeString(cosePublicKeyHex)

		publicKeySize, err := verifyCOSEPublicKey(cosePublicKey)
		if err != nil {
			t.Errorf("error: %s", err.Error())
		}
		if publicKeySize != len(cosePublicKey) {
			t.Error("public size mismatch")
		}
	})
}
