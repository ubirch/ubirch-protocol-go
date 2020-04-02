/*
 * Copyright (c) 2019 ubirch GmbH.
 *
 * ```
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ```
 */

package ubirch

import (
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

// TestNewEncryptedKeystore tests the creation of a new keystore
//		with correct secret length
// 		with empty secret
// 		with too long secret length
func TestNewEncryptedKeystore(t *testing.T) {
	asserter := assert.New(t)
	//create new encrypted keystore with valid secret
	testkeystore := NewEncryptedKeystore([]byte(defaultSecret))
	asserter.NotNilf(testkeystore, "KeyStore not created")
	asserter.IsTypef(testkeystore, &EncryptedKeystore{}, "Type is not correct")
	asserter.Equalf(testkeystore.Secret, []byte(defaultSecret), "the secret is different, should be the same")

	// try to create a KeyStore without secret
	testkeystore2 := NewEncryptedKeystore([]byte(""))
	asserter.Nilf(testkeystore2, "KeyStore created, should be Nil")

	// try to create a KeyStore with too long secret
	testkeystore3 := NewEncryptedKeystore(append([]byte(defaultSecret), 0x00))
	asserter.Nilf(testkeystore3, "KeyStore created, should be Nil")
}

// TestEncryptedKeystore_GetKey tests to Get a specific key from the keystore
//		Load a protocol context from file and
//			get the public key
//			get the private key
func TestEncryptedKeystore_GetKey(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var testKeystore = NewEncryptedKeystore([]byte(defaultSecret))
	var context = &CryptoContext{
		Keystore: testKeystore,
		Names:    map[string]uuid.UUID{},
	}
	p := Protocol{Crypto: context, Signatures: map[uuid.UUID][]byte{}}
	requirer.NoErrorf(loadProtocolContext(&p, "test3.json"), "Failed loading protocol context")
	// Get the public key
	pubKeyEncoded, err := testKeystore.GetKey("_" + defaultUUID)
	asserter.NoErrorf(err, "failed to get the public key")
	asserter.NotNilf(pubKeyEncoded, "pubkey is 'Nil'")
	// decode the key and compare it
	pubKey, err := decodePublicKeyCommon(pubKeyEncoded)
	pubKeyBytes := pubKey.X.Bytes()
	pubKeyBytes = append(pubKeyBytes, pubKey.Y.Bytes()...)
	pubKeyString := hex.EncodeToString(pubKeyBytes)
	asserter.Equalf(defaultPub, pubKeyString, "not equal")
	// Get the private key
	privKeyEncoded, err := testKeystore.GetKey(defaultUUID)
	asserter.NoErrorf(err, "failed to get the privlic key")
	asserter.NotNilf(privKeyEncoded, "privkey is 'Nil'")
	// decode the private key and compare it
	privKey, err := decodePrivateKeyCommon(privKeyEncoded)
	privKeyBytes := privKey.D.Bytes()
	privKeyString := hex.EncodeToString(privKeyBytes)
	asserter.Equalf(defaultPriv, privKeyString, "not equal")
}

// test, where the get method should fail
func TestEncryptedKeystore_GetKeyFails_NOTRDY(t *testing.T) {
}

// TestEncryptedKeystore_SetKey tests the Set method for a key in the keystore
//		Create an encoded private key
// 			set the complete key
//			set only part of the key, which is not practical, but allows the testing of different lengths
//		Create an encoded public key
// 			set the complete key
//			set only part of the key, which is not practical, but allows the testing of different lengths
func TestEncryptedKeystore_SetKey(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var testKeystore = NewEncryptedKeystore([]byte(defaultSecret))
	// make Encoded private Key and test
	privBytesCorrect, err := hex.DecodeString(defaultPriv)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	privEncodedCorrect, err := encodePrivateKeyCommon(privBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	// Test valid key length
	asserter.NoErrorf(testKeystore.SetKey(defaultUUID, privEncodedCorrect),
		"set private key with correct length failed")
	// test different lengths for the key
	for i := 1; i < len(privEncodedCorrect); i++ {
		if (i % 8) == 0 {
			i++
		} //todo, see TestEncryptedKeystore_SetKeyNOTRDY() below
		asserter.NoErrorf(testKeystore.SetKey(defaultUUID, privEncodedCorrect[:i]),
			"set private key with length (%v) failed", i)
	}
	// make Encoded public Key and test
	pubBytesCorrect, err := hex.DecodeString(defaultPub)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	pubEncodedCorrect, err := encodePublicKeyCommon(pubBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	// Test valid key length  //todo this test fails, but shouldn't
	asserter.NoErrorf(testKeystore.SetKey("_"+defaultUUID, pubEncodedCorrect),
		"set public key with correct length failed")
	// test different lengths for the key
	for i := 1; i < len(pubEncodedCorrect); i++ {
		if (i % 8) == 0 {
			i++
		} //todo, see TestEncryptedKeystore_SetKeyNOTRDY() below
		asserter.NoErrorf(testKeystore.SetKey("_"+defaultUUID, pubEncodedCorrect[:i]),
			"set public key with length (%v) failed", i)
	}
}

// Test the set method with keylengths of n*8 Bytes, where n >=1, which currently fails
// because of a bug in the paypal/keystore library
func TestEncryptedKeystore_SetKeyNOTRDY(t *testing.T) {
	asserter := assert.New(t)
	requirer := require.New(t)
	//Set up test objects and parameters
	var testKeystore = NewEncryptedKeystore([]byte(defaultSecret))
	// make Encoded private key and test
	privBytesCorrect, err := hex.DecodeString(defaultPriv)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	privEncodedCorrect, err := encodePrivateKeyCommon(privBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	// test all available legths n*8 Byte
	for i := 8; i < len(privEncodedCorrect); {
		i += 8
		asserter.NoErrorf(testKeystore.SetKey(defaultUUID, privEncodedCorrect[:i]),
			"set private key with length (%v) failed", i)
	}
	// make Encoded public Key and test
	pubBytesCorrect, err := hex.DecodeString(defaultPub)
	requirer.NoErrorf(err, "Decoding private Key Bytes failed")
	pubEncodedCorrect, err := encodePublicKeyCommon(pubBytesCorrect)
	requirer.NoErrorf(err, "Encoding PrivateKey failed")
	// test all available legths n*8 Byte
	for i := 8; i < len(pubEncodedCorrect); {
		i += 8
		asserter.NoErrorf(testKeystore.SetKey("_"+defaultUUID, pubEncodedCorrect[:i]),
			"set public key with length (%v) failed", i)
	}
}

func TestEncryptedKeystore_MarshalJSON_NOTRDY(t *testing.T) {
	t.Error("MarshalJSON() not implemented")
}

func TestEncryptedKeystore_UnmarshalJSON_NOTRDY(t *testing.T) {
	t.Error("UnmarshalJSON() not implemented")
}
