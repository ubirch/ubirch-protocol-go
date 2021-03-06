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
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"github.com/ugorji/go/codec"
)

// ProtocolVersion definition
type ProtocolVersion uint8
type Hint uint8

const (
	Signed                     ProtocolVersion = 0x22 // Signed protocol, the Ubirch Protocol Package is signed
	Chained                    ProtocolVersion = 0x23 // Chained protocol, the Ubirch Protocol Package contains the previous signature and is signed
	Binary                     Hint            = 0x00
	Disable                    Hint            = 0xFA
	Enable                     Hint            = 0xFB
	Delete                     Hint            = 0xFC
	expectedHashSize                           = 32                          // length of a SHA256 hash
	lenMsgpackSignatureElement                 = 2 + nistp256SignatureLength // length of a signature plus msgpack header for byte array (0xc4XX)
)

// Crypto Interface for exported functionality
type Crypto interface {
	GetUUID(name string) (uuid.UUID, error)
	GenerateKey(name string, id uuid.UUID) error
	GetCSR(name string, subjectCountry string, subjectOrganization string) ([]byte, error)
	GetPublicKey(name string) ([]byte, error)
	PrivateKeyExists(name string) bool
	SetPublicKey(name string, id uuid.UUID, pubKeyBytes []byte) error
	SetKey(name string, id uuid.UUID, privKeyBytes []byte) error

	Sign(id uuid.UUID, value []byte) ([]byte, error)
	Verify(id uuid.UUID, value []byte, signature []byte) (bool, error)
}

// Protocol structure
type Protocol struct {
	Crypto
	Signatures map[uuid.UUID][]byte
}

// interface for Ubirch Protocol Packages
type UPP interface {
	GetVersion() ProtocolVersion
	GetUuid() uuid.UUID
	GetPrevSignature() []byte
	GetHint() Hint
	GetPayload() []byte
	GetSignature() []byte
}

// SignedUPP is the Signed Ubirch Protocol Package
type SignedUPP struct {
	Version   ProtocolVersion
	Uuid      uuid.UUID
	Hint      Hint
	Payload   []byte
	Signature []byte
}

func (upp SignedUPP) GetVersion() ProtocolVersion {
	return upp.Version
}

func (upp SignedUPP) GetUuid() uuid.UUID {
	return upp.Uuid
}

func (upp SignedUPP) GetPrevSignature() []byte {
	return nil
}

func (upp SignedUPP) GetHint() Hint {
	return upp.Hint
}

func (upp SignedUPP) GetPayload() []byte {
	return upp.Payload
}

func (upp SignedUPP) GetSignature() []byte {
	return upp.Signature
}

// ChainedUPP is the Chained Ubirch Protocol Package
type ChainedUPP struct {
	Version       ProtocolVersion
	Uuid          uuid.UUID
	PrevSignature []byte
	Hint          Hint
	Payload       []byte
	Signature     []byte
}

func (upp ChainedUPP) GetVersion() ProtocolVersion {
	return upp.Version
}

func (upp ChainedUPP) GetUuid() uuid.UUID {
	return upp.Uuid
}

func (upp ChainedUPP) GetPrevSignature() []byte {
	return upp.PrevSignature
}

func (upp ChainedUPP) GetHint() Hint {
	return upp.Hint
}

func (upp ChainedUPP) GetPayload() []byte {
	return upp.Payload
}

func (upp ChainedUPP) GetSignature() []byte {
	return upp.Signature
}

// Encode encodes a UPP into MsgPack and returns it, if successful with 'nil' error
func Encode(upp UPP) ([]byte, error) {
	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	encoded := make([]byte, 128)
	encoder := codec.NewEncoderBytes(&encoded, &mh)
	if err := encoder.Encode(upp); err != nil {
		return nil, err
	}
	return encoded, nil
}

// Decode decodes raw protocol package data (bytes) into an UPP (structured) and returns it, if successful with 'nil' error
func Decode(upp []byte) (UPP, error) {
	if upp == nil || len(upp) < 2 {
		return nil, fmt.Errorf("input nil or invalid length")
	}

	var mh codec.MsgpackHandle
	mh.StructToArray = true
	mh.WriteExt = true

	decoder := codec.NewDecoderBytes(upp, &mh)
	switch upp[1] {
	case byte(Signed):
		signedUPP := new(SignedUPP)
		err := decoder.Decode(signedUPP)
		if err != nil {
			return nil, err
		}
		return signedUPP, nil
	case byte(Chained):
		chainedUPP := new(ChainedUPP)
		err := decoder.Decode(chainedUPP)
		if err != nil {
			return nil, err
		}
		return chainedUPP, nil
	default:
		return nil, fmt.Errorf("invalid protocol version: 0x%02x", upp[1])
	}
}

func DecodeSigned(upp []byte) (*SignedUPP, error) {
	i, err := Decode(upp)
	if err != nil {
		return nil, err
	}

	signed, ok := i.(*SignedUPP)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: input not a signed UPP")
	}

	return signed, nil
}

func DecodeChained(upp []byte) (*ChainedUPP, error) {
	i, err := Decode(upp)
	if err != nil {
		return nil, err
	}

	chained, ok := i.(*ChainedUPP)
	if !ok {
		return nil, fmt.Errorf("type assertion failed: input not a chained UPP")
	}

	return chained, nil
}

// appendSignature appends a signature to an encoded message and returns it
func appendSignature(data []byte, signature []byte) []byte {
	if len(data) == 0 || len(signature) == 0 {
		return nil
	}
	data = append(data, 0xC4, byte(len(signature)))
	return append(data, signature...)
}

// sign encodes, signs and appends the signature to a UPP
// also saves the signature for chained UPPs
func (p *Protocol) sign(upp UPP) ([]byte, error) {
	encoded, err := Encode(upp)
	if err != nil {
		return nil, err
	}

	uppWithoutSig := encoded[:len(encoded)-1]

	signature, err := p.Crypto.Sign(upp.GetUuid(), uppWithoutSig)
	if err != nil {
		return nil, err
	}
	if len(signature) != nistp256SignatureLength {
		return nil, fmt.Errorf("generated signature has invalid length")
	}

	uppWithSig := appendSignature(uppWithoutSig, signature)
	if uppWithSig == nil {
		return nil, fmt.Errorf("appending signature to UPP data failed")
	}

	// save the signature for chained UPPs
	if upp.GetVersion() == Chained {
		p.Signatures[upp.GetUuid()] = signature
	}

	return uppWithSig, nil
}

//Sign is a wrapper for backwards compatibility with Sign() calls, will be removed in the future
func (p *Protocol) Sign(name string, hash []byte, protocol ProtocolVersion) ([]byte, error) {
	fmt.Println("Warning: Sign() is deprecated, please use SignHash() or SignData() as appropriate")
	return p.SignHash(name, hash, protocol)
}

// SignHash creates and signs a ubirch-protocol message using the given hash and the protocol version.
// The method expects a SHA256 hash as input data.
// Returns a standard ubirch-protocol packet (UPP) with the hint 0x00 (binary hash).
func (p *Protocol) SignHash(name string, hash []byte, protocol ProtocolVersion) ([]byte, error) {
	return p.SignHashExtended(name, hash, protocol, Binary)
}

// SignData creates and signs a ubirch-protocol message using the given user data and the protocol version.
// The method expects the user data as input data. Data will be SHA256 hashed and a UPP using
// the hash as payload will be created by calling SignHash(). The UUID is automatically retrieved
// from the context using the given device name.
// FIXME this method name might be confusing. If the user explicitly wants to sign original data,
//  (e.g. for msgpack key registration messages) the method name sounds like it would do that.
func (p *Protocol) SignData(name string, userData []byte, protocol ProtocolVersion) ([]byte, error) {
	//Catch errors
	if userData == nil || len(userData) < 1 {
		return nil, fmt.Errorf("input data is nil or empty")
	}
	//Calculate hash
	//TODO: Make this dependent on the used crypto if we implement more than one
	hash := sha256.Sum256(userData)

	return p.SignHash(name, hash[:], protocol)
}

// SignHashExtended creates and signs a ubirch-protocol message using the given hash, hint and protocol version.
// The method expects a SHA256 hash as input data.
// Returns a standard ubirch-protocol packet (UPP)
func (p *Protocol) SignHashExtended(name string, hash []byte, protocol ProtocolVersion, hint Hint) ([]byte, error) {
	if len(hash) != expectedHashSize {
		return nil, fmt.Errorf("invalid hash size, expected %v, got %v bytes", expectedHashSize, len(hash))
	}

	id, err := p.GetUUID(name)
	if err != nil {
		return nil, err
	}

	switch protocol {
	case Signed:
		return p.sign(&SignedUPP{Signed, id, hint, hash, nil})
	case Chained:
		prevSignature, found := p.Signatures[id] // load signature of last UPP
		if !found {
			prevSignature = make([]byte, nistp256SignatureLength) // not found: make new chain start (all zeroes signature)
		} else if len(prevSignature) != nistp256SignatureLength { // found: check that loaded signature has valid length
			return nil, fmt.Errorf("invalid last signature, can't create chained UPP")
		}
		return p.sign(&ChainedUPP{Chained, id, prevSignature, hint, hash, nil})
	default:
		return nil, fmt.Errorf("invalid protocol version: 0x%02x", protocol)
	}
}

// Verify verifies the signature of a ubirch-protocol message.
func (p *Protocol) Verify(name string, upp []byte) (bool, error) {
	if len(upp) <= lenMsgpackSignatureElement {
		return false, fmt.Errorf("input not verifiable, not enough data: len %d <= %d bytes", len(upp), lenMsgpackSignatureElement)
	}

	id, err := p.GetUUID(name)
	if err != nil {
		return false, err
	}

	data := upp[:len(upp)-lenMsgpackSignatureElement]
	signature := upp[len(upp)-nistp256SignatureLength:]
	return p.Crypto.Verify(id, data, signature)
}

// CheckChainLink compares the signature bytes of a previous ubirch protocol package with the previous signature bytes of
// a subsequent chained ubirch protocol package and returns true if they match.
// Returns an error if one of the UPPs is invalid.
func CheckChainLink(previousUPP UPP, subsequentUPP UPP) (bool, error) {
	if len(previousUPP.GetSignature()) == 0 {
		return false, fmt.Errorf("signature field of previous UPP is empty")
	}
	if len(subsequentUPP.GetPrevSignature()) == 0 {
		return false, fmt.Errorf("previous signature field of subsequent UPP empty")
	}
	return bytes.Equal(previousUPP.GetSignature(), subsequentUPP.GetPrevSignature()), nil
}
