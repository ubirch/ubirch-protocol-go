package ubirch

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"github.com/paypal/go.crypto/keystore"
	"math/big"
)

type CryptoContext struct {
	Keystore      *keystore.Keystore
	LastSignature []byte
}

func encodePriv(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return pemEncoded, nil
}

func encodePub(publicKey *ecdsa.PublicKey) ([]byte, error) {
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return pemEncoded, nil
}

func decodePriv(pemEncoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemEncoded)
	x509Encoded := block.Bytes
	return x509.ParseECPrivateKey(x509Encoded)
}

func decodePub(pemEncoded []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemEncoded)
	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return genericPublicKey.(*ecdsa.PublicKey), nil
}

func signatureToPoints(signature []byte) (r, s *big.Int, err error) {
	r, s = &big.Int{}, &big.Int{}

	data := asn1.RawValue{}
	_, err = asn1.Unmarshal(signature, &data)
	if err != nil {
		return nil, nil, err
	}

	rLen := data.Bytes[1]
	r.SetBytes(data.Bytes[2 : rLen+2])
	s.SetBytes(data.Bytes[rLen+4:])

	return r, s, nil
}

func (c *CryptoContext) AddPublicKey(id uuid.UUID, k *ecdsa.PublicKey) error {
	pubKeyBytes, err := encodePub(k)
	if err != nil {
		return err
	}
	pph, _ := id.MarshalBinary()
	return c.Keystore.Set("_"+id.String(), pubKeyBytes, pph)
}

func (c *CryptoContext) AddKey(id uuid.UUID, k *ecdsa.PrivateKey) error {
	err := c.AddPublicKey(id, &k.PublicKey)
	if err != nil {
		return err
	}

	pubKeyBytes, err := encodePriv(k)
	if err != nil {
		return err
	}
	pph, _ := id.MarshalBinary()
	return c.Keystore.Set(id.String(), pubKeyBytes, pph)
}

func (c *CryptoContext) Sign(id uuid.UUID, data []byte) ([]byte, error) {
	pph, _ := id.MarshalBinary()
	privKeyBytes, err := c.Keystore.Get(id.String(), pph)
	priv, err := decodePriv(privKeyBytes)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, data)
	if err != nil {
		return nil, err
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

func (c *CryptoContext) Verify(id uuid.UUID, data []byte) ([]byte, error) {
	pph, _ := id.MarshalBinary()
	pubKeyBytes, err := c.Keystore.Get("_"+id.String(), pph)

	pub, err := decodePub(pubKeyBytes)
	if err != nil {
		return nil, err
	}

	r, s, err := signatureToPoints(data[len(data)-66:])
	if err != nil {
		return nil, err
	}

	value := data[0 : len(data)-64]
	if ecdsa.Verify(pub, value, r, s) {
		return value, nil
	}
	return nil, errors.New("signature verification failed")
}
