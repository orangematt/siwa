package siwa

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUnknownKey     = errors.New("unknown public key")
	ErrMalformedToken = errors.New("malformed token")
)

type JWT struct {
	keyID      string
	alg        string
	tokenBytes []byte
	signature  []byte
}

func DecodeJWT(token string, body interface{}) (*JWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	var tokenBytes []byte
	if x := strings.LastIndexByte(token, '.'); x != -1 {
		tokenBytes = ([]byte)(token[:x])
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}
	bodyBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformedToken
	}

	// Decode the header. It tells us which RSA PublicKey to use to verify
	// the identity token.
	var header struct {
		KeyID string `json:"kid"`
		Alg   string `json:"alg"`
	}
	if err = json.Unmarshal(headerBytes, &header); err != nil {
		return nil, ErrMalformedToken
	}

	if err = json.Unmarshal(bodyBytes, body); err != nil {
		return nil, err
	}

	j := &JWT{
		keyID:      header.KeyID,
		alg:        header.Alg,
		tokenBytes: tokenBytes,
		signature:  signature,
	}
	return j, nil
}

func (j *JWT) Verify(ctx context.Context, store *KeyStore) error {
	key, ok := store.GetPublicKey(j.keyID, j.alg, "sig")
	if !ok {
		ok, err := store.MaybeRefreshPublicKeys(ctx, AuthKeysFetchFrequency)
		if !ok {
			if err != nil {
				return fmt.Errorf("cannot refresh public keys: %w", err)
			}
			return ErrUnknownKey
		}
		key, ok = store.GetPublicKey(j.keyID, j.alg, "sig")
		if !ok {
			return ErrUnknownKey
		}
	}

	h := sha256.New()
	h.Write(j.tokenBytes)
	hashed := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed, j.signature)
	if err != nil {
		return err
	}

	return nil
}
