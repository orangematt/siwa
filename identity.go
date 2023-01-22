// (c) Copyright 2023 Matt Messier

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
	"strconv"
	"strings"
	"time"
)

var (
	ErrUnknownKey      = errors.New("unknown public key")
	ErrMalformedToken  = errors.New("malformed token")
	ErrInvalidNonce    = errors.New("invalid nonce")
	ErrInvalidIssuer   = errors.New("invalid issuer")
	ErrInvalidAudience = errors.New("invalid audience")
	ErrTokenExpired    = errors.New("token expired")
)

const expectedIssuer = "https://appleid.apple.com"

type RealUserStatus int

const (
	Unsupported RealUserStatus = 0
	Unknown     RealUserStatus = 1
	LikelyReal  RealUserStatus = 2
)

type IdentityToken struct {
	// Header information
	KeyID string
	Alg   string

	// Body information
	Issuer         string
	Audience       string
	Expires        time.Time
	IssuedAt       time.Time
	Subject        string
	Email          string
	EmailVerified  bool
	IsPrivateEmail bool
	RealUserStatus RealUserStatus
	NonceSupported bool
	Nonce          string

	token     []byte
	signature []byte
}

func parseBool(v interface{}) (bool, error) {
	if s, ok := v.(string); ok {
		return strconv.ParseBool(s)
	}
	if b, ok := v.(bool); ok {
		return b, nil
	}
	return false, nil
}

func NewIdentityToken(token string) (*IdentityToken, error) {
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

	// This contains only Apple documented fields. There may be others
	// present, but we will pay them no mind.
	var body struct {
		Issuer         string      `json:"iss"` // This should be "https://appleid.apple.com"
		Audience       string      `json:"aud"` // This should be the app bundle ID
		Expires        int64       `json:"exp"` // This should be in the future
		IssuedAt       int64       `json:"iat"` // This should be before Expires
		Subject        string      `json:"sub"`
		Email          string      `json:"email"`
		EmailVerified  interface{} `json:"email_verified"`
		IsPrivateEmail interface{} `json:"is_private_email"`
		RealUserStatus int         `json:"real_user_status"`
		NonceSupported interface{} `json:"nonce_supported"`
		Nonce          string      `json:"nonce"`
	}
	if err = json.Unmarshal(bodyBytes, &body); err != nil {
		return nil, ErrMalformedToken
	}

	emailVerified, err := parseBool(body.EmailVerified)
	if err != nil {
		return nil, ErrMalformedToken
	}
	nonceSupported, err := parseBool(body.NonceSupported)
	if err != nil {
		return nil, ErrMalformedToken
	}
	isPrivateEmail, err := parseBool(body.IsPrivateEmail)
	if err != nil {
		return nil, ErrMalformedToken
	}

	t := IdentityToken{
		KeyID: header.KeyID,
		Alg:   header.Alg,

		Issuer:         body.Issuer,
		Audience:       body.Audience,
		Expires:        time.Unix(body.Expires, 0),
		IssuedAt:       time.Unix(body.IssuedAt, 0),
		Subject:        body.Subject,
		Email:          body.Email,
		EmailVerified:  emailVerified,
		IsPrivateEmail: isPrivateEmail,
		RealUserStatus: RealUserStatus(body.RealUserStatus),
		NonceSupported: nonceSupported,
		Nonce:          body.Nonce,

		token:     tokenBytes,
		signature: signature,
	}
	return &t, nil
}

func (t *IdentityToken) verifyWithoutTimeCheck(
	ctx context.Context,
	store *KeyStore,
	audience string,
	nonce string,
) error {
	key, ok := store.GetPublicKey(t.KeyID, t.Alg, "sig")
	if !ok {
		ok, err := store.MaybeRefreshPublicKeys(ctx, AuthKeysFetchFrequency)
		if !ok {
			if err != nil {
				return fmt.Errorf("cannot refresh public keys: %w", err)
			}
			return ErrUnknownKey
		}
		key, ok = store.GetPublicKey(t.KeyID, t.Alg, "sig")
		if !ok {
			return ErrUnknownKey
		}
	}

	h := sha256.New()
	h.Write(t.token)
	hashed := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed, t.signature)
	if err != nil {
		return err
	}

	if nonce != "" {
		if !t.NonceSupported {
			return ErrInvalidNonce
		}
	} else {
		if t.Nonce != "" {
			return ErrInvalidNonce
		}
	}

	if t.Issuer != expectedIssuer {
		return ErrInvalidIssuer
	}
	if t.Audience != audience {
		return ErrInvalidAudience
	}
	if t.IssuedAt.After(t.Expires) {
		return ErrTokenExpired
	}

	return nil
}

func (t *IdentityToken) Verify(
	ctx context.Context,
	store *KeyStore,
	audience string,
	nonce string,
) error {
	if err := t.verifyWithoutTimeCheck(ctx, store, audience, nonce); err != nil {
		return err
	}
	if t.Expires.Before(time.Now()) {
		return ErrTokenExpired
	}
	return nil
}
