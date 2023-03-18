// (c) Copyright 2023 Matt Messier

package siwa

import (
	"context"
	"errors"
	"strconv"
	"time"
)

var (
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

	token *JWT
	_     struct{}
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
	j, err := DecodeJWT(token, &body)
	if err != nil {
		return nil, err
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
		token:          j,
	}
	return &t, nil
}

func (t *IdentityToken) verifyWithoutTimeCheck(
	ctx context.Context,
	store *KeyStore,
	audience string,
	nonce string,
) error {
	if err := t.token.Verify(ctx, store); err != nil {
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
