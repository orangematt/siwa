// (c) Copyright 2023 Matt Messier

package siwa

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidPrivateKey = errors.New("invalid or missing private key")
	ErrInvalidResponse   = errors.New("invalid response")
)

const appleAuthURL = "https://appleid.apple.com/auth/token"

type HTTPRequestProvider interface {
	NewRequestWithContext(context.Context, string, string, io.Reader) (*http.Request, error)
}

type Manager struct {
	bundleID   string
	teamID     string
	keyID      string
	keyStore   *KeyStore
	privateKey crypto.PrivateKey
	delegate   interface{}
}

func NewManager(bundleID, teamID, keyID string, privateKey crypto.PrivateKey) *Manager {
	m := &Manager{
		bundleID:   bundleID,
		teamID:     teamID,
		keyID:      keyID,
		keyStore:   NewKeyStore(),
		privateKey: privateKey,
	}
	m.keyStore.SetDelegate(m)
	return m
}

func NewManagerFromKeyBytes(bundleID, teamID, keyID string, keyBytes []byte) (*Manager, error) {
	// Maybe keyBytes is already DER, not PEM?
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err == nil {
		return NewManager(bundleID, teamID, keyID, key), nil
	}

	for {
		block, rest := pem.Decode(keyBytes)
		if block.Type != "PRIVATE KEY" {
			if rest == nil {
				return nil, ErrInvalidPrivateKey
			}
			continue
		}

		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalidPrivateKey
		}
		return NewManager(bundleID, teamID, keyID, key), nil
	}
}

func NewManagerFromKeyFile(bundleID, teamID, keyID, filename string) (*Manager, error) {
	fileBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewManagerFromKeyBytes(bundleID, teamID, keyID, fileBytes)
}

func (m *Manager) SetDelegate(delegate interface{}) {
	m.delegate = delegate
}

func (m *Manager) NewRequestWithContext(
	ctx context.Context,
	method string,
	url string,
	body io.Reader,
) (*http.Request, error) {
	if p, ok := m.delegate.(HTTPRequestProvider); ok {
		return p.NewRequestWithContext(ctx, method, url, body)
	}
	return http.NewRequestWithContext(ctx, method, url, body)
}

func (m *Manager) VerifyIdentityToken(
	ctx context.Context,
	token string,
	nonce string,
) (*IdentityToken, error) {
	t, err := NewIdentityToken(token)
	if err != nil {
		return nil, err
	}
	if err = t.Verify(ctx, m.keyStore, m.bundleID, nonce); err != nil {
		return nil, err
	}
	return t, nil
}

func (m *Manager) newClientSecret() (string, error) {
	headerData := struct {
		Alg   string `json:"alg"`
		KeyID string `json:"kid"`
	}{
		Alg:   "ES256",
		KeyID: m.keyID,
	}
	header, err := json.Marshal(headerData)
	if err != nil {
		return "", err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)

	now := time.Now()
	payloadData := struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
		Expires  int64  `json:"exp"`
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
	}{
		Issuer:   m.teamID,
		IssuedAt: now.Unix(),
		Expires:  now.Add(30 * 24 * time.Hour).Unix(),
		Audience: expectedIssuer,
		Subject:  m.bundleID,
	}
	payload, err := json.Marshal(payloadData)
	if err != nil {
		return "", err
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)

	data := encodedHeader + "." + encodedPayload
	hash := sha256.Sum256([]byte(data))

	privateKey, ok := m.privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", ErrInvalidPrivateKey
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", err
	}
	signature := append(r.Bytes(), s.Bytes()...)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return data + "." + encodedSignature, nil
}

func (m *Manager) newClientRequest(
	ctx context.Context,
	values url.Values,
) (*http.Request, error) {
	secret, err := m.newClientSecret()
	if err != nil {
		return nil, err
	}
	values.Set("client_id", m.bundleID)
	values.Set("client_secret", secret)
	r := strings.NewReader(values.Encode())

	req, err := m.NewRequestWithContext(ctx, http.MethodPost, appleAuthURL, r)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

func (m *Manager) NewValidateAuthCodeRequest(
	ctx context.Context,
	code string,
	redirectURI string,
) (*http.Request, error) {
	values := url.Values{}
	values.Set("code", code)
	values.Set("grant_type", "authorization_code")
	if redirectURI != "" {
		values.Set("redirectURI", redirectURI)
	}

	return m.newClientRequest(ctx, values)
}

func (m *Manager) NewValidateRefreshTokenRequest(
	ctx context.Context,
	refreshToken string,
) (*http.Request, error) {
	values := url.Values{}
	values.Set("grant_type", "refresh_token")
	values.Set("refresh_token", refreshToken)

	return m.newClientRequest(ctx, values)
}

type TokenResponse struct {
	AccessToken   string `json:"access_token"`
	IdentityToken string `json:"id_token"`
	TokenType     string `json:"token_type"`
	ExpiresIn     int    `json:"expires_in"`
	RefreshToken  string `json:"refresh_token"`
}

type ErrorResponse struct {
	Type        string `json:"error"`
	Description string `json:"error_description"`
}

func (e ErrorResponse) Error() string {
	return fmt.Sprintf("%s: %s", e.Type, e.Description)
}

func (m *Manager) ProcessValidateResponse(
	ctx context.Context,
	nonce string,
	resp *http.Response,
) (*TokenResponse, error) {
	// Note it's the caller's responsibility to close resp.Body
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var r ErrorResponse
		if err = json.Unmarshal(b, &r); err == nil {
			return nil, r
		}
		return nil, ErrInvalidResponse
	}

	var v TokenResponse
	if err = json.Unmarshal(b, &v); err != nil {
		return nil, err
	}

	_, err = m.VerifyIdentityToken(ctx, v.IdentityToken, nonce)
	if err != nil {
		return nil, err
	}

	if v.TokenType != "Bearer" {
		return &v, ErrInvalidResponse
	}
	if v.ExpiresIn < 0 {
		return &v, ErrInvalidResponse
	}

	return &v, nil
}

func (m *Manager) ValidateAuthCode(
	ctx context.Context,
	nonce string,
	code string,
	redirectURI string,
) (*TokenResponse, error) {
	req, err := m.NewValidateAuthCodeRequest(ctx, code, redirectURI)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()

	return m.ProcessValidateResponse(ctx, nonce, resp)
}

func (m *Manager) ValidateRefreshToken(
	ctx context.Context,
	nonce string,
	refreshToken string,
) (*TokenResponse, error) {
	req, err := m.NewValidateRefreshTokenRequest(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()

	return m.ProcessValidateResponse(ctx, nonce, resp)
}

func (m *Manager) NewRevokeTokenRequest(
	ctx context.Context,
	token string,
	tokenType string,
) (*http.Request, error) {
	values := url.Values{}
	values.Set("token", token)
	if tokenType != "" {
		values.Set("token_type_hint", tokenType)
	}

	return m.newClientRequest(ctx, values)
}

func (m *Manager) ProcessRevokeResponse(
	ctx context.Context,
	resp *http.Response,
) error {
	if resp.StatusCode != http.StatusOK {
		return ErrInvalidResponse
	}
	// Note it's the caller's responsibility to close resp.Body
	return nil
}

func (m *Manager) RevokeToken(
	ctx context.Context,
	token string,
	tokenType string,
) error {
	req, err := m.NewRevokeTokenRequest(ctx, token, tokenType)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	return m.ProcessRevokeResponse(ctx, resp)
}
