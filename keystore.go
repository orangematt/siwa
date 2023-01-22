// (c) Copyright 2023 Matt Messier

package siwa

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const authKeysURL = "https://appleid.apple.com/auth/keys"

const AuthKeysFetchFrequency = 5 * time.Minute

type PublicKey struct {
	KeyType string `json:"kty"`
	KeyID   string `json:"kid"`
	Use     string `json:"use"`
	Alg     string `json:"alg"`
	N       string `json:"n"`
	E       string `json:"e"`

	rsa *rsa.PublicKey
}

func (k *PublicKey) RSA() (*rsa.PublicKey, error) {
	if k.rsa == nil {
		N, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		E, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}

		key := &rsa.PublicKey{}
		key.N = new(big.Int)
		key.N.SetBytes(N)
		for _, v := range E {
			key.E = (key.E << 8) | int(v)
		}
		k.rsa = key
	}
	return k.rsa, nil
}

type KeyStore struct {
	lock             sync.Mutex
	cond             sync.Cond
	keys             []PublicKey
	lastRefresh      time.Time
	lastRefreshError error
	refreshing       bool
	delegate         interface{}
}

func NewKeyStore() *KeyStore {
	return &KeyStore{}
}

func (s *KeyStore) SetDelegate(delegate interface{}) {
	s.delegate = delegate
}

func (s *KeyStore) NewRequestWithContext(
	ctx context.Context,
	method string,
	url string,
	body io.Reader,
) (*http.Request, error) {
	if p, ok := s.delegate.(HTTPRequestProvider); ok {
		return p.NewRequestWithContext(ctx, method, url, body)
	}
	return http.NewRequestWithContext(ctx, method, url, body)
}

func (s *KeyStore) RefreshPublicKeys(ctx context.Context) (err error) {
	s.lock.Lock()
	if s.refreshing {
		defer s.lock.Unlock()
		for s.refreshing {
			s.cond.Wait()
		}
		return s.lastRefreshError
	}
	s.refreshing = true
	s.lock.Unlock()

	defer func() {
		s.lock.Lock()
		s.lastRefreshError = err
		s.refreshing = false
		s.cond.Broadcast()
		s.lock.Unlock()
	}()

	req, err := s.NewRequestWithContext(ctx, http.MethodGet, authKeysURL, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil || len(data) == 0 {
		return nil
	}

	var jsonKeys struct {
		Keys []PublicKey `json:"keys"`
	}
	if err = json.Unmarshal(data, &jsonKeys); err != nil {
		return err
	}

	s.lock.Lock()
	s.keys = jsonKeys.Keys
	s.lastRefresh = time.Now()
	s.lock.Unlock()

	return
}

func (s *KeyStore) MaybeRefreshPublicKeys(
	ctx context.Context,
	freq time.Duration,
) (bool, error) {
	if time.Now().Sub(s.lastRefresh) < freq {
		return false, nil
	}
	return true, s.RefreshPublicKeys(ctx)
}

func (s *KeyStore) GetPublicKey(kid, alg, use string) (*rsa.PublicKey, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, key := range s.keys {
		if key.KeyID != kid {
			continue
		}
		if alg != "" && key.Alg != alg {
			continue
		}
		if use != "" && key.Use != use {
			continue
		}
		if k, err := key.RSA(); err == nil {
			return k, true
		}
	}

	return nil, false
}
