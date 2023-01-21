// (c) Copyright 2023 Matt Messier

package siwa

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
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
}

func NewKeyStore() *KeyStore {
	return &KeyStore{}
}

func (c *KeyStore) RefreshPublicKeys() (err error) {
	c.lock.Lock()
	if c.refreshing {
		defer c.lock.Unlock()
		for c.refreshing {
			c.cond.Wait()
		}
		return c.lastRefreshError
	}
	c.refreshing = true
	c.lock.Unlock()

	defer func() {
		c.lock.Lock()
		c.lastRefreshError = err
		c.refreshing = false
		c.cond.Broadcast()
		c.lock.Unlock()
	}()

	req, err := http.NewRequest(http.MethodGet, authKeysURL, nil)
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

	c.lock.Lock()
	c.keys = jsonKeys.Keys
	c.lastRefresh = time.Now()
	c.lock.Unlock()

	return
}

func (c *KeyStore) MaybeRefreshPublicKeys(freq time.Duration) (bool, error) {
	if time.Now().Sub(c.lastRefresh) < freq {
		return false, nil
	}
	return true, c.RefreshPublicKeys()
}

func (c *KeyStore) GetPublicKey(kid, alg, use string) (*rsa.PublicKey, bool) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for _, key := range c.keys {
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
