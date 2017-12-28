package jwks

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/patrickmn/go-cache"
	"gopkg.in/square/go-jose.v2"
)

func New(source JWKSSource) *JWKSClient {
	return &JWKSClient{
		source: source,
		cache:  DefaultCache(),
	}
}

type JWKSClient struct {
	source JWKSSource
	cache  LocalCache
}

// Set a custom jwks source
func (c *JWKSClient) SetJWKSSource(source JWKSSource) {
	c.source = source
}

// Set a custom local cache
func (c *JWKSClient) SetLocalCache(cache LocalCache) {
	c.cache = cache
}

func (c *JWKSClient) GetUseKey(kid, use string) (*jose.JSONWebKey, error) {
	jwks, err := c.source.JSONWebKeySet()
	if err != nil {
		return nil, err
	}
	jwkList := jwks.Key(kid)
	if len(jwkList) == 0 {
		return nil, fmt.Errorf("not found a jwk that matches '%s'", kid)
	}

	// Filter key
	for _, jwk := range jwkList {
		if jwk.Use == use && jwk.IsPublic() && jwk.Valid() {
			return &jwk, nil
		}
	}
	return nil, fmt.Errorf("not found a jwk contains valid public-key, used to '%s'", use)
}

func (c *JWKSClient) GetSignatureKey(kid string) (*jose.JSONWebKey, error) {
	value, existed := c.cache.Get(kid)
	if existed {
		return value.(*jose.JSONWebKey), nil
	}
	jwk, err := c.GetUseKey(kid, "sig")
	if err != nil {
		return nil, err
	}
	c.cache.Set(kid, jwk, cache.DefaultExpiration)
	return jwk, nil
}

func (c *JWKSClient) GetEncryptionKey(kid string) (*jose.JSONWebKey, error) {
	value, existed := c.cache.Get(kid)
	if existed {
		return value.(*jose.JSONWebKey), nil
	}
	jwk, err := c.GetUseKey(kid, "enc")
	if err != nil {
		return nil, err
	}
	c.cache.Set(kid, jwk, cache.DefaultExpiration)
	return jwk, nil
}

func (c *JWKSClient) JWTKeyFunc() jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("not found a kid in jwt header")
		}

		jwk, err := c.GetSignatureKey(kid)
		if err != nil {
			return nil, err
		}

		// Check algorithm
		if token.Method.Alg() != jwk.Algorithm {
			return nil, fmt.Errorf("unexpected jwt signing method=%s", token.Method.Alg())
		}

		return jwk.Key, nil
	}
}
