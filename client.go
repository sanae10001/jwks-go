package jwks

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/square/go-jose.v2"
)

func New(source JWKSSource) *JWKSClient {
	return &JWKSClient{source: source}
}

type JWKSClient struct {
	source JWKSSource
}

// Set a custom jwks source
func (c *JWKSClient) SetJWKSSource(source JWKSSource) {
	c.source = source
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
	return c.GetUseKey(kid, "sig")
}

func (c *JWKSClient) GetEncryptionKey(kid string) (*jose.JSONWebKey, error) {
	return c.GetUseKey(kid, "enc")
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
