package jwks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const (
	defaultExpiration = 24 * time.Hour
)

type JWKSSource interface {
	JSONWebKeySet() (*jose.JSONWebKeySet, error)
}

func NewEndpointSource(jwksUri string) *EndpointSource {
	return &EndpointSource{
		client:  new(http.Client),
		jwksUri: jwksUri,
	}
}

type EndpointSource struct {
	client  *http.Client
	jwksUri string
	mu      sync.Mutex

	jwks         *jose.JSONWebKeySet
	expirationAt int64
}

func (s *EndpointSource) JSONWebKeySet() (*jose.JSONWebKeySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jwks == nil || time.Now().UnixNano() > s.expirationAt {
		var err error
		s.jwks, err = s.load()
		if err != nil {
			return nil, err
		}
		s.expirationAt = time.Now().Add(defaultExpiration).UnixNano()
	}
	return s.jwks, nil
}

func (s *EndpointSource) load() (*jose.JSONWebKeySet, error) {
	resp, err := s.client.Get(s.jwksUri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed request, status: %d", resp.StatusCode)
	}

	jwks := new(jose.JSONWebKeySet)
	if err = json.NewDecoder(resp.Body).Decode(jwks); err != nil {
		return nil, err
	}
	return jwks, err
}

func NewFileSource(filePath string) *FileSource {
	return &FileSource{filePath: filePath}
}

type FileSource struct {
	filePath string
	mu       sync.Mutex

	jwks         *jose.JSONWebKeySet
	expirationAt int64
}

func (s *FileSource) JSONWebKeySet() (*jose.JSONWebKeySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jwks == nil || time.Now().UnixNano() > s.expirationAt {
		var err error
		s.jwks, err = s.load()
		if err != nil {
			return nil, err
		}
		s.expirationAt = time.Now().Add(defaultExpiration).UnixNano()
	}
	return s.jwks, nil
}

func (s *FileSource) load() (*jose.JSONWebKeySet, error) {
	f, err := os.Open(s.filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	jwks := new(jose.JSONWebKeySet)
	if err = json.NewDecoder(f).Decode(jwks); err != nil {
		return nil, err
	}
	return jwks, nil
}
