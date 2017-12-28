package jwks

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"gopkg.in/square/go-jose.v2"
)

type JWKSSource interface {
	JSONWebKeySet() (*jose.JSONWebKeySet, error)
}

func MustValidEndpointSource(jwksUri string) *EndpointSource {
	s := NewEndpointSource(jwksUri)
	_, err := s.JSONWebKeySet()
	if err != nil {
		log.Panic(err)
	}
	return s
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
}

func (s *EndpointSource) JSONWebKeySet() (*jose.JSONWebKeySet, error) {
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

func MustValidFileSource(filePath string) *FileSource {
	s := NewFileSource(filePath)
	_, err := s.JSONWebKeySet()
	if err != nil {
		log.Panic(err)
	}
	return s
}

func NewFileSource(filePath string) *FileSource {
	return &FileSource{filePath: filePath}
}

type FileSource struct {
	filePath string
}

func (s *FileSource) JSONWebKeySet() (*jose.JSONWebKeySet, error) {
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
