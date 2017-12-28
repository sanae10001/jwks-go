package jwks

import (
	"time"

	"github.com/patrickmn/go-cache"
)

type LocalCache interface {
	Get(k string) (interface{}, bool)
	Set(k string, x interface{}, d time.Duration)
}

func DefaultCache() LocalCache {
	return cache.New(23*time.Hour, 24*time.Hour)
}
