package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/goware/cachestore"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// operationKeySet is a jwk.Set valid only for a single request.
// It is not thread safe and should not be stored. Instead, it must be discarded after every operation.
type operationKeySet struct {
	ctx       context.Context
	iss       string
	store     cachestore.Store[jwk.Key]
	getKeySet func(ctx context.Context, iss string) (jwk.Set, error)

	cachedSet jwk.Set
}

func (ks *operationKeySet) LookupKeyID(s string) (jwk.Key, bool) {
	ttl := 1 * time.Hour
	getter := func(ctx context.Context, _ string) (jwk.Key, error) {
		key, ok := ks.getCachedSet(ctx).LookupKeyID(s)
		if !ok {
			return nil, fmt.Errorf("key not found")
		}
		return key, nil
	}

	key, err := ks.store.GetOrSetWithLockEx(ks.ctx, ks.iss+"#"+s, getter, ttl)
	if err != nil {
		return nil, false
	}
	return key, true
}

func (ks *operationKeySet) AddKey(key jwk.Key) error {
	return fmt.Errorf("operationKeySet is immutable")
}

func (ks *operationKeySet) Clear() error {
	return fmt.Errorf("operationKeySet is immutable")
}

func (ks *operationKeySet) Key(i int) (jwk.Key, bool) {
	return ks.getCachedSet(ks.ctx).Key(i)
}

func (ks *operationKeySet) Get(s string) (interface{}, bool) {
	return ks.getCachedSet(ks.ctx).Get(s)
}

func (ks *operationKeySet) Set(s string, i interface{}) error {
	return fmt.Errorf("operationKeySet is immutable")
}

func (ks *operationKeySet) Remove(s string) error {
	return fmt.Errorf("operationKeySet is immutable")
}

func (ks *operationKeySet) Index(key jwk.Key) int {
	return ks.getCachedSet(ks.ctx).Index(key)
}

func (ks *operationKeySet) Len() int {
	return ks.getCachedSet(ks.ctx).Len()
}

func (ks *operationKeySet) RemoveKey(key jwk.Key) error {
	return fmt.Errorf("operationKeySet is immutable")
}

func (ks *operationKeySet) Keys(ctx context.Context) jwk.KeyIterator {
	return ks.getCachedSet(ks.ctx).Keys(ctx)
}

func (ks *operationKeySet) Iterate(ctx context.Context) jwk.HeaderIterator {
	return ks.getCachedSet(ks.ctx).Iterate(ctx)
}

func (ks *operationKeySet) Clone() (jwk.Set, error) {
	return ks.getCachedSet(ks.ctx).Clone()
}

func (ks *operationKeySet) getCachedSet(ctx context.Context) jwk.Set {
	set, err := ks.getKeySet(ctx, ks.iss)
	if err != nil {
		return jwk.NewSet()
	}
	ks.cachedSet = set
	return set
}

var _ jwk.Set = (*operationKeySet)(nil)
