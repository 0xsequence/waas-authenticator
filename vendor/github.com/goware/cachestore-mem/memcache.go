package memcache

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/elastic/go-freelru"
	cachestore "github.com/goware/cachestore2"
	"github.com/goware/singleflight"
	"github.com/zeebo/xxh3"
)

func NewBackend(size uint32, opts ...cachestore.StoreOptions) (cachestore.Backend, error) {
	return NewCacheWithSize[any](size, opts...)
}

func NewCache[V any](opts ...cachestore.StoreOptions) (cachestore.Store[V], error) {
	const defaultLRUSize = 512
	return NewCacheWithSize[V](defaultLRUSize, opts...)
}

func NewCacheWithSize[V any](size uint32, opts ...cachestore.StoreOptions) (*MemLRU[V], error) {
	if size == 0 {
		return nil, errors.New("cachestore-mem: size cannot be 0")
	}

	maxShards := uint32(runtime.NumCPU() * 16)                           // ie. 16*16=256
	minShards := max(1, uint32(float64(size)/float64(runtime.NumCPU()))) // ie. 512/16=32

	var shards uint32
	if size <= maxShards*2 {
		shards = minShards
	} else {
		shards = maxShards
	}

	capacity := uint32(float64(size) * 1.25)
	lru, err := freelru.NewShardedWithSize[string, V](shards, size, capacity, hashStringXXH3)
	if err != nil {
		return nil, err
	}

	options := cachestore.ApplyOptions(opts...)
	if options.LockRetryTimeout == 0 {
		options.LockRetryTimeout = 8 * time.Second
	}

	memLRU := &MemLRU[V]{
		options: options,
		lru:     lru,
	}

	return memLRU, nil
}

func hashStringXXH3(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

type MemLRU[V any] struct {
	options      cachestore.StoreOptions
	lru          *freelru.ShardedLRU[string, V]
	singleflight singleflight.Group[string, V]
}

var _ cachestore.Store[any] = &MemLRU[any]{}

func (m *MemLRU[V]) Name() string {
	return "memcache"
}

func (m *MemLRU[V]) Options() cachestore.StoreOptions {
	return m.options
}

func (m *MemLRU[V]) Exists(ctx context.Context, key string) (bool, error) {
	_, exists := m.lru.Peek(key)
	return exists, nil
}

func (m *MemLRU[V]) Set(ctx context.Context, key string, value V) error {
	// note: m.options.DefaultKeyExpiry is 0, so this is the same as SetEx with ttl=0
	// which means the key will not expire, and will only be evicted when it is removed
	// from the lru cache.
	return m.SetEx(ctx, key, value, m.options.DefaultKeyExpiry)
}

func (m *MemLRU[V]) SetEx(ctx context.Context, key string, value V, ttl time.Duration) error {
	if err := m.setKeyValue(key, value, ttl); err != nil {
		return err
	}
	return nil
}

func (m *MemLRU[V]) BatchSet(ctx context.Context, keys []string, values []V) error {
	return m.BatchSetEx(ctx, keys, values, m.options.DefaultKeyExpiry)
}

func (m *MemLRU[V]) BatchSetEx(ctx context.Context, keys []string, values []V, ttl time.Duration) error {
	if len(keys) != len(values) {
		return errors.New("cachestore-mem: keys and values are not the same length")
	}
	if len(keys) == 0 {
		return errors.New("cachestore-mem: no keys are passed")
	}
	for i, key := range keys {
		m.setKeyValue(key, values[i], ttl)
	}
	return nil
}

func (m *MemLRU[V]) Get(ctx context.Context, key string) (V, bool, error) {
	var out V
	v, ok := m.lru.Get(key)

	if !ok {
		// key not found, respond with no data
		return out, false, nil
	}

	return v, true, nil
}

func (m *MemLRU[V]) BatchGet(ctx context.Context, keys []string) ([]V, []bool, error) {
	vals := make([]V, 0, len(keys))
	oks := make([]bool, 0, len(keys))
	var out V

	for _, key := range keys {
		v, ok := m.lru.Get(key)
		if !ok {
			// key not found, add empty/default value
			vals = append(vals, out)
			oks = append(oks, false)
			continue
		}

		vals = append(vals, v)
		oks = append(oks, true)
	}

	return vals, oks, nil
}

func (m *MemLRU[V]) Delete(ctx context.Context, key string) error {
	present := m.lru.Remove(key)

	// NOTE/TODO: we do not check for presence, prob okay
	_ = present
	return nil
}

func (m *MemLRU[V]) DeletePrefix(ctx context.Context, keyPrefix string) error {
	for _, key := range m.lru.Keys() {
		if strings.HasPrefix(key, keyPrefix) {
			m.lru.Remove(key)
		}
	}
	return nil
}

func (m *MemLRU[V]) ClearAll(ctx context.Context) error {
	m.lru.Purge()
	return nil
}

func (m *MemLRU[V]) GetOrSetWithLock(ctx context.Context, key string, getter func(context.Context, string) (V, error)) (V, error) {
	return m.GetOrSetWithLockEx(ctx, key, getter, m.options.DefaultKeyExpiry)
}

func (m *MemLRU[V]) GetOrSetWithLockEx(
	ctx context.Context, key string, getter func(context.Context, string) (V, error), ttl time.Duration,
) (V, error) {
	var out V

	ctx, cancel := context.WithTimeout(ctx, m.options.LockRetryTimeout)
	defer cancel()

	v, ok := m.lru.Get(key)
	if ok {
		return v, nil
	}

	v, err, _ := m.singleflight.Do(key, func() (V, error) {
		v, err := getter(ctx, key)
		if err != nil {
			return out, fmt.Errorf("cachestore-mem: getter error: %w", err)
		}
		if err := m.setKeyValue(key, v, ttl); err != nil {
			return out, err
		}
		return v, nil
	})
	if err != nil {
		return out, fmt.Errorf("cachestore-mem: singleflight error: %w", err)
	}

	return v, nil
}

func (m *MemLRU[V]) setKeyValue(key string, value V, ttl time.Duration) error {
	if len(key) > cachestore.MaxKeyLength {
		return cachestore.ErrKeyLengthTooLong
	}
	if len(key) == 0 {
		return cachestore.ErrInvalidKey
	}
	if ttl > 0 {
		m.lru.AddWithLifetime(key, value, ttl)
	} else {
		m.lru.Add(key, value)
	}
	return nil
}
