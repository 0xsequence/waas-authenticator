package cachestore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type Backend interface {
	Store[any]
}

func OpenStore[T any](backend Backend, opts ...StoreOptions) Store[T] {
	options := backend.Options()
	if len(opts) > 0 {
		options = ApplyOptions(opts...)
	}

	store, ok := backend.(Store[any])
	if !ok {
		// NOTE: we return a nil store here, so that the caller can
		// check if the store is nil and return an error. Alternatively,
		// we could update OpenStore() to return a concrete error, but
		// this is more flexible.
		return &backendAdapter[T]{anyStore: nil, options: options}
	} else {
		// return a new backend adapter which is an adapter for a
		// Store[any] to a Store[T]. You may also pass in new store
		// options to the adapter when you open the store from a backend,
		// or use the existing options on the backend.
		return newBackendAdapter[T](store, options)
	}
}

var ErrBackendAdapterNil = fmt.Errorf("cachestore: backend adapter is nil")
var ErrBackendTypeCast = fmt.Errorf("cachestore: backend type cast failure")

func newBackendAdapter[T any](anyStore Store[any], options StoreOptions) Store[T] {
	adapter := &backendAdapter[T]{
		anyStore: anyStore,
		options:  options,
	}
	return adapter
}

type backendAdapter[T any] struct {
	anyStore Store[any]
	options  StoreOptions
}

func (s *backendAdapter[T]) Name() string {
	if s.anyStore == nil {
		return ""
	}
	return s.anyStore.Name()
}

func (s *backendAdapter[T]) Options() StoreOptions {
	return s.options
}

func (s *backendAdapter[T]) Exists(ctx context.Context, key string) (bool, error) {
	if s.anyStore == nil {
		return false, ErrBackendAdapterNil
	}
	return s.anyStore.Exists(ctx, key)
}

func (s *backendAdapter[T]) Set(ctx context.Context, key string, value T) error {
	return s.SetEx(ctx, key, value, s.options.DefaultKeyExpiry)
}

func (s *backendAdapter[T]) SetEx(ctx context.Context, key string, value T, ttl time.Duration) error {
	if s.anyStore == nil {
		return ErrBackendAdapterNil
	}

	// See comments in Get()
	bs, ok := s.anyStore.(ByteStoreGetter)
	if ok {
		byteStore := bs.ByteStore()

		serialized, err := Serialize(value)
		if err != nil {
			return err
		}

		return byteStore.SetEx(ctx, key, serialized, ttl)
	} else {
		return s.anyStore.SetEx(ctx, key, value, ttl)
	}
}

func (s *backendAdapter[T]) BatchSet(ctx context.Context, keys []string, values []T) error {
	return s.BatchSetEx(ctx, keys, values, s.options.DefaultKeyExpiry)
}

func (s *backendAdapter[T]) BatchSetEx(ctx context.Context, keys []string, values []T, ttl time.Duration) error {
	if s.anyStore == nil {
		return ErrBackendAdapterNil
	}

	bs, ok := s.anyStore.(ByteStoreGetter)
	if ok {
		byteStore := bs.ByteStore()

		vs := make([][]byte, len(values))
		for i, v := range values {
			serialized, err := Serialize(v)
			if err != nil {
				return err
			}
			vs[i] = serialized
		}

		return byteStore.BatchSetEx(ctx, keys, vs, s.options.DefaultKeyExpiry)
	} else {
		vs := make([]any, len(values))
		for i := 0; i < len(vs); i++ {
			vs[i] = values[i]
		}
		return s.anyStore.BatchSetEx(ctx, keys, vs, s.options.DefaultKeyExpiry)
	}
}

func (s *backendAdapter[T]) Get(ctx context.Context, key string) (T, bool, error) {
	var v T

	if s.anyStore == nil {
		return v, false, ErrBackendAdapterNil
	}

	bs, ok := s.anyStore.(ByteStoreGetter)
	if ok {
		// If the underlining store implements ByteStoreGetter,
		// then we assume the Get will return []byte types, and we will
		// handle serialization here. This is used by cachestore-redis
		// and all other external stores.
		byteStore := bs.ByteStore()

		bv, ok, err := byteStore.Get(ctx, key)
		if err != nil {
			return v, false, err
		}
		if !ok {
			return v, false, nil
		}

		deserialized, err := Deserialize[T](bv)
		if err != nil {
			return v, false, err
		}
		return deserialized, true, nil
	} else {
		// Otherwise, we just use the underlying store's Get method,
		// and type cast to the generic type. This is used by cachestore-mem.
		bv, ok, err := s.anyStore.Get(ctx, key)
		if err != nil {
			return v, ok, err
		}
		if !ok {
			return v, false, nil
		}
		v, ok = bv.(T)
		if !ok {
			// should not happen, but just in case
			return v, false, fmt.Errorf("cachestore: failed to cast value to type %T: %w", v, ErrBackendTypeCast)
		}
		return v, ok, nil
	}
}

func (s *backendAdapter[T]) BatchGet(ctx context.Context, keys []string) ([]T, []bool, error) {
	vs := make([]T, len(keys))
	exists := make([]bool, len(keys))

	if s.anyStore == nil {
		return vs, exists, ErrBackendAdapterNil
	}

	bs, ok := s.anyStore.(ByteStoreGetter)
	if ok {
		byteStore := bs.ByteStore()

		bvs, exists, err := byteStore.BatchGet(ctx, keys)
		if err != nil {
			return vs, exists, err
		}

		for i, v := range bvs {
			if !exists[i] {
				continue
			}

			deserialized, err := Deserialize[T](v)
			if err != nil {
				return vs, exists, err
			}
			vs[i] = deserialized
		}

		return vs, exists, nil
	} else {
		bvs, exists, err := s.anyStore.BatchGet(ctx, keys)
		if err != nil {
			return vs, exists, err
		}

		var ok bool
		for i, v := range bvs {
			if !exists[i] {
				continue
			}
			vs[i], ok = v.(T)
			if !ok {
				// should not happen, but just in case
				return vs, exists, fmt.Errorf("cachestore: failed to cast value to type %T: %w", v, ErrBackendTypeCast)
			}
		}

		return vs, exists, nil
	}
}

func (s *backendAdapter[T]) Delete(ctx context.Context, key string) error {
	if s.anyStore == nil {
		return ErrBackendAdapterNil
	}
	return s.anyStore.Delete(ctx, key)
}

func (s *backendAdapter[T]) DeletePrefix(ctx context.Context, keyPrefix string) error {
	if s.anyStore == nil {
		return ErrBackendAdapterNil
	}
	return s.anyStore.DeletePrefix(ctx, keyPrefix)
}

func (s *backendAdapter[T]) ClearAll(ctx context.Context) error {
	if s.anyStore == nil {
		return ErrBackendAdapterNil
	}
	return s.anyStore.ClearAll(ctx)
}

func (s *backendAdapter[T]) GetOrSetWithLock(ctx context.Context, key string, getter func(context.Context, string) (T, error)) (T, error) {
	return s.GetOrSetWithLockEx(ctx, key, getter, s.options.DefaultKeyExpiry)
}

func (s *backendAdapter[T]) GetOrSetWithLockEx(ctx context.Context, key string, getter func(context.Context, string) (T, error), ttl time.Duration) (T, error) {
	var v T
	if s.anyStore == nil {
		return v, ErrBackendAdapterNil
	}

	bs, ok := s.anyStore.(ByteStoreGetter)
	if ok {
		byteStore := bs.ByteStore()

		g := func(ctx context.Context, key string) ([]byte, error) {
			bv, err := getter(ctx, key)
			if err != nil {
				return nil, err
			}
			return Serialize(bv)
		}

		serialized, err := byteStore.GetOrSetWithLockEx(ctx, key, g, ttl)
		if err != nil {
			return v, err
		}

		deserialized, err := Deserialize[T](serialized)
		if err != nil {
			return v, err
		}
		return deserialized, nil

	} else {
		g := func(ctx context.Context, key string) (any, error) {
			v, err := getter(ctx, key)
			if err != nil {
				return nil, err
			}
			return v, nil
		}

		bv, err := s.anyStore.GetOrSetWithLockEx(ctx, key, g, ttl)
		if err != nil {
			return v, err
		}
		v, ok := bv.(T)
		if !ok {
			return v, fmt.Errorf("cachestore: failed to cast value to type %T: %w", v, ErrBackendTypeCast)
		}
		return v, nil
	}
}

func Serialize[V any](value V) ([]byte, error) {
	switch v := any(value).(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	default:
		out, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("cachestore: failed to marshal data: %w", err)
		}
		return out, nil
	}
}

func Deserialize[V any](data []byte) (V, error) {
	var out V
	switch any(out).(type) {
	case string:
		str := string(data)
		out = any(str).(V)
		return out, nil
	case []byte:
		out = any(data).(V)
		return out, nil
	default:
		err := json.Unmarshal(data, &out)
		if err != nil {
			return out, fmt.Errorf("cachestore: failed to unmarshal data: %w", err)
		}
		return out, nil
	}
}
