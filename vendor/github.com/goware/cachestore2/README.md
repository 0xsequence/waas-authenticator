# cachestore

The `cachestore` package provides a generic caching interfaces with different
backends.

Please see https://github.com/goware/cachestore-examples for example usage.

Cachestore is designed to work with pluggable backends, currently supported:
* `memcache`: in-memory lru cache -- https://github.com/goware/cachestore-mem
* `rediscache`: redis cache -- https://github.com/goware/cachestore-redis
* (TODO) `gcloudcache`: gcloud storage bucket backend -- https://github.com/goware/cachestore-gcloud

## LICENSE

Copyright (c) 2021-present [Sequence Platforms Inc](https://sequence.xyz).

Licensed under [Apache-2.0](./LICENSE)
