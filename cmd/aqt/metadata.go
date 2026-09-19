// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "fmt"

// cachedMetadataFetcher shares memory and disk caching across tree levels.
// Only verified ciphertext enters the cache; access rules belong to fetch.
func cachedMetadataFetcher(seed map[string][]byte, fetch func([]string) (map[string][]byte, error)) func([]string) (map[string][]byte, error) {
	cache := make(map[string][]byte, len(seed))
	for id, ct := range seed {
		cache[id] = ct
	}
	disk := openNodeCache()
	return func(ids []string) (map[string][]byte, error) {
		var missing []string
		for _, id := range ids {
			if _, ok := cache[id]; ok {
				continue
			}
			if ct, ok := disk.get(id); ok {
				cache[id] = ct
				continue
			}
			missing = append(missing, id)
		}
		if len(missing) > 0 {
			found, err := fetch(missing)
			if err != nil {
				return nil, err
			}
			for _, id := range missing {
				ct, ok := found[id]
				if !ok {
					return nil, fmt.Errorf("metadata object %s was not returned", id)
				}
				if err := verifyFrame(id, ct); err != nil {
					return nil, err
				}
				cache[id] = ct
				disk.put(id, ct)
			}
		}
		out := make(map[string][]byte, len(ids))
		for _, id := range ids {
			if ct, ok := cache[id]; ok {
				out[id] = ct
			}
		}
		return out, nil
	}
}
