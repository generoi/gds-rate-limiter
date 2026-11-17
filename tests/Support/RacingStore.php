<?php

namespace GeneroWP\RateLimiter\Tests\Support;

use Closure;
use GeneroWP\RateLimiter\Store\Store;

/**
 * A MemoryStore that runs another request mid-way through one: the first
 * increment of a key matching $race runs $other before it counts, as a worker
 * racing this one would, having read the store before this one wrote it.
 */
final class RacingStore implements Store
{
    private ?Closure $other = null;

    public function __construct(private MemoryStore $store, private string $race) {}

    /** Runs $other once, at the next increment of a key starting with the race's. */
    public function race(Closure $other): void
    {
        $this->other = $other;
    }

    public function increment(string $key, int $ttl): int
    {
        if ($this->other !== null && str_starts_with($key, $this->race)) {
            $other = $this->other;
            $this->other = null;
            $other();
        }

        return $this->store->increment($key, $ttl);
    }

    public function get(string $key): ?int
    {
        return $this->store->get($key);
    }

    public function getMany(array $keys): array
    {
        return $this->store->getMany($keys);
    }

    public function set(string $key, int $value, int $ttl): void
    {
        $this->store->set($key, $value, $ttl);
    }

    public function delete(string $key): void
    {
        $this->store->delete($key);
    }

    public function flush(): ?int
    {
        return $this->store->flush();
    }

    public function needsWordPress(): bool
    {
        return $this->store->needsWordPress();
    }
}
