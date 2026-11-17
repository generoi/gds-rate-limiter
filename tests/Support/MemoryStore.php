<?php

namespace GeneroWP\RateLimiter\Tests\Support;

use Closure;
use GeneroWP\RateLimiter\Store\Store;

/**
 * A store in an array, with its TTLs on the tests' clock.
 */
final class MemoryStore implements Store
{
    /** @var array<string,array{int,int}> key => [value, expires] */
    public array $items = [];

    public function __construct(private Closure $clock, private bool $needsWordPress = false) {}

    public function increment(string $key, int $ttl): int
    {
        $value = $this->get($key);
        if ($value === null) {
            $this->items[$key] = [1, ($this->clock)() + $ttl];

            return 1;
        }
        $this->items[$key][0] = $value + 1;

        return $value + 1;
    }

    public function get(string $key): ?int
    {
        if (! isset($this->items[$key]) || $this->items[$key][1] <= ($this->clock)()) {
            unset($this->items[$key]);

            return null;
        }

        return $this->items[$key][0];
    }

    public function getMany(array $keys): array
    {
        $out = [];
        foreach ($keys as $key) {
            $out[$key] = $this->get($key);
        }

        return $out;
    }

    public function set(string $key, int $value, int $ttl): void
    {
        $this->items[$key] = [$value, ($this->clock)() + $ttl];
    }

    public function delete(string $key): void
    {
        unset($this->items[$key]);
    }

    public function flush(): ?int
    {
        $count = count($this->items);
        $this->items = [];

        return $count;
    }

    public function needsWordPress(): bool
    {
        return $this->needsWordPress;
    }
}
