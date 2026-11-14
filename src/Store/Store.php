<?php

namespace GeneroWP\RateLimiter\Store;

/**
 * Where counters and bans live, each with its own time to live. A store that
 * can't be reached answers as if empty, so the limiter fails open.
 */
interface Store
{
    /**
     * Adds one to $key and returns the new count; the TTL starts with the
     * first. 0 when the store can't count.
     */
    public function increment(string $key, int $ttl): int;

    /** The stored number, or null. */
    public function get(string $key): ?int;

    public function set(string $key, int $value, int $ttl): void;

    public function delete(string $key): void;

    /** Removes every key of the limiter's; the count when known. */
    public function flush(): ?int;

    /** Whether the store needs WordPress loaded (so the check waits for it). */
    public function needsWordPress(): bool;
}
