<?php

namespace GeneroWP\RateLimiter\Store;

/**
 * Redis through the phpredis extension: shared across servers. It connects
 * on first use, with a short timeout, and a Redis that can't be reached
 * leaves requests unlimited.
 */
final class RedisStore implements Store
{
    private ?\Redis $redis;

    private bool $failed = false;

    public function __construct(
        private string $host = '127.0.0.1',
        private int $port = 6379,
        private ?string $password = null,
        private int $database = 0,
        private float $timeout = 0.5,
        private string $prefix = 'gds_rate_limit:',
        ?\Redis $client = null,
    ) {
        $this->redis = $client;
    }

    public function increment(string $key, int $ttl): int
    {
        $redis = $this->redis();
        if ($redis === null) {
            return 0;
        }
        try {
            // Created with its TTL in one command, then counted (INCR keeps
            // the TTL): a key can never be left without one.
            $redis->set($this->prefix.$key, '0', ['nx', 'ex' => max(1, $ttl)]);

            return (int) $redis->incr($this->prefix.$key);
        } catch (\RedisException) {
            return 0;
        }
    }

    public function get(string $key): ?int
    {
        $redis = $this->redis();
        if ($redis === null) {
            return null;
        }
        try {
            $value = $redis->get($this->prefix.$key);

            return $value === false || $value === null ? null : (int) $value;
        } catch (\RedisException) {
            return null;
        }
    }

    public function set(string $key, int $value, int $ttl): void
    {
        $redis = $this->redis();
        if ($redis === null) {
            return;
        }
        try {
            $redis->setex($this->prefix.$key, max(1, $ttl), (string) $value);
        } catch (\RedisException) {
        }
    }

    public function delete(string $key): void
    {
        $redis = $this->redis();
        if ($redis === null) {
            return;
        }
        try {
            $redis->del($this->prefix.$key);
        } catch (\RedisException) {
        }
    }

    public function flush(): ?int
    {
        $redis = $this->redis();
        if ($redis === null) {
            return null;
        }
        try {
            $deleted = 0;
            $cursor = null;
            do {
                $keys = $redis->scan($cursor, $this->prefix.'*', 500);
                if (is_array($keys) && $keys !== []) {
                    $deleted += (int) $redis->del($keys);
                }
            } while ($cursor !== 0 && $cursor !== null);

            return $deleted;
        } catch (\RedisException) {
            return null;
        }
    }

    public function needsWordPress(): bool
    {
        return false;
    }

    private function redis(): ?\Redis
    {
        if ($this->redis !== null || $this->failed) {
            return $this->redis;
        }
        if (! class_exists(\Redis::class)) {
            $this->failed = true;

            return null;
        }
        try {
            $redis = new \Redis;
            $redis->connect($this->host, $this->port, $this->timeout);
            if ($this->password !== null && $this->password !== '') {
                $redis->auth($this->password);
            }
            if ($this->database !== 0) {
                $redis->select($this->database);
            }
            $this->redis = $redis;
        } catch (\RedisException) {
            $this->failed = true;
        }

        return $this->redis;
    }
}
