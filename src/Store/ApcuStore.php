<?php

namespace GeneroWP\RateLimiter\Store;

/**
 * APCu: in the server's memory, shared by its PHP workers (and every site of
 * a network on them), the fastest, and lost on a PHP restart. Doesn't work
 * across servers, and not from WP-CLI unless apc.enable_cli is on.
 */
final class ApcuStore implements Store
{
    public function __construct(private string $prefix = 'gds_rate_limit:') {}

    public static function available(): bool
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    public function increment(string $key, int $ttl): int
    {
        if (! self::available()) {
            return 0;
        }
        // apcu_add creates the key with its TTL only if it's missing, so the
        // window starts at the first request.
        apcu_add($this->prefix.$key, 0, $ttl);
        $count = apcu_inc($this->prefix.$key);

        return $count === false ? 1 : (int) $count;
    }

    public function get(string $key): ?int
    {
        if (! self::available()) {
            return null;
        }
        $value = apcu_fetch($this->prefix.$key, $found);

        return $found ? (int) $value : null;
    }

    public function set(string $key, int $value, int $ttl): void
    {
        if (self::available()) {
            apcu_store($this->prefix.$key, $value, $ttl);
        }
    }

    public function delete(string $key): void
    {
        if (self::available()) {
            apcu_delete($this->prefix.$key);
        }
    }

    public function flush(): ?int
    {
        if (! self::available() || ! class_exists(\APCUIterator::class)) {
            return null;
        }
        $keys = [];
        foreach (new \APCUIterator('/^'.preg_quote($this->prefix, '/').'/', APC_ITER_KEY) as $item) {
            $keys[] = $item['key'];
        }
        if ($keys !== []) {
            apcu_delete($keys);
        }

        return count($keys);
    }

    public function needsWordPress(): bool
    {
        return false;
    }
}
