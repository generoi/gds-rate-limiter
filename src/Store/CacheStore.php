<?php

namespace GeneroWP\RateLimiter\Store;

/**
 * WordPress's object cache when it's persistent (Redis or Memcached through
 * a drop-in), else transients in the database. Needs WordPress, so the check
 * runs once plugins have loaded, not before WordPress. Transient counts
 * aren't atomic: under a burst a few requests can slip through.
 */
final class CacheStore implements Store
{
    public const GROUP = 'gds_rate_limit';

    public function increment(string $key, int $ttl): int
    {
        if (wp_using_ext_object_cache()) {
            $count = wp_cache_incr($key, 1, self::GROUP);
            if ($count === false) {
                wp_cache_add($key, 0, self::GROUP, $ttl);
                $count = wp_cache_incr($key, 1, self::GROUP);
            }

            return $count === false ? 1 : (int) $count;
        }

        $count = (int) ($this->get($key) ?? 0) + 1;
        if ($count === 1) {
            set_transient(self::GROUP.':'.$key, $count, $ttl);
        } else {
            // Keep the window's end: update the value, not its timeout.
            update_option('_transient_'.self::GROUP.':'.$key, $count, false);
        }

        return $count;
    }

    public function get(string $key): ?int
    {
        $value = wp_using_ext_object_cache()
            ? wp_cache_get($key, self::GROUP)
            : get_transient(self::GROUP.':'.$key);

        return $value === false ? null : (int) $value;
    }

    public function set(string $key, int $value, int $ttl): void
    {
        if (wp_using_ext_object_cache()) {
            wp_cache_set($key, $value, self::GROUP, $ttl);

            return;
        }
        set_transient(self::GROUP.':'.$key, $value, $ttl);
    }

    public function delete(string $key): void
    {
        if (wp_using_ext_object_cache()) {
            wp_cache_delete($key, self::GROUP);

            return;
        }
        delete_transient(self::GROUP.':'.$key);
    }

    public function flush(): ?int
    {
        if (wp_using_ext_object_cache()) {
            if (function_exists('wp_cache_supports') && wp_cache_supports('flush_group')) {
                wp_cache_flush_group(self::GROUP);
            }

            return null;
        }

        global $wpdb;

        // delete_transient, not a DELETE query: it clears the option cache too.
        $names = $wpdb->get_col($wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            $wpdb->esc_like('_transient_'.self::GROUP.':').'%',
        ));
        foreach ($names as $name) {
            delete_transient(substr((string) $name, strlen('_transient_')));
        }

        return count($names);
    }

    public function needsWordPress(): bool
    {
        return true;
    }
}
