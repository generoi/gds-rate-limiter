<?php

namespace GeneroWP\RateLimiter\Tests\Integration;

use GeneroWP\RateLimiter\Store\CacheStore;
use WP_UnitTestCase;

/**
 * The store on WordPress's transients (wp-env has no persistent object
 * cache), and on its object cache API as a drop-in would provide it.
 */
class CacheStoreTest extends WP_UnitTestCase
{
    public function test_counts_values_and_flush_on_transients(): void
    {
        $this->assertNotTrue(wp_using_ext_object_cache());
        $store = new CacheStore;

        $this->assertSame(1, $store->increment('203.0.113.9:count', 60));
        $this->assertSame(2, $store->increment('203.0.113.9:count', 60));
        $this->assertSame(2, $store->get('203.0.113.9:count'));
        $store->set('203.0.113.9:banned', 1_800_000_120, 120);
        $this->assertSame(1_800_000_120, $store->get('203.0.113.9:banned'));
        $this->assertNull($store->get('missing'));

        $this->assertSame(2, $store->flush());
        $this->assertNull($store->get('203.0.113.9:count'));
    }

    /**
     * A count keeps the end of its window: later increments don't push the
     * transient's timeout out.
     */
    public function test_a_count_keeps_its_window(): void
    {
        $store = new CacheStore;
        $store->increment('203.0.113.9:count', 60);
        $timeout = (int) get_option('_transient_timeout_'.CacheStore::GROUP.':203.0.113.9:count');
        update_option('_transient_timeout_'.CacheStore::GROUP.':203.0.113.9:count', $timeout - 30, false);

        $store->increment('203.0.113.9:count', 60);

        $this->assertSame($timeout - 30, (int) get_option('_transient_timeout_'.CacheStore::GROUP.':203.0.113.9:count'));
        $this->assertSame(2, $store->get('203.0.113.9:count'));
    }

    public function test_an_expired_count_starts_again(): void
    {
        $store = new CacheStore;
        $store->increment('203.0.113.9:count', 60);
        update_option('_transient_timeout_'.CacheStore::GROUP.':203.0.113.9:count', time() - 1, false);

        $this->assertNull($store->get('203.0.113.9:count'));
        $this->assertSame(1, $store->increment('203.0.113.9:count', 60));
    }

    public function test_counts_on_the_object_cache(): void
    {
        wp_using_ext_object_cache(true);
        try {
            $store = new CacheStore;
            $this->assertSame(1, $store->increment('198.51.100.7:count', 60));
            $this->assertSame(2, $store->increment('198.51.100.7:count', 60));
            $this->assertSame(2, (int) wp_cache_get('198.51.100.7:count', CacheStore::GROUP));
            $this->assertFalse(get_transient(CacheStore::GROUP.':198.51.100.7:count'));
        } finally {
            wp_using_ext_object_cache(false);
        }
    }
}
