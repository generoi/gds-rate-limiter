<?php

namespace GeneroWP\RateLimiter\Tests\Unit;

use GeneroWP\RateLimiter\Store\ApcuStore;
use GeneroWP\RateLimiter\Store\RedisStore;
use GeneroWP\RateLimiter\Store\Store;
use PHPUnit\Framework\TestCase;

/**
 * The real APCu and Redis, where they're there: CI runs these with APCu on
 * for the CLI and a Redis service at REDIS_HOST.
 */
class StoreTest extends TestCase
{
    /**
     * @return array<string,array{callable():?Store}>
     */
    public static function stores(): array
    {
        return [
            'apcu' => [fn () => ApcuStore::available() ? new ApcuStore('gds_rl_test:') : null],
            'redis' => [function () {
                $host = getenv('REDIS_HOST');

                return class_exists(\Redis::class) && $host ? new RedisStore($host, (int) (getenv('REDIS_PORT') ?: 6379), prefix: 'gds_rl_test:') : null;
            }],
        ];
    }

    /**
     * @dataProvider stores
     */
    public function test_counts_values_and_flush(callable $make): void
    {
        $store = $make();
        if ($store === null) {
            $this->markTestSkipped('Not set up here.');
        }
        $store->flush();

        $this->assertSame(1, $store->increment('203.0.113.9:count', 60));
        $this->assertSame(2, $store->increment('203.0.113.9:count', 60));
        $this->assertSame(2, $store->get('203.0.113.9:count'));
        $this->assertNull($store->get('missing'));

        $store->set('203.0.113.9:banned', 1_800_000_120, 120);
        $this->assertSame(1_800_000_120, $store->get('203.0.113.9:banned'));
        $store->set('203.0.113.9:bans', 1, 120);
        $store->delete('203.0.113.9:bans');
        $this->assertNull($store->get('203.0.113.9:bans'));

        $this->assertSame(2, $store->flush());
        $this->assertNull($store->get('203.0.113.9:count'));
    }

    /**
     * @dataProvider stores
     */
    public function test_get_many_reads_present_and_missing_keys(callable $make): void
    {
        $store = $make();
        if ($store === null) {
            $this->markTestSkipped('Not set up here.');
        }
        $store->flush();
        $store->set('203.0.113.9:banned', 1_800_000_120, 120);
        $store->increment('site:surge', 60);

        $this->assertSame(
            ['203.0.113.9:banned' => 1_800_000_120, 'net4:203.0.113:banned' => null, 'site:surge' => 1],
            $store->getMany(['203.0.113.9:banned', 'net4:203.0.113:banned', 'site:surge']),
        );
        $this->assertSame([], $store->getMany([]));
        $store->flush();
    }

    /**
     * Redis only: APCu expires a key on a later request, not within one.
     *
     * @return array<string,array{callable():?Store}>
     */
    public static function expiringStores(): array
    {
        return ['redis' => self::stores()['redis']];
    }

    /**
     * @dataProvider expiringStores
     */
    public function test_a_count_expires_with_its_window(callable $make): void
    {
        $store = $make();
        if ($store === null) {
            $this->markTestSkipped('Not set up here.');
        }
        $store->flush();
        $store->increment('203.0.113.9:count', 1);
        sleep(2);

        $this->assertNull($store->get('203.0.113.9:count'));
        $this->assertSame(1, $store->increment('203.0.113.9:count', 60));
        $store->flush();
    }

    public function test_redis_that_cant_be_reached_lets_requests_through(): void
    {
        if (! class_exists(\Redis::class)) {
            $this->markTestSkipped('No phpredis here.');
        }
        $store = new RedisStore('127.0.0.1', 1, timeout: 0.1);

        $this->assertSame(0, $store->increment('203.0.113.9:count', 60));
        $this->assertNull($store->get('203.0.113.9:count'));
        $this->assertSame(['203.0.113.9:banned' => null], $store->getMany(['203.0.113.9:banned']));
        $this->assertNull($store->flush());
    }
}
