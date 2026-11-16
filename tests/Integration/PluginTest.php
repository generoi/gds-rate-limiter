<?php

namespace GeneroWP\RateLimiter\Tests\Integration;

use GeneroWP\RateLimiter\Options;
use GeneroWP\RateLimiter\RateLimiter;
use GeneroWP\RateLimiter\Store\CacheStore;
use GeneroWP\RateLimiter\Tests\Support\RecordingResponder;
use WP_UnitTestCase;

/**
 * The mu-plugin's half: the check boot() left, once WordPress can tell
 * whether a login cookie belongs to a logged-in user.
 */
class PluginTest extends WP_UnitTestCase
{
    private const SERVER = ['REMOTE_ADDR' => '203.0.113.9'];

    public function test_the_check_runs_first_on_plugins_loaded(): void
    {
        $this->assertSame(PHP_INT_MIN, $this->priority());
    }

    public function test_a_logged_in_user_is_never_limited_and_a_forged_cookie_is(): void
    {
        $responder = new RecordingResponder;
        $limiter = new RateLimiter(Options::from(['limit' => 2, 'store' => new CacheStore, 'log' => fn () => null]), $responder);
        $cookie = ['wordpress_logged_in_x' => 'forged'];

        wp_set_current_user(self::factory()->user->create());
        for ($i = 0; $i < 5; $i++) {
            $limiter->early(self::SERVER, $cookie);
            $limiter->late(self::SERVER, is_user_logged_in());
        }
        $this->assertSame([], $responder->rejected);

        wp_set_current_user(0);
        for ($i = 0; $i < 3; $i++) {
            $limiter->early(self::SERVER, $cookie);
            $limiter->late(self::SERVER, is_user_logged_in());
        }
        $this->assertCount(1, $responder->rejected);
        $this->assertSame(1, (int) get_transient(CacheStore::GROUP.':203.0.113.9:bans'));
    }

    /** sage-cachetags' warmer sends the warm token through this filter. */
    public function test_the_cache_warmer_gets_the_warm_header(): void
    {
        $instance = new \ReflectionProperty(RateLimiter::class, 'instance');
        $saved = $instance->getValue();
        try {
            RateLimiter::boot(['bypass_token' => 'secret', 'store' => new CacheStore]);

            $headers = apply_filters('cachetags/warm/request-headers', ['User-Agent' => 'warmer']);

            $this->assertSame(['User-Agent' => 'warmer', RateLimiter::WARM_HEADER => 'secret'], $headers);
        } finally {
            $instance->setValue(null, $saved);
        }
    }

    public function test_without_a_limiter_the_warm_headers_are_untouched(): void
    {
        $instance = new \ReflectionProperty(RateLimiter::class, 'instance');
        $saved = $instance->getValue();
        $instance->setValue(null, null);
        try {
            $this->assertSame(['User-Agent' => 'warmer'], apply_filters('cachetags/warm/request-headers', ['User-Agent' => 'warmer']));
        } finally {
            $instance->setValue(null, $saved);
        }
    }

    /** WordPress's requests to its own host carry the self token; others don't. */
    public function test_requests_to_the_site_itself_get_the_self_header(): void
    {
        $instance = new \ReflectionProperty(RateLimiter::class, 'instance');
        $saved = $instance->getValue();
        try {
            $limiter = RateLimiter::boot(['bypass_token' => 'secret', 'store' => new CacheStore]);

            $own = apply_filters('http_request_args', ['headers' => ['Accept' => 'text/html']], site_url('wp-cron.php'));
            $other = apply_filters('http_request_args', ['headers' => []], 'https://api.example.com/');

            $this->assertSame(['Accept' => 'text/html', RateLimiter::SELF_HEADER => $limiter?->selfToken()], $own['headers']);
            $this->assertSame([], $other['headers']);
        } finally {
            $instance->setValue(null, $saved);
        }
    }

    private function priority(): ?int
    {
        global $wp_filter;
        foreach ($wp_filter['plugins_loaded']->callbacks ?? [] as $priority => $callbacks) {
            foreach ($callbacks as $callback) {
                if ($callback['function'] instanceof \Closure && str_contains((string) (new \ReflectionFunction($callback['function']))->getFileName(), 'gds-rate-limiter/src/Plugin.php')) {
                    return (int) $priority;
                }
            }
        }

        return null;
    }
}
