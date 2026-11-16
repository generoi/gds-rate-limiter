<?php

namespace GeneroWP\RateLimiter\Tests\Unit;

use GeneroWP\RateLimiter\Edge\Edge;
use GeneroWP\RateLimiter\Options;
use GeneroWP\RateLimiter\RateLimiter;
use GeneroWP\RateLimiter\Store\Store;
use GeneroWP\RateLimiter\Tests\Support\MemoryStore;
use GeneroWP\RateLimiter\Tests\Support\RecordingResponder;
use PHPUnit\Framework\TestCase;

class RateLimiterTest extends TestCase
{
    private int $now = 1_800_000_000;

    private RecordingResponder $responder;

    /** @var list<string> */
    private array $logged = [];

    /**
     * @param  array<string,mixed>  $options
     */
    private function limiter(array $options = []): RateLimiter
    {
        $clock = fn (): int => $this->now;
        $this->responder = new RecordingResponder;

        return new RateLimiter(Options::from($options + [
            'limit' => 2,
            'store' => new MemoryStore($clock),
            'log' => function (string $line): void {
                $this->logged[] = $line;
            },
        ]), $this->responder, $clock);
    }

    private const SERVER = ['REMOTE_ADDR' => '203.0.113.9', 'REQUEST_URI' => "/recipes/\x01x/", 'REQUEST_METHOD' => 'get', 'HTTP_USER_AGENT' => 'Crawler/1.0'];

    /**
     * @param  array<string,mixed>  $cookies
     */
    private function requests(RateLimiter $l, int $n, array $cookies = []): void
    {
        for ($i = 0; $i < $n; $i++) {
            $l->early(self::SERVER, $cookies);
        }
    }

    public function test_the_request_over_the_limit_is_refused_and_logged(): void
    {
        $l = $this->limiter();
        $this->requests($l, 3);

        $this->assertCount(1, $this->responder->rejected);
        $this->assertSame(['[Rate Limit] IP: 203.0.113.9 | Retry-After: 120s | URI: /recipes/x/ | Method: GET | User-Agent: Crawler/1.0'], $this->logged);
    }

    /** With log_file the routine lines leave error_log; failures and an unwritable file stay on it. */
    public function test_log_file_takes_routine_lines_and_failures_stay_on_error_log(): void
    {
        $dir = sys_get_temp_dir().'/gds-rl-'.bin2hex(random_bytes(4));
        mkdir($dir);
        $file = $dir.'/rate-limit.log';
        $errors = $dir.'/php-errors.log';
        $previous = ini_get('error_log');
        ini_set('error_log', $errors);
        try {
            $l = $this->limiter(['log' => null, 'log_file' => $file]);
            $this->requests($l, 3);
            $l->log('Store error: down', failure: true);

            $this->assertMatchesRegularExpression(
                '/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \[Rate Limit\] IP: 203\.0\.113\.9 \| Retry-After: 120s .*\n$/',
                (string) file_get_contents($file),
            );
            $this->assertStringContainsString('[Rate Limit] Store error: down', (string) file_get_contents($errors));
            $this->assertStringNotContainsString('IP: 203.0.113.9', (string) file_get_contents($errors));

            $unwritable = $this->limiter(['log' => null, 'log_file' => $dir.'/missing/rate-limit.log']);
            $unwritable->log('Surge: x');
            $this->assertStringContainsString('[Rate Limit] Surge: x', (string) file_get_contents($errors));
        } finally {
            ini_set('error_log', (string) $previous);
            array_map('unlink', glob($dir.'/*') ?: []);
            rmdir($dir);
        }
    }

    /** A surge's start is logged once; its refusals are answered, not logged. */
    public function test_a_surge_is_logged_once_and_its_refusals_answered_quietly(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 2, 'surge_limit' => 1, 'surge_for' => 300]);
        foreach (['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.1', '203.0.113.1'] as $ip) {
            $l->check(['REMOTE_ADDR' => $ip] + self::SERVER);
        }

        $this->assertSame(['[Rate Limit] Surge: 3 requests in 60s over the site limit of 2; each IP gets 1 a window for 300s'], $this->logged);
        $this->assertCount(2, $this->responder->rejected);
        $this->assertSame('surge', $this->responder->rejected[0]->reason);
    }

    /** The cache warmer's requests aren't counted, by IP or site-wide. */
    public function test_a_cache_warm_request_is_not_counted(): void
    {
        $l = $this->limiter(['bypass_token' => 'secret', 'site_limit' => 100]);
        for ($i = 0; $i < 10; $i++) {
            $l->check(['HTTP_X_CACHE_WARM' => 'secret'] + self::SERVER);
        }

        $this->assertSame([], $this->responder->rejected);
        $this->assertSame(0, $l->limiter->count('203.0.113.9'));
        $this->assertSame(0, $l->limiter->count('site'));
    }

    /** While the site is busy a warm request gets a 429, which stops the warmer's run. */
    public function test_a_cache_warm_request_is_refused_while_the_site_is_busy(): void
    {
        $l = $this->limiter(['bypass_token' => 'secret', 'limit' => 100, 'site_limit' => 4]);
        $warm = ['HTTP_X_CACHE_WARM' => 'secret'] + self::SERVER;
        foreach (['198.51.100.1', '198.51.100.2'] as $ip) {
            $l->check(['REMOTE_ADDR' => $ip] + self::SERVER);
        }
        $l->check($warm);
        $this->assertSame([], $this->responder->rejected, 'half the site limit is not busy yet');

        $l->check(['REMOTE_ADDR' => '198.51.100.3'] + self::SERVER);
        $l->check($warm);

        $this->assertCount(1, $this->responder->rejected);
        $this->assertSame(['busy', 60], [$this->responder->rejected[0]->reason, $this->responder->rejected[0]->retryAfter]);
        $this->assertSame([], $this->logged);
    }

    public function test_a_wrong_or_missing_warm_token_is_counted(): void
    {
        $l = $this->limiter(['bypass_token' => 'secret']);
        $l->check(['HTTP_X_CACHE_WARM' => 'guess'] + self::SERVER);
        $l->check(['HTTP_X_CACHE_WARM' => ''] + self::SERVER);

        $this->assertSame(2, $l->limiter->count('203.0.113.9'));
    }

    public function test_the_warm_token_is_the_bypass_token_when_set(): void
    {
        $this->assertSame('secret', $this->limiter(['bypass_token' => 'secret'])->warmToken());
        if (! defined('AUTH_KEY')) {
            $this->assertSame('', $this->limiter()->warmToken(), 'no token without AUTH_KEY or a bypass_token');
        }
    }

    /** WordPress's own requests are never limited, not even during a surge. */
    public function test_a_self_request_is_never_limited(): void
    {
        $l = $this->limiter(['bypass_token' => 'secret', 'limit' => 100, 'site_limit' => 1, 'surge_limit' => 1]);
        $self = ['HTTP_X_RATE_LIMIT_SELF' => $l->selfToken()] + self::SERVER;
        $l->check(['REMOTE_ADDR' => '198.51.100.1'] + self::SERVER);
        $l->check(['REMOTE_ADDR' => '198.51.100.2'] + self::SERVER);
        for ($i = 0; $i < 10; $i++) {
            $l->check($self);
        }

        $this->assertSame([], $this->responder->rejected);
        $this->assertSame(0, $l->limiter->count('203.0.113.9'));
    }

    public function test_the_self_token_is_its_own_and_a_wrong_one_is_counted(): void
    {
        $l = $this->limiter(['bypass_token' => 'secret']);
        $this->assertNotContains($l->selfToken(), ['', 'secret', $l->warmToken()]);

        $l->check(['HTTP_X_RATE_LIMIT_SELF' => 'secret'] + self::SERVER);
        $l->check(['HTTP_X_RATE_LIMIT_SELF' => $l->warmToken()] + self::SERVER);
        $this->assertSame(2, $l->limiter->count('203.0.113.9'));

        if (! defined('AUTH_KEY')) {
            $this->assertSame('', $this->limiter()->selfToken(), 'no token without AUTH_KEY or a bypass_token');
        }
    }

    public function test_a_login_cookie_waits_for_wordpress_and_a_logged_in_user_passes(): void
    {
        $l = $this->limiter();
        $cookie = ['wordpress_logged_in_abc' => 'x'];
        for ($i = 0; $i < 5; $i++) {
            $l->early(self::SERVER, $cookie);
            $l->late(self::SERVER, loggedIn: true);
        }
        $this->assertSame([], $this->responder->rejected);

        // A login cookie that isn't a logged-in user's is counted.
        for ($i = 0; $i < 3; $i++) {
            $l->early(self::SERVER, $cookie);
            $l->late(self::SERVER, loggedIn: false);
        }
        $this->assertCount(1, $this->responder->rejected);
    }

    public function test_api_credentials_wait_for_wordpress_and_a_valid_one_passes(): void
    {
        $l = $this->limiter();
        $basic = self::SERVER + ['HTTP_AUTHORIZATION' => 'Basic eDp5'];
        for ($i = 0; $i < 5; $i++) {
            $l->early($basic, []);
            $this->assertTrue($l->awaitsApiAuth());
            $l->late($basic, loggedIn: true);
        }
        $this->assertSame([], $this->responder->rejected);

        // Credentials WordPress didn't accept are counted.
        for ($i = 0; $i < 3; $i++) {
            $l->early($basic, []);
            $l->late($basic, loggedIn: false);
        }
        $this->assertCount(1, $this->responder->rejected);
    }

    public function test_api_credentials_are_counted_when_not_trusted(): void
    {
        $l = $this->limiter(['trust_api_credentials' => false]);
        $basic = self::SERVER + ['HTTP_AUTHORIZATION' => 'Basic eDp5'];
        for ($i = 0; $i < 3; $i++) {
            $l->early($basic, []);
            $this->assertFalse($l->awaitsApiAuth());
        }
        $this->assertCount(1, $this->responder->rejected);
    }

    public function test_what_counts_as_api_credentials(): void
    {
        $this->assertTrue(RateLimiter::hasCredentials(['HTTP_AUTHORIZATION' => 'Basic eDp5']));
        $this->assertTrue(RateLimiter::hasCredentials(['REDIRECT_HTTP_AUTHORIZATION' => 'Basic eDp5']));
        $this->assertTrue(RateLimiter::hasCredentials(['PHP_AUTH_USER' => 'x']));
        $this->assertTrue(RateLimiter::hasCredentials(['QUERY_STRING' => 'per_page=10&consumer_key=ck_x']));
        $this->assertFalse(RateLimiter::hasCredentials(['QUERY_STRING' => 'consumer_key=']));
        $this->assertFalse(RateLimiter::hasCredentials(self::SERVER));
    }

    public function test_a_login_cookie_alone_doesnt_await_api_auth(): void
    {
        $l = $this->limiter();
        $l->early(self::SERVER, ['wordpress_logged_in_abc' => 'x']);

        $this->assertFalse($l->awaitsApiAuth());
    }

    public function test_late_only_checks_what_early_left(): void
    {
        $l = $this->limiter();
        $this->requests($l, 2);
        $l->late(self::SERVER, loggedIn: false);

        $this->assertSame([], $this->responder->rejected);
    }

    public function test_a_store_that_needs_wordpress_waits_for_it(): void
    {
        $l = $this->limiter(['store' => new MemoryStore(fn (): int => $this->now, needsWordPress: true)]);
        for ($i = 0; $i < 3; $i++) {
            $l->early(self::SERVER, []);
        }
        $this->assertSame([], $this->responder->rejected);

        for ($i = 0; $i < 3; $i++) {
            $l->early(self::SERVER, []);
            $l->late(self::SERVER, loggedIn: false);
        }
        $this->assertCount(1, $this->responder->rejected);
    }

    public function test_bypass_cookie_disable_and_allowlist_skip_it(): void
    {
        $l = $this->limiter(['bypass_token' => 'tok']);
        $this->requests($l, 5, ['rate_limit_bypass' => 'tok']);
        $this->assertSame([], $this->responder->rejected);

        $l = $this->limiter(['disable' => '1']);
        $this->requests($l, 5);
        $this->assertSame([], $this->responder->rejected);

        $l = $this->limiter(['allow' => ['203.0.113.0/24']]);
        $this->requests($l, 5);
        $this->assertSame([], $this->responder->rejected);
    }

    public function test_a_wrong_bypass_cookie_is_counted(): void
    {
        $l = $this->limiter(['bypass_token' => 'tok']);
        $this->requests($l, 3, ['rate_limit_bypass' => 'wrong']);

        $this->assertCount(1, $this->responder->rejected);
    }

    public function test_a_failing_store_lets_requests_through(): void
    {
        $store = $this->createMock(Store::class);
        $store->method('get')->willThrowException(new \RuntimeException('down'));
        $l = $this->limiter(['store' => $store]);
        $this->requests($l, 5);

        $this->assertSame([], $this->responder->rejected);
        $this->assertContains('[Rate Limit] Store error: down', $this->logged);
    }

    public function test_an_escalated_ip_goes_to_every_edge_after_the_answer(): void
    {
        $edges = [];
        foreach (['Fastly', 'Cloudflare'] as $name) {
            $edge = $this->createMock(Edge::class);
            $edge->method('name')->willReturn($name);
            $edge->expects($this->once())->method('block')->with('203.0.113.9')->willReturn(true);
            $edges[] = $edge;
        }
        $l = $this->limiter(['limit' => 1, 'ban' => 10, 'edge' => $edges, 'edge_after' => 2]);
        for ($i = 0; $i < 2; $i++) {
            $this->requests($l, 2);
            $this->now += 100;
        }

        $this->assertContains('[Rate Limit] Escalated 203.0.113.9 to the Fastly blocklist', $this->logged);
        $this->assertContains('[Rate Limit] Escalated 203.0.113.9 to the Cloudflare blocklist', $this->logged);
    }

    public function test_only_an_address_reaches_the_edge(): void
    {
        $edge = $this->createMock(Edge::class);
        $edge->expects($this->never())->method('block');

        $this->assertFalse($this->limiter(['edge' => [$edge]])->block('net4:203.0.113'));
    }

    public function test_an_unknown_option_is_an_error(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Options::from(['limt' => 5]);
    }

    /**
     * In config/application.php that error must not take the site down.
     */
    public function test_options_boot_cant_read_leave_it_unbooted(): void
    {
        $log = ini_get('error_log');
        ini_set('error_log', '/dev/null');
        try {
            $this->assertNull(RateLimiter::boot(['limt' => 5]));
            $this->assertNull(RateLimiter::boot(['store' => 'apcu']));
            $this->assertNull(RateLimiter::instance());
        } finally {
            ini_set('error_log', (string) $log);
        }
    }
}
