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
