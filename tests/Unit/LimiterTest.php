<?php

namespace GeneroWP\RateLimiter\Tests\Unit;

use GeneroWP\RateLimiter\Edge\Edge;
use GeneroWP\RateLimiter\Limiter;
use GeneroWP\RateLimiter\Options;
use GeneroWP\RateLimiter\Tests\Support\MemoryStore;
use PHPUnit\Framework\TestCase;

class LimiterTest extends TestCase
{
    private int $now = 1_800_000_000;

    /**
     * @param  array<string,mixed>  $options
     */
    private function limiter(array $options = []): Limiter
    {
        $clock = fn (): int => $this->now;

        return new Limiter(Options::from($options + ['store' => new MemoryStore($clock)]), $clock);
    }

    private function hits(Limiter $limiter, string $ip, int $n): void
    {
        for ($i = 0; $i < $n; $i++) {
            $this->assertTrue($limiter->hit($ip)->allowed, "request {$i} of {$n}");
        }
    }

    public function test_an_ip_over_the_limit_is_banned_for_the_ban(): void
    {
        $l = $this->limiter(['limit' => 5]);
        $this->hits($l, '203.0.113.9', 5);

        $d = $l->hit('203.0.113.9');

        $this->assertFalse($d->allowed);
        $this->assertSame('ip', $d->reason);
        $this->assertSame(120, $d->retryAfter);
        $this->assertSame(6, $d->count);
    }

    public function test_a_ban_is_served_with_the_time_left_and_then_lifts(): void
    {
        $l = $this->limiter(['limit' => 2]);
        $this->hits($l, '203.0.113.9', 2);
        $l->hit('203.0.113.9');

        $this->now += 30;
        $d = $l->hit('203.0.113.9');
        $this->assertSame(['banned', 90], [$d->reason, $d->retryAfter]);

        $this->now += 91;
        $this->assertTrue($l->hit('203.0.113.9')->allowed);
    }

    /**
     * A ban shorter than the window: the count starts over with the ban, so
     * the first request after it isn't banned again.
     */
    public function test_a_short_ban_ends_with_a_fresh_count(): void
    {
        $l = $this->limiter(['limit' => 3, 'window' => 60, 'ban' => 10]);
        $this->hits($l, '203.0.113.9', 3);
        $l->hit('203.0.113.9');
        $this->now += 11;

        $this->hits($l, '203.0.113.9', 3);
    }

    public function test_the_window_resets_the_count(): void
    {
        $l = $this->limiter(['limit' => 3, 'window' => 60]);
        $this->hits($l, '203.0.113.9', 3);
        $this->now += 61;

        $this->hits($l, '203.0.113.9', 3);
    }

    public function test_repeat_bans_double_up_to_the_cap(): void
    {
        $l = $this->limiter(['limit' => 1, 'ban' => 100, 'max_ban' => 350]);
        $durations = [];
        for ($i = 0; $i < 4; $i++) {
            $l->hit('203.0.113.9');
            $durations[] = $l->hit('203.0.113.9')->retryAfter;
            $this->now += 400; // past the ban and the window
        }

        $this->assertSame([100, 200, 350, 350], $durations);
    }

    public function test_a_day_without_a_ban_starts_again_from_the_first(): void
    {
        $l = $this->limiter(['limit' => 1, 'ban' => 100, 'escalation_window' => 1000]);
        $l->hit('203.0.113.9');
        $l->hit('203.0.113.9');
        $this->now += 1001;

        $l->hit('203.0.113.9');
        $this->assertSame(100, $l->hit('203.0.113.9')->retryAfter);
    }

    /**
     * Bans that keep coming keep doubling past the first ban's window: the
     * window counts from the last ban.
     */
    public function test_steady_bans_keep_escalating_past_the_first_window(): void
    {
        $l = $this->limiter(['limit' => 1, 'ban' => 100, 'max_ban' => 100_000, 'escalation_window' => 1000]);
        $durations = [];
        for ($i = 0; $i < 4; $i++) {
            $l->hit('203.0.113.9');
            $durations[] = $l->hit('203.0.113.9')->retryAfter;
            $this->now += 900; // under the window each time, 2700 s in all
        }

        $this->assertSame([100, 200, 400, 800], $durations);
    }

    public function test_a_crawl_spread_over_a_subnet_bans_the_subnet(): void
    {
        $l = $this->limiter(['limit' => 100, 'subnet_limit' => 10, 'subnet_ban' => 300]);
        for ($i = 1; $i <= 10; $i++) {
            $this->assertTrue($l->hit("198.51.100.{$i}")->allowed);
        }

        $d = $l->hit('198.51.100.200');
        $this->assertSame(['subnet', 'net4:198.51.100', 300, false], [$d->reason, $d->key, $d->retryAfter, $d->escalate]);

        // Its neighbours are refused too; another subnet isn't.
        $this->assertSame('banned', $l->hit('198.51.100.1')->reason);
        $this->assertTrue($l->hit('198.51.101.1')->allowed);
    }

    public function test_the_subnet_limit_can_be_off(): void
    {
        $l = $this->limiter(['limit' => 100, 'subnet_limit' => 0]);
        for ($i = 1; $i <= 200; $i++) {
            $this->assertTrue($l->hit('198.51.100.'.($i % 250 + 1))->allowed);
        }
    }

    public function test_the_nth_ban_within_the_edge_window_escalates_once(): void
    {
        $edge = $this->createMock(Edge::class);
        $l = $this->limiter(['limit' => 1, 'ban' => 10, 'edge' => [$edge], 'edge_after' => 3, 'edge_window' => 1800]);
        $escalated = [];
        for ($i = 0; $i < 4; $i++) {
            $l->hit('203.0.113.9');
            $escalated[] = $l->hit('203.0.113.9')->escalate;
            $this->now += 200;
        }

        $this->assertSame([false, false, true, false], $escalated);
    }

    public function test_without_edges_nothing_escalates(): void
    {
        $l = $this->limiter(['limit' => 1, 'ban' => 10, 'edge_after' => 1]);
        $l->hit('203.0.113.9');

        $this->assertFalse($l->hit('203.0.113.9')->escalate);
    }

    public function test_ipv6_subnets_are_the_64(): void
    {
        $l = $this->limiter(['limit' => 100, 'subnet_limit' => 2]);
        $l->hit('2001:db8:1:2::1');
        $l->hit('2001:db8:1:2:ffff::1');

        $this->assertSame('subnet', $l->hit('2001:db8:1:2::3')->reason);
        $this->assertTrue($l->hit('2001:db8:1:3::1')->allowed);
    }

    /**
     * Many IPs each under the limit: going over site_limit starts a surge, and
     * from then each IP gets only surge_limit a window.
     */
    public function test_a_crawl_spread_over_ips_starts_a_surge(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 10, 'surge_limit' => 2]);
        foreach (['203.0.113.1', '203.0.113.2', '198.51.100.3', '192.0.2.4', '198.51.100.5'] as $ip) {
            $this->hits($l, $ip, 2);
        }

        $start = $l->hit('192.0.2.6');
        $this->assertTrue($start->allowed);
        $this->assertSame(11, $start->surgeStarted);
        $this->assertSame(300, $l->surgeLeft());

        $d = $l->hit('203.0.113.1');
        $this->assertSame([false, 'surge', 60], [$d->allowed, $d->reason, $d->retryAfter]);
        $this->hits($l, '192.0.2.7', 2);
        $this->assertSame('surge', $l->hit('192.0.2.7')->reason);
        $this->assertSame(0, $l->hit('192.0.2.8')->surgeStarted, 'a surge starts once');
    }

    /** A surge refusal is no ban: the next window lets the IP back in. */
    public function test_a_surge_refusal_is_no_ban(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 1, 'surge_limit' => 1]);
        $this->hits($l, '203.0.113.1', 1);
        $l->hit('203.0.113.2'); // starts the surge
        $this->assertSame('surge', $l->hit('203.0.113.1')->reason);

        $this->assertSame(0, $l->retryAfter('203.0.113.1'));
        $this->assertSame(0, $l->bans('203.0.113.1'));
        $this->now += 61;
        $this->assertTrue($l->hit('203.0.113.1')->allowed);
        $this->assertGreaterThan(0, $l->surgeLeft());
    }

    public function test_a_surge_ends_after_surge_for(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 1, 'surge_limit' => 1, 'surge_for' => 120]);
        $l->hit('203.0.113.1');
        $l->hit('203.0.113.2');

        $this->now += 121;
        $this->assertSame(0, $l->surgeLeft());
        $this->assertTrue($l->hit('203.0.113.1')->allowed);
        $this->assertTrue($l->hit('203.0.113.1')->allowed);
    }

    /**
     * The first request after a surge carries how it went, once: the highest
     * window count while it lasted (not the count that crossed site_limit),
     * and the requests and distinct IPs it refused, prefetches among them.
     */
    public function test_a_surge_end_reports_its_peak_and_refusals_once(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 3, 'surge_limit' => 1, 'surge_for' => 120]);
        foreach (['203.0.113.1', '203.0.113.2', '203.0.113.3'] as $ip) {
            $l->hit($ip);
        }
        $this->assertSame(4, $l->hit('203.0.113.4')->surgeStarted);
        $this->assertTrue($l->hit('203.0.113.5')->allowed);
        $this->assertTrue($l->hit('203.0.113.6')->allowed);
        foreach (['203.0.113.1', '203.0.113.1', '203.0.113.2'] as $ip) {
            $this->assertSame('surge', $l->hit($ip)->reason);
        }
        $this->assertSame('prefetch', $l->hit('203.0.113.7', prefetch: true)->reason);
        $this->assertNull($l->hit('203.0.113.8')->surgeEnded, 'still surging');

        $this->now += 121;
        $ended = $l->hit('203.0.113.9')->surgeEnded;
        $this->assertNotNull($ended);
        $this->assertSame([7, 4, 3], [$ended->peak, $ended->refused, $ended->ips]);
        $this->assertNull($l->hit('203.0.113.10')->surgeEnded, 'logged once');
    }

    /** The next surge counts afresh, its IPs too. */
    public function test_the_next_surge_counts_afresh(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 1, 'surge_limit' => 1, 'surge_for' => 120]);
        $l->hit('203.0.113.1');
        $l->hit('203.0.113.2'); // starts the surge
        $l->hit('203.0.113.1'); // refused
        $this->now += 121;
        $l->hit('203.0.113.3'); // ends it

        $l->hit('203.0.113.4'); // starts the next
        $this->assertTrue($l->hit('203.0.113.1')->allowed);
        $this->assertSame('surge', $l->hit('203.0.113.1')->reason, 'refused in the last surge too, counted again');
        $this->now += 121;
        $ended = $l->hit('203.0.113.5')->surgeEnded;
        $this->assertNotNull($ended);
        $this->assertSame([3, 1, 1], [$ended->peak, $ended->refused, $ended->ips]);
    }

    /** Only what reaches PHP counts: a crawler's 429s don't prolong a surge. */
    public function test_refused_requests_dont_count_toward_the_site(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 3, 'surge_limit' => 1]);
        foreach (['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4'] as $ip) {
            $l->hit($ip);
        }
        for ($i = 0; $i < 20; $i++) {
            $l->hit('203.0.113.1');
        }

        $this->assertSame(4, $l->count('site'));
    }

    public function test_surges_are_off_by_default(): void
    {
        $l = $this->limiter(['limit' => 1000, 'subnet_limit' => 0]);
        for ($i = 0; $i < 200; $i++) {
            $this->assertTrue($l->hit('203.0.113.'.($i % 50))->allowed);
        }

        $this->assertSame(0, $l->count('site'));
        $this->assertSame(0, $l->surgeLeft());
    }

    /**
     * A phone prefetching every product it scrolls past: its prefetches are
     * counted apart, so its own clicks stay under the limit, and a prefetch
     * over the limit is refused without a ban.
     */
    public function test_prefetches_never_ban_and_dont_count_toward_clicks(): void
    {
        $l = $this->limiter(['limit' => 3]);
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue($l->hit('203.0.113.9', prefetch: true)->allowed);
        }

        $d = $l->hit('203.0.113.9', prefetch: true);
        $this->assertSame([false, 'prefetch', 60], [$d->allowed, $d->reason, $d->retryAfter]);
        $this->assertSame(0, $l->retryAfter('203.0.113.9'));
        $this->assertSame(0, $l->bans('203.0.113.9'));
        $this->hits($l, '203.0.113.9', 3);
    }

    public function test_a_banned_ip_is_refused_its_prefetches_too(): void
    {
        $l = $this->limiter(['limit' => 1]);
        $l->hit('203.0.113.9');
        $l->hit('203.0.113.9');

        $this->assertSame('banned', $l->hit('203.0.113.9', prefetch: true)->reason);
    }

    /** While the site surges every prefetch is refused, and a click still gets surge_limit. */
    public function test_a_surge_refuses_every_prefetch(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 1, 'surge_limit' => 2]);
        $l->hit('203.0.113.1');
        $l->hit('203.0.113.2'); // starts the surge

        $this->assertSame('prefetch', $l->hit('203.0.113.3', prefetch: true)->reason);
        $this->hits($l, '203.0.113.3', 2);
    }

    /** An allowed prefetch reaches PHP, so it counts toward the site and can start a surge. */
    public function test_an_allowed_prefetch_counts_toward_the_site(): void
    {
        $l = $this->limiter(['limit' => 100, 'site_limit' => 2]);
        $l->hit('203.0.113.1', prefetch: true);
        $l->hit('203.0.113.2', prefetch: true);

        $this->assertSame(3, $l->hit('203.0.113.3', prefetch: true)->surgeStarted);
    }

    /** An IP over the normal limit is still banned during a surge. */
    public function test_the_limit_still_bans_during_a_surge(): void
    {
        $l = $this->limiter(['limit' => 3, 'site_limit' => 1, 'surge_limit' => 100]);
        $l->hit('203.0.113.2');
        $l->hit('203.0.113.3'); // starts the surge
        $this->hits($l, '203.0.113.1', 3);

        $this->assertSame('ip', $l->hit('203.0.113.1')->reason);
    }
}
