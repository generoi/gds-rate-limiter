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
}
