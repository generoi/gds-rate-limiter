<?php

namespace GeneroWP\RateLimiter;

use Closure;

/**
 * Counts one IP's request and decides: an active ban (its own or its
 * subnet's) is served first; then over `limit` in a window bans the IP, each
 * ban within `escalation_window` twice as long as the last, up to `max_ban`;
 * then over `subnet_limit` bans the subnet for `subnet_ban`. The `edge_after`th
 * ban within `edge_window` sends the IP to the edge, when edges are set.
 *
 * With `site_limit` set, the requests let through from all IPs are counted
 * too; going over starts a surge of `surge_for` seconds, during which each IP
 * gets only `surge_limit` a window. Over that is a 429 until the window ends,
 * not a ban: no doubling, no edge, so a real visitor loses at most a window.
 */
final class Limiter
{
    private Closure $clock;

    public function __construct(private Options $options, ?Closure $clock = null)
    {
        $this->clock = $clock ?? fn (): int => time();
    }

    public function hit(string $ip): Decision
    {
        $o = $this->options;
        $now = ($this->clock)();
        $subnet = $o->subnetLimit > 0 ? Ip::subnet($ip) : null;

        foreach (array_filter([$ip, $subnet]) as $key) {
            $retry = $this->retryAfter($key, $now);
            if ($retry > 0) {
                return new Decision(false, $retry, 'banned', $key);
            }
        }

        $count = $o->store->increment("{$ip}:count", $o->window);
        if ($count > $o->limit) {
            // Stored again so its TTL restarts: the doubling ends only after
            // a whole escalation_window without a ban.
            $bans = $o->store->increment("{$ip}:bans", $o->escalationWindow);
            $o->store->set("{$ip}:bans", $bans, $o->escalationWindow);
            $duration = min($o->ban * 2 ** min(max($bans, 1) - 1, 20), $o->maxBan);
            $this->ban($ip, $duration, $now);
            $escalate = $o->edge !== [] && $o->store->increment("{$ip}:edge", $o->edgeWindow) === $o->edgeAfter;

            return new Decision(false, $duration, 'ip', $ip, $count, $escalate);
        }

        if ($subnet !== null) {
            $subnetCount = $o->store->increment("{$subnet}:count", $o->window);
            if ($subnetCount > $o->subnetLimit) {
                $this->ban($subnet, $o->subnetBan, $now);

                return new Decision(false, $o->subnetBan, 'subnet', $subnet, $subnetCount);
            }
        }

        if ($o->siteLimit <= 0) {
            return new Decision(true, 0, '', $ip, $count);
        }
        $surging = $o->store->get('site:surge') !== null;
        if ($surging && $count > $o->surgeLimit) {
            return new Decision(false, $o->window, 'surge', $ip, $count);
        }
        // Only what reaches PHP counts, so a crawler's 429s don't keep the
        // site surging once the load is gone.
        $site = $o->store->increment('site:count', $o->window);
        if (! $surging && $site > $o->siteLimit) {
            $o->store->set('site:surge', $now + $o->surgeFor, $o->surgeFor);

            return new Decision(true, 0, '', $ip, $count, false, $site);
        }

        return new Decision(true, 0, '', $ip, $count);
    }

    /** Seconds left of the site's surge, 0 when it isn't surging. */
    public function surgeLeft(?int $now = null): int
    {
        $until = $this->options->store->get('site:surge');

        return $until === null ? 0 : max(0, $until - ($now ?? ($this->clock)()));
    }

    /** Seconds left of $key's ban, 0 when it has none. */
    public function retryAfter(string $key, ?int $now = null): int
    {
        $until = $this->options->store->get("{$key}:banned");

        return $until === null ? 0 : max(0, $until - ($now ?? ($this->clock)()));
    }

    /** The count of $key's current window. */
    public function count(string $key): int
    {
        return (int) ($this->options->store->get("{$key}:count") ?? 0);
    }

    /** Bans of $ip within the escalation window. */
    public function bans(string $ip): int
    {
        return (int) ($this->options->store->get("{$ip}:bans") ?? 0);
    }

    /**
     * Its count starts over: a ban shorter than the window would otherwise
     * end with the count still over, and the next request ban it again.
     */
    private function ban(string $key, int $duration, int $now): void
    {
        $this->options->store->set("{$key}:banned", $now + $duration, $duration);
        $this->options->store->delete("{$key}:count");
    }
}
