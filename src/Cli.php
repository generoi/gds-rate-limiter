<?php

namespace GeneroWP\RateLimiter;

use GeneroWP\RateLimiter\Edge\Edge;
use WP_CLI;

/**
 * `wp rate-limit`: look at an IP, empty the store, and manage the edge
 * blocklists. With APCu the store is the web server's memory, which WP-CLI
 * doesn't share (apc.enable_cli or not), so `status` and `flush` only work
 * with Redis or the object cache there.
 */
final class Cli
{
    public function __construct(private RateLimiter $limiter) {}

    public static function register(): void
    {
        WP_CLI::add_command('rate-limit', function (array $args) {
            $limiter = RateLimiter::instance();
            if ($limiter === null) {
                WP_CLI::error('The rate limiter isn\'t booted: call GeneroWP\RateLimiter\RateLimiter::boot() in config/application.php.');
            }
            $cli = new self($limiter);
            $command = array_shift($args) ?? '';
            match ($command) {
                'status' => $cli->status($args),
                'flush' => $cli->flush(),
                'block' => $cli->block($args),
                'unblock' => $cli->unblock($args),
                'blocklist' => $cli->blocklist(),
                default => WP_CLI::error('Usage: wp rate-limit status <ip> | flush | block <ip> | unblock <ip> | blocklist'),
            };
        });
    }

    /**
     * @param  list<string>  $args
     */
    public function status(array $args): void
    {
        $ip = $this->ip($args);
        $o = $this->limiter->options;
        $l = $this->limiter->limiter;

        WP_CLI::line(sprintf('Store: %s', (new \ReflectionClass($o->store))->getShortName()));
        $retry = $l->retryAfter($ip);
        WP_CLI::line($retry > 0 ? "Banned: {$retry}s left" : 'Banned: no');
        WP_CLI::line(sprintf('Requests this window: %d/%d per %ds', $l->count($ip), $o->limit, $o->window));
        WP_CLI::line(sprintf('Bans in the last %ds: %d', $o->escalationWindow, $l->bans($ip)));
        $subnet = Ip::subnet($ip);
        if ($subnet !== null && $o->subnetLimit > 0) {
            $subnetRetry = $l->retryAfter($subnet);
            WP_CLI::line(sprintf('Subnet %s: %d/%d per %ds%s', $subnet, $l->count($subnet), $o->subnetLimit, $o->window, $subnetRetry > 0 ? ", banned {$subnetRetry}s" : ''));
        }
        WP_CLI::line(sprintf('Edge blocklists: %s', $o->edge === [] ? 'none' : implode(', ', array_map(fn ($e) => $e->name(), $o->edge))));
    }

    public function flush(): void
    {
        $deleted = $this->limiter->options->store->flush();
        WP_CLI::success($deleted === null ? 'Flushed the rate limit store.' : "Flushed the rate limit store ({$deleted} keys).");
    }

    /**
     * @param  list<string>  $args
     */
    public function block(array $args): void
    {
        $ip = $this->ip($args);
        $this->edges();
        $this->limiter->block($ip)
            ? WP_CLI::success("Added {$ip} to the edge blocklist.")
            : WP_CLI::error("Couldn't add {$ip} to the edge blocklist.");
    }

    /**
     * @param  list<string>  $args
     */
    public function unblock(array $args): void
    {
        $ip = $this->ip($args);
        $removed = false;
        foreach ($this->edges() as $edge) {
            $removed = $edge->unblock($ip) || $removed;
        }
        $removed
            ? WP_CLI::success("Removed {$ip} from the edge blocklist.")
            : WP_CLI::error("Couldn't remove {$ip} (it may not be listed).");
    }

    public function blocklist(): void
    {
        $ips = [];
        foreach ($this->edges() as $edge) {
            $list = $edge->blocked();
            if ($list === null) {
                WP_CLI::error("Couldn't read the {$edge->name()} blocklist.");
            }
            foreach ($list as $ip) {
                $ips[$ip] = true;
            }
        }
        WP_CLI::line($ips === [] ? 'The blocklist is empty.' : implode("\n", array_keys($ips)));
    }

    /**
     * @return list<Edge>
     */
    private function edges(): array
    {
        if ($this->limiter->options->edge === []) {
            WP_CLI::error('No edge blocklist is configured (the `edge` option).');
        }

        return $this->limiter->options->edge;
    }

    /**
     * @param  list<string>  $args
     */
    private function ip(array $args): string
    {
        $ip = $args[0] ?? '';
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            WP_CLI::error('Give an IP address.');
        }

        return $ip;
    }
}
