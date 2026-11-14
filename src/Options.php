<?php

namespace GeneroWP\RateLimiter;

use GeneroWP\RateLimiter\ClientIp\ClientIp;
use GeneroWP\RateLimiter\ClientIp\RemoteAddr;
use GeneroWP\RateLimiter\Edge\Edge;
use GeneroWP\RateLimiter\Store\ApcuStore;
use GeneroWP\RateLimiter\Store\CacheStore;
use GeneroWP\RateLimiter\Store\Store;

/**
 * The limiter's settings, from the array a site passes to RateLimiter::boot().
 * Every key is optional; an unknown key is an error, so a typo can't
 * silently leave a default in place.
 */
final class Options
{
    /** Requests per IP per window before it's banned. */
    public int $limit = 45;

    /** The counting window, in seconds. */
    public int $window = 60;

    /** The first ban; each further one within escalation_window doubles it. */
    public int $ban = 120;

    public int $maxBan = 86400;

    /** An IP that goes this long without a ban starts again from `ban`. */
    public int $escalationWindow = 86400;

    /** Requests per /24 (IPv4) or /64 (IPv6) per window; 0 turns it off. */
    public int $subnetLimit = 150;

    /** A subnet's ban: short, and never doubled or sent to the edge. */
    public int $subnetBan = 300;

    /** @var list<string> Addresses and CIDR ranges never limited. */
    public array $allow = [];

    /** A `rate_limit_bypass` cookie with this value skips the limiter (e2e runs). */
    public string $bypassToken = '';

    public Store $store;

    public ClientIp $clientIp;

    /** @var list<Edge> */
    public array $edge = [];

    /** Bans within edge_window before an IP goes to the edge blocklists. */
    public int $edgeAfter = 3;

    public int $edgeWindow = 1800;

    public bool $disable = false;

    /** @var (callable(string):void)|null Where log lines go; null for error_log. */
    public $log = null;

    /**
     * @param  array<string,mixed>  $options
     */
    public static function from(array $options): self
    {
        $o = new self;
        $o->store = ApcuStore::available() ? new ApcuStore : new CacheStore;
        $o->clientIp = new RemoteAddr;

        foreach ($options as $key => $value) {
            $property = lcfirst(str_replace('_', '', ucwords((string) $key, '_')));
            if (! property_exists($o, $property)) {
                throw new \InvalidArgumentException("gds-rate-limiter: unknown option '{$key}'");
            }
            $o->{$property} = match ($property) {
                'allow' => array_values(array_map('strval', (array) $value)),
                'edge' => array_values((array) $value),
                'bypassToken' => (string) $value,
                'disable' => filter_var($value, FILTER_VALIDATE_BOOLEAN),
                'store', 'clientIp', 'log' => $value,
                default => (int) $value,
            };
        }

        return $o;
    }
}
