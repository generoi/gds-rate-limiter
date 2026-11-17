<?php

namespace GeneroWP\RateLimiter;

/**
 * How a surge went, for the line its end logs: the most requests reaching
 * PHP in one window while it lasted, and the requests and IPs it refused.
 */
final class SurgeEnd
{
    public function __construct(
        public readonly int $peak,
        public readonly int $refused,
        public readonly int $ips,
    ) {}
}
