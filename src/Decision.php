<?php

namespace GeneroWP\RateLimiter;

/**
 * What the limiter decided for one request.
 */
final class Decision
{
    /**
     * @param  string  $reason  '' (allowed), 'banned' (an earlier ban), 'ip' or 'subnet' (this request went over), 'surge' (over surge_limit while the site surges), 'busy' (a cache-warm request while the site is busy)
     * @param  int  $surgeStarted  the site's count when this request started a surge, else 0
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly int $retryAfter = 0,
        public readonly string $reason = '',
        public readonly string $key = '',
        public readonly int $count = 0,
        public readonly bool $escalate = false,
        public readonly int $surgeStarted = 0,
    ) {}
}
