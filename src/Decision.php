<?php

namespace GeneroWP\RateLimiter;

/**
 * What the limiter decided for one request.
 */
final class Decision
{
    /**
     * @param  string  $reason  '' (allowed), 'banned' (an earlier ban), 'ip' or 'subnet' (this request went over)
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly int $retryAfter = 0,
        public readonly string $reason = '',
        public readonly string $key = '',
        public readonly int $count = 0,
        public readonly bool $escalate = false,
    ) {}
}
