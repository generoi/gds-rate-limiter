<?php

namespace GeneroWP\RateLimiter\Edge;

/**
 * A CDN's blocklist that a repeat offender is added to, so it's refused
 * before it reaches the site at all. An entry stays until removed
 * (`wp rate-limit unblock`).
 */
interface Edge
{
    public function name(): string;

    public function block(string $ip): bool;

    public function unblock(string $ip): bool;

    /** @return list<string>|null null when the list can't be read */
    public function blocked(): ?array;
}
