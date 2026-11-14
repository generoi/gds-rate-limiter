<?php

namespace GeneroWP\RateLimiter\ClientIp;

use GeneroWP\RateLimiter\Ip;

/**
 * The client address a CDN forwards, trusted only when the CDN proves the
 * request came through it by sending a shared secret: Fastly sets
 * X-Origin-Verify and Fastly-Client-IP, Cloudflare X-Origin-Verify-Cloudflare
 * and CF-Connecting-IP. Each CDN overwrites only its own headers, so each
 * secret header unlocks only its own CDN's address header.
 *
 * Without a matching secret (direct-to-origin traffic, or everything while
 * the secret is unset) the request isn't limited: enabling is fail-open and
 * order-free, and a caller can't forge an address to fill another's counter.
 */
final class VerifiedCdn implements ClientIp
{
    public function __construct(private string $secret, private bool $allowPrivate = false) {}

    public function resolve(array $server): ?string
    {
        if ($this->secret === '') {
            return null;
        }
        if (hash_equals($this->secret, (string) ($server['HTTP_X_ORIGIN_VERIFY_CLOUDFLARE'] ?? ''))) {
            return Ip::normalize((string) ($server['HTTP_CF_CONNECTING_IP'] ?? ''), $this->allowPrivate);
        }
        if (hash_equals($this->secret, (string) ($server['HTTP_X_ORIGIN_VERIFY'] ?? ''))) {
            return Ip::normalize((string) ($server['HTTP_FASTLY_CLIENT_IP'] ?? ''), $this->allowPrivate);
        }

        return null;
    }
}
