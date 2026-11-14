<?php

namespace GeneroWP\RateLimiter\ClientIp;

use GeneroWP\RateLimiter\Ip;

/**
 * The connection's own address, where the host already puts the visitor's
 * there and a header can't change it (Kinsta, behind its Cloudflare).
 */
final class RemoteAddr implements ClientIp
{
    public function __construct(private bool $allowPrivate = false) {}

    public function resolve(array $server): ?string
    {
        return Ip::normalize((string) ($server['REMOTE_ADDR'] ?? ''), $this->allowPrivate);
    }
}
