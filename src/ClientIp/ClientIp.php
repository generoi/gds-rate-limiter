<?php

namespace GeneroWP\RateLimiter\ClientIp;

/**
 * Where a request's client address comes from. Null leaves the request
 * unlimited.
 */
interface ClientIp
{
    /**
     * @param  array<string,mixed>  $server  $_SERVER
     */
    public function resolve(array $server): ?string;
}
