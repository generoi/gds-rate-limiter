<?php

namespace GeneroWP\RateLimiter\Tests\Unit;

use GeneroWP\RateLimiter\ClientIp\RemoteAddr;
use GeneroWP\RateLimiter\ClientIp\VerifiedCdn;
use GeneroWP\RateLimiter\Ip;
use PHPUnit\Framework\TestCase;

class IpTest extends TestCase
{
    public function test_normalize_keeps_public_addresses_only(): void
    {
        $this->assertSame('203.0.113.9', Ip::normalize(' 203.0.113.9 '));
        $this->assertSame('203.0.113.9', Ip::normalize('203.0.113.9, 10.0.0.1'));
        $this->assertSame('2a00:1450::1', Ip::normalize('2a00:1450::1'));
        $this->assertNull(Ip::normalize('10.0.0.1'));
        $this->assertNull(Ip::normalize('127.0.0.1'));
        $this->assertNull(Ip::normalize('not an ip'));
        $this->assertNull(Ip::normalize(''));
        $this->assertSame('172.18.0.1', Ip::normalize('172.18.0.1', allowPrivate: true));
        // One spelling per IPv6 address.
        $this->assertSame('2a00:1450::1', Ip::normalize('2A00:1450:0000:0000:0000:0000:0000:0001'));
    }

    public function test_a_prefix_out_of_range_is_clamped(): void
    {
        $this->assertTrue(Ip::matches('203.0.113.9', ['203.0.113.9/33']));
        $this->assertFalse(Ip::matches('203.0.113.8', ['203.0.113.9/40']));
        $this->assertTrue(Ip::matches('203.0.113.9', ['198.51.100.0/-1']));
    }

    public function test_subnets(): void
    {
        $this->assertSame('net4:203.0.113', Ip::subnet('203.0.113.9'));
        $this->assertSame('net6:20010db800010002', Ip::subnet('2001:db8:1:2::1'));
        $this->assertNull(Ip::subnet('nope'));
    }

    public function test_allowlist_matches_addresses_and_ranges(): void
    {
        $list = ['203.0.113.10', '198.51.100.0/24', '2001:db8::/32', '192.0.2.128/25'];

        $this->assertTrue(Ip::matches('203.0.113.10', $list));
        $this->assertTrue(Ip::matches('198.51.100.77', $list));
        $this->assertTrue(Ip::matches('2001:db8:ffff::1', $list));
        $this->assertTrue(Ip::matches('192.0.2.200', $list));
        $this->assertFalse(Ip::matches('192.0.2.100', $list));
        $this->assertFalse(Ip::matches('203.0.113.11', $list));
        $this->assertFalse(Ip::matches('2001:db9::1', $list));
        $this->assertFalse(Ip::matches('203.0.113.9', []));
    }

    public function test_remote_addr(): void
    {
        $this->assertSame('203.0.113.9', (new RemoteAddr)->resolve(['REMOTE_ADDR' => '203.0.113.9']));
        // A forwarded header is ignored.
        $this->assertNull((new RemoteAddr)->resolve(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9']));
    }

    public function test_a_cdn_address_counts_only_with_its_own_secret(): void
    {
        $cdn = new VerifiedCdn('s3cret');

        $this->assertSame('203.0.113.9', $cdn->resolve(['HTTP_X_ORIGIN_VERIFY' => 's3cret', 'HTTP_FASTLY_CLIENT_IP' => '203.0.113.9']));
        $this->assertSame('198.51.100.7', $cdn->resolve(['HTTP_X_ORIGIN_VERIFY_CLOUDFLARE' => 's3cret', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7']));
        // A forged address of the other CDN through this one isn't read.
        $this->assertNull($cdn->resolve(['HTTP_X_ORIGIN_VERIFY' => 's3cret', 'HTTP_CF_CONNECTING_IP' => '198.51.100.7']));
        $this->assertNull($cdn->resolve(['HTTP_X_ORIGIN_VERIFY' => 'wrong', 'HTTP_FASTLY_CLIENT_IP' => '203.0.113.9']));
        // Direct to origin, or while the secret is unset: not limited.
        $this->assertNull($cdn->resolve(['REMOTE_ADDR' => '203.0.113.9']));
        $this->assertNull((new VerifiedCdn(''))->resolve(['HTTP_X_ORIGIN_VERIFY' => '', 'HTTP_FASTLY_CLIENT_IP' => '203.0.113.9']));
    }
}
