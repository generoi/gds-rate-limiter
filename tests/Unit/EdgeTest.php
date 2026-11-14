<?php

namespace GeneroWP\RateLimiter\Tests\Unit;

use GeneroWP\RateLimiter\Edge\Cloudflare;
use GeneroWP\RateLimiter\Edge\Fastly;
use GeneroWP\RateLimiter\Tests\Support\FakeHttp;
use PHPUnit\Framework\TestCase;

class EdgeTest extends TestCase
{
    public function test_fastly_puts_the_ip_in_the_dictionary(): void
    {
        $http = new FakeHttp([['code' => 200, 'body' => []]]);

        $this->assertTrue((new Fastly('key', 'svc', 'dict', $http))->block('203.0.113.9'));
        $this->assertSame([[
            'method' => 'PUT',
            'url' => 'https://api.fastly.com/service/svc/dictionary/dict/item/203.0.113.9',
            'headers' => ['Fastly-Key' => 'key'],
            'json' => ['item_value' => '1'],
        ]], $http->requests);
    }

    public function test_fastly_reports_a_refusal_and_lists_its_keys(): void
    {
        $http = new FakeHttp([['code' => 403, 'body' => ['msg' => 'no']], ['code' => 200, 'body' => [['item_key' => '203.0.113.9'], ['item_key' => '2001:db8::1']]]]);
        $fastly = new Fastly('key', 'svc', 'dict', $http);

        $this->assertFalse($fastly->block('203.0.113.9'));
        $this->assertSame(['203.0.113.9', '2001:db8::1'], $fastly->blocked());
    }

    public function test_cloudflare_appends_the_ip_to_the_list(): void
    {
        $http = new FakeHttp;

        $this->assertTrue((new Cloudflare('tok', 'acc', 'list', $http))->block('203.0.113.9'));
        $this->assertSame('POST', $http->requests[0]['method']);
        $this->assertSame('https://api.cloudflare.com/client/v4/accounts/acc/rules/lists/list/items', $http->requests[0]['url']);
        $this->assertSame(['Authorization' => 'Bearer tok'], $http->requests[0]['headers']);
        $this->assertSame([['ip' => '203.0.113.9', 'comment' => 'gds-rate-limiter']], $http->requests[0]['json']);
    }

    public function test_cloudflare_unblock_deletes_the_exact_address_only(): void
    {
        $http = new FakeHttp([
            ['code' => 200, 'body' => ['success' => true, 'result' => [
                ['id' => 'a', 'ip' => '203.0.113.9'],
                ['id' => 'b', 'ip' => '203.0.113.90'],
            ]]],
            ['code' => 200, 'body' => ['success' => true]],
        ]);

        $this->assertTrue((new Cloudflare('tok', 'acc', 'list', $http))->unblock('203.0.113.9'));
        $this->assertStringEndsWith('/items?search=203.0.113.9', $http->requests[0]['url']);
        $this->assertSame(['method' => 'DELETE', 'json' => ['items' => [['id' => 'a']]]], ['method' => $http->requests[1]['method'], 'json' => $http->requests[1]['json']]);
    }

    public function test_cloudflare_lists_every_page(): void
    {
        $http = new FakeHttp([
            ['code' => 200, 'body' => ['success' => true, 'result' => [['ip' => '203.0.113.9']], 'result_info' => ['cursors' => ['after' => 'c2']]]],
            ['code' => 200, 'body' => ['success' => true, 'result' => [['ip' => '198.51.100.7']]]],
        ]);

        $this->assertSame(['203.0.113.9', '198.51.100.7'], (new Cloudflare('tok', 'acc', 'list', $http))->blocked());
        $this->assertStringEndsWith('?per_page=500&cursor=c2', $http->requests[1]['url']);
    }

    public function test_cloudflare_without_success_is_a_failure(): void
    {
        $http = new FakeHttp([['code' => 403, 'body' => ['success' => false, 'errors' => []]]]);

        $this->assertFalse((new Cloudflare('tok', 'acc', 'list', $http))->block('203.0.113.9'));
    }
}
