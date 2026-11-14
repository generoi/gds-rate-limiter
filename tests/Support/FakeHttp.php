<?php

namespace GeneroWP\RateLimiter\Tests\Support;

use GeneroWP\RateLimiter\Edge\Http;

/**
 * Records requests and answers from a queue.
 */
final class FakeHttp extends Http
{
    /** @var list<array{method:string,url:string,headers:array<string,string>,json:mixed}> */
    public array $requests = [];

    /**
     * @param  list<array{code:int,body:mixed}|null>  $responses
     */
    public function __construct(public array $responses = []) {}

    public function request(string $method, string $url, array $headers = [], mixed $json = null, int $timeout = 5): ?array
    {
        $this->requests[] = compact('method', 'url', 'headers', 'json');

        return array_shift($this->responses) ?? ['code' => 200, 'body' => ['success' => true, 'result' => []]];
    }
}
