<?php

namespace GeneroWP\RateLimiter\Edge;

/**
 * A Fastly Edge Dictionary of blocked IPs, which the service's VCL refuses:
 *
 *     sub vcl_recv {
 *       if (table.lookup(blocked_ips, client.ip, "0") == "1") {
 *         error 403 "Forbidden";
 *       }
 *     }
 */
final class Fastly implements Edge
{
    private Http $http;

    public function __construct(
        private string $apiKey,
        private string $serviceId,
        private string $dictionaryId,
        ?Http $http = null,
    ) {
        $this->http = $http ?? new Http;
    }

    public function name(): string
    {
        return 'Fastly';
    }

    public function block(string $ip): bool
    {
        $response = $this->request('PUT', '/item/'.rawurlencode($ip), ['item_value' => '1']);

        return $response !== null && $response['code'] < 400;
    }

    public function unblock(string $ip): bool
    {
        $response = $this->request('DELETE', '/item/'.rawurlencode($ip));

        return $response !== null && $response['code'] < 400;
    }

    public function blocked(): ?array
    {
        $response = $this->request('GET', '/items?per_page=1000');
        if ($response === null || $response['code'] >= 400 || ! is_array($response['body'])) {
            return null;
        }

        return array_values(array_map(fn ($item) => (string) ($item['item_key'] ?? ''), $response['body']));
    }

    /**
     * @return array{code:int,body:mixed}|null
     */
    private function request(string $method, string $path, mixed $json = null): ?array
    {
        return $this->http->request(
            $method,
            "https://api.fastly.com/service/{$this->serviceId}/dictionary/{$this->dictionaryId}{$path}",
            ['Fastly-Key' => $this->apiKey],
            $json,
        );
    }
}
