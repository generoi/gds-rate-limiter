<?php

namespace GeneroWP\RateLimiter\Edge;

/**
 * A Cloudflare account IP list (Lists → IP), which a WAF custom rule blocks:
 * `ip.src in $blocked_ips`. The token needs Account Filter Lists: Edit.
 */
final class Cloudflare implements Edge
{
    private Http $http;

    public function __construct(
        private string $token,
        private string $accountId,
        private string $listId,
        ?Http $http = null,
    ) {
        $this->http = $http ?? new Http;
    }

    public function name(): string
    {
        return 'Cloudflare';
    }

    public function block(string $ip): bool
    {
        // POST appends, replacing an existing entry for the same IP.
        return $this->request('POST', '', [['ip' => $ip, 'comment' => 'gds-rate-limiter']]) !== null;
    }

    public function unblock(string $ip): bool
    {
        $response = $this->request('GET', '?search='.rawurlencode($ip));
        if ($response === null) {
            return false;
        }
        // Search matches by prefix (1.2.3.4 also finds 1.2.3.45) and Cloudflare
        // stores IPv6 normalized, so compare the packed addresses.
        $ids = [];
        foreach ((array) ($response['result'] ?? []) as $item) {
            if (@inet_pton((string) ($item['ip'] ?? '')) === @inet_pton($ip)) {
                $ids[] = ['id' => (string) $item['id']];
            }
        }

        return $ids !== [] && $this->request('DELETE', '', ['items' => $ids]) !== null;
    }

    public function blocked(): ?array
    {
        $ips = [];
        $cursor = '';
        do {
            $response = $this->request('GET', '?per_page=500'.($cursor !== '' ? '&cursor='.rawurlencode($cursor) : ''));
            if ($response === null) {
                return null;
            }
            foreach ((array) ($response['result'] ?? []) as $item) {
                $ips[] = (string) ($item['ip'] ?? '');
            }
            $cursor = (string) ($response['result_info']['cursors']['after'] ?? '');
        } while ($cursor !== '');

        return $ips;
    }

    /**
     * Cloudflare's answer, or null unless it says success.
     *
     * @return array<string,mixed>|null
     */
    private function request(string $method, string $query, mixed $json = null): ?array
    {
        $response = $this->http->request(
            $method,
            "https://api.cloudflare.com/client/v4/accounts/{$this->accountId}/rules/lists/{$this->listId}/items{$query}",
            ['Authorization' => 'Bearer '.$this->token],
            $json,
        );
        $body = $response['body'] ?? null;

        return is_array($body) && ! empty($body['success']) ? $body : null;
    }
}
