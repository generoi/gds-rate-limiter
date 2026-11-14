<?php

namespace GeneroWP\RateLimiter\Edge;

/**
 * The few HTTP calls an edge blocklist makes, with curl: they can happen
 * before WordPress loads, so not through its HTTP API.
 */
class Http
{
    /**
     * @param  array<string,string>  $headers
     * @return array{code:int,body:mixed}|null null when the request failed
     */
    public function request(string $method, string $url, array $headers = [], mixed $json = null, int $timeout = 5): ?array
    {
        if (! function_exists('curl_init')) {
            return null;
        }
        $lines = [];
        foreach ($headers + ['Accept' => 'application/json'] as $name => $value) {
            $lines[] = "{$name}: {$value}";
        }
        $curl = curl_init($url);
        curl_setopt_array($curl, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
        ]);
        if ($json !== null) {
            $lines[] = 'Content-Type: application/json';
            curl_setopt($curl, CURLOPT_POSTFIELDS, (string) json_encode($json));
        }
        curl_setopt($curl, CURLOPT_HTTPHEADER, $lines);
        $body = curl_exec($curl);
        $code = (int) curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

        return is_string($body) ? ['code' => $code, 'body' => json_decode($body, true)] : null;
    }
}
