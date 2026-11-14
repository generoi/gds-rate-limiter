<?php

namespace GeneroWP\RateLimiter;

/**
 * Answers a refused request: 429, Retry-After and never cached (a page cache
 * keyed on the URL alone would serve it to everyone), then ends PHP. Work
 * left for after the answer ($after: telling the edge) runs once the
 * visitor has it.
 */
class Responder
{
    /**
     * @param  callable():void|null  $after
     */
    public function reject(Decision $decision, ?callable $after = null): void
    {
        if (! headers_sent()) {
            http_response_code(429);
            header(sprintf('Retry-After: %d', $decision->retryAfter));
            header('Content-Type: text/plain; charset=utf-8');
            header('Cache-Control: no-store, private');
        }
        echo sprintf('Rate limit exceeded. Please retry after %d seconds.', $decision->retryAfter);

        if ($after !== null) {
            if (function_exists('fastcgi_finish_request')) {
                fastcgi_finish_request();
            }
            $after();
        }

        exit;
    }
}
