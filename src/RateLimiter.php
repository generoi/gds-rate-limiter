<?php

namespace GeneroWP\RateLimiter;

/**
 * The site's limiter: booted from config/application.php with its options,
 * it checks a request before WordPress loads. A request with a login cookie
 * waits until WordPress can tell whether it's a logged-in user (who is never
 * limited), and so does every request when the store needs WordPress; the
 * mu-plugin runs those on plugins_loaded.
 */
final class RateLimiter
{
    private static ?self $instance = null;

    public readonly Limiter $limiter;

    private bool $deferred = false;

    /**
     * Options that can't be read (a typo, a wrong type) are logged and leave
     * requests unlimited, not the site down.
     *
     * @param  array<string,mixed>  $options
     */
    public static function boot(array $options = []): ?self
    {
        try {
            self::$instance = new self(Options::from($options));
        } catch (\Throwable $e) {
            self::$instance = null;
            error_log('[Rate Limit] Not booted: '.$e->getMessage());

            return null;
        }
        // WP-CLI and cron from the shell aren't visitors; the instance is
        // still there for `wp rate-limit`.
        if (PHP_SAPI !== 'cli') {
            self::$instance->early($_SERVER, $_COOKIE);
        }

        return self::$instance;
    }

    public static function instance(): ?self
    {
        return self::$instance;
    }

    public function __construct(
        public readonly Options $options,
        private Responder $responder = new Responder,
        ?\Closure $clock = null,
    ) {
        $this->limiter = new Limiter($options, $clock);
    }

    /**
     * Before WordPress: check now, or leave it for late().
     *
     * @param  array<string,mixed>  $server
     * @param  array<string,mixed>  $cookies
     */
    public function early(array $server, array $cookies): void
    {
        if ($this->skipped($cookies)) {
            return;
        }
        if ($this->options->store->needsWordPress() || self::hasLoginCookie($cookies)) {
            $this->deferred = true;

            return;
        }
        $this->check($server);
    }

    /**
     * Once WordPress has loaded plugins: the requests early() left, unless a
     * user is logged in.
     *
     * @param  array<string,mixed>  $server
     */
    public function late(array $server, bool $loggedIn): void
    {
        if (! $this->deferred) {
            return;
        }
        $this->deferred = false;
        if (! $loggedIn) {
            $this->check($server);
        }
    }

    /**
     * @param  array<string,mixed>  $server
     */
    public function check(array $server): void
    {
        $ip = $this->options->clientIp->resolve($server);
        if ($ip === null || Ip::matches($ip, $this->options->allow)) {
            return;
        }

        try {
            $decision = $this->limiter->hit($ip);
        } catch (\Throwable $e) {
            // A store that breaks lets the request through.
            $this->log('Store error: '.$e->getMessage());

            return;
        }
        if ($decision->allowed) {
            return;
        }

        if ($decision->reason === 'subnet') {
            $this->log(sprintf('Subnet limit: %s (%d/%ds), %ds ban', $decision->key, $decision->count, $this->options->window, $decision->retryAfter));
        }
        $this->log(sprintf(
            'IP: %s | Retry-After: %ds | URI: %s | Method: %s | User-Agent: %s',
            $ip,
            $decision->retryAfter,
            self::printable((string) ($server['REQUEST_URI'] ?? 'unknown'), 200),
            preg_replace('/[^A-Z]/', '', strtoupper((string) ($server['REQUEST_METHOD'] ?? 'unknown'))),
            self::printable((string) ($server['HTTP_USER_AGENT'] ?? 'unknown'), 100),
        ));

        $this->responder->reject($decision, $decision->escalate ? function () use ($ip): void {
            $this->block($ip);
        } : null);
    }

    /**
     * Adds $ip to every edge blocklist; true when one took it. Only ever a
     * single validated address: an edge block lasts until removed by hand,
     * so a subnet must never reach here.
     */
    public function block(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $any = false;
        foreach ($this->options->edge as $edge) {
            $ok = $edge->block($ip);
            $this->log($ok ? "Escalated {$ip} to the {$edge->name()} blocklist" : "Couldn't add {$ip} to the {$edge->name()} blocklist");
            $any = $any || $ok;
        }

        return $any;
    }

    public function log(string $message): void
    {
        $line = "[Rate Limit] {$message}";
        if ($this->options->log !== null) {
            ($this->options->log)($line);

            return;
        }
        error_log($line);
    }

    /**
     * @param  array<string,mixed>  $cookies
     */
    public static function hasLoginCookie(array $cookies): bool
    {
        foreach (array_keys($cookies) as $name) {
            if (str_starts_with((string) $name, 'wordpress_logged_in_') || str_starts_with((string) $name, 'wordpress_sec_')) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<string,mixed>  $cookies
     */
    private function skipped(array $cookies): bool
    {
        if ($this->options->disable) {
            return true;
        }
        $token = $this->options->bypassToken;

        return $token !== '' && hash_equals($token, (string) ($cookies['rate_limit_bypass'] ?? ''));
    }

    private static function printable(string $value, int $max): string
    {
        return substr((string) preg_replace('/[^\x20-\x7e]/', '', $value), 0, $max);
    }
}
