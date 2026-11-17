<?php

namespace GeneroWP\RateLimiter;

/**
 * The site's limiter: booted from config/application.php with its options,
 * it checks a request before WordPress loads. A request with a login cookie
 * or API credentials (an application password, a WooCommerce key) waits
 * until WordPress can tell whether it's a logged-in user (who is never
 * limited), and so does every request when the store needs WordPress; the
 * mu-plugin runs those on plugins_loaded, or for credentials on a REST
 * request once WordPress serves it.
 */
final class RateLimiter
{
    /**
     * Sent by sage-cachetags' warmer (see Plugin): a request carrying the warm
     * token isn't counted, and while the site is busy it gets a 429, which
     * makes the warmer stop its run.
     */
    public const WARM_HEADER = 'X-Cache-Warm';

    /**
     * Sent on WordPress's own requests to the site (see Plugin): loopbacks,
     * cron spawning. A request carrying the self token is never limited, so
     * the server's outbound address needn't be in `allow`.
     */
    public const SELF_HEADER = 'X-Rate-Limit-Self';

    private static ?self $instance = null;

    public readonly Limiter $limiter;

    private bool $deferred = false;

    private bool $awaitsApiAuth = false;

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
        $this->awaitsApiAuth = $this->options->trustApiCredentials && self::hasCredentials($server);
        if ($this->awaitsApiAuth || $this->options->store->needsWordPress() || self::hasLoginCookie($cookies)) {
            $this->deferred = true;

            return;
        }
        $this->check($server);
    }

    /**
     * Left by early() for API credentials, which WordPress checks only once
     * it's serving the REST API.
     */
    public function awaitsApiAuth(): bool
    {
        return $this->deferred && $this->awaitsApiAuth;
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
        if (self::sent($server, self::SELF_HEADER, $this->selfToken())) {
            return;
        }
        if (self::sent($server, self::WARM_HEADER, $this->warmToken())) {
            if ($this->busy()) {
                $this->responder->reject(new Decision(false, $this->options->window, 'busy'), null);
            }

            return;
        }

        $ip = $this->options->clientIp->resolve($server);
        if ($ip === null || Ip::matches($ip, $this->options->allow)) {
            return;
        }

        try {
            $decision = $this->limiter->hit($ip, self::isPrefetch($server));
        } catch (\Throwable $e) {
            // A store that breaks lets the request through.
            $this->log('Store error: '.$e->getMessage(), failure: true);

            return;
        }
        if ($decision->surgeStarted > 0) {
            $this->log(sprintf(
                'Surge: %d requests in %ds over the site limit of %d; each IP gets %d a window for %ds',
                $decision->surgeStarted,
                $this->options->window,
                $this->options->siteLimit,
                $this->options->surgeLimit,
                $this->options->surgeFor,
            ));
        }
        if ($decision->allowed) {
            return;
        }
        if ($decision->reason === 'surge' || $decision->reason === 'prefetch') {
            // Not logged per request: a surge is many of them, and its start
            // is logged once; a refused prefetch costs the visitor nothing.
            $this->responder->reject($decision, null);

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
     * The token the cache warmer sends in WARM_HEADER: `bypass_token` when
     * set, else one derived from AUTH_KEY, so WP-CLI and the web server agree
     * on it without configuration. '' when there's neither.
     */
    public function warmToken(): string
    {
        if ($this->options->bypassToken !== '') {
            return $this->options->bypassToken;
        }

        return self::derived('gds-rate-limiter/cache-warm', self::authKey());
    }

    /**
     * The token in SELF_HEADER, derived from `bypass_token` when set, else
     * from AUTH_KEY. '' when there's neither. `wp rate-limit token` prints it
     * for scripts that request the site from the server.
     */
    public function selfToken(): string
    {
        return self::derived('gds-rate-limiter/self', $this->options->bypassToken !== '' ? $this->options->bypassToken : self::authKey());
    }

    private static function authKey(): string
    {
        return defined('AUTH_KEY') && is_string(AUTH_KEY) ? AUTH_KEY : '';
    }

    private static function derived(string $purpose, string $key): string
    {
        return $key === '' ? '' : hash_hmac('sha256', $purpose, $key);
    }

    /**
     * Too busy for the warmer: surging, or past half the site limit. Without a
     * site limit the warmer is never held back.
     */
    public function busy(): bool
    {
        $o = $this->options;

        return $o->siteLimit > 0
            && ($this->limiter->surgeLeft() > 0 || $this->limiter->count('site') * 2 > $o->siteLimit);
    }

    /**
     * @param  array<string,mixed>  $server
     */
    private static function sent(array $server, string $header, string $token): bool
    {
        $sent = (string) ($server['HTTP_'.strtoupper(str_replace('-', '_', $header))] ?? '');

        return $token !== '' && $sent !== '' && hash_equals($token, $sent);
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
            $this->log($ok ? "Escalated {$ip} to the {$edge->name()} blocklist" : "Couldn't add {$ip} to the {$edge->name()} blocklist", failure: ! $ok);
            $any = $any || $ok;
        }

        return $any;
    }

    /**
     * A `failure` is something to look at (a broken store, a refused edge
     * call) and stays on error_log even with `log_file`; the routine lines
     * go to the file, so they stay out of the host's error stream.
     */
    public function log(string $message, bool $failure = false): void
    {
        $line = "[Rate Limit] {$message}";
        if ($this->options->log !== null) {
            ($this->options->log)($line);

            return;
        }
        if (! $failure && $this->options->logFile !== null
            && @error_log(date('Y-m-d H:i:s ').$line."\n", 3, $this->options->logFile)) {
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
     * Basic auth (application passwords, WooCommerce keys) or WooCommerce's
     * consumer_key in the query string. Whether they're valid is WordPress's
     * to decide: until it does, they're just a reason to wait.
     *
     * @param  array<string,mixed>  $server
     */
    public static function hasCredentials(array $server): bool
    {
        foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION', 'PHP_AUTH_USER'] as $key) {
            if ((string) ($server[$key] ?? '') !== '') {
                return true;
            }
        }
        parse_str((string) ($server['QUERY_STRING'] ?? ''), $query);

        return (string) ($query['consumer_key'] ?? '') !== '';
    }

    /**
     * A prefetch or prerender the browser started by itself: speculation
     * rules (WordPress core adds them) and `<link rel="prefetch">` send
     * `Sec-Purpose: prefetch`, a prerender `prefetch;prerender`.
     *
     * @param  array<string,mixed>  $server
     */
    public static function isPrefetch(array $server): bool
    {
        return str_starts_with(strtolower(trim((string) ($server['HTTP_SEC_PURPOSE'] ?? ''))), 'prefetch');
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
