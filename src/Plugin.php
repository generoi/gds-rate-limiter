<?php

namespace GeneroWP\RateLimiter;

/**
 * The mu-plugin's part: the checks RateLimiter::boot() left for when
 * WordPress can tell a logged-in user, the WP-CLI command, the header
 * sage-cachetags' warmer sends so the limiter knows its requests, and the one
 * on WordPress's own requests to the site.
 */
final class Plugin
{
    public static function load(): void
    {
        // First on plugins_loaded: pluggable.php (is_user_logged_in) is in,
        // nothing has rendered yet.
        add_action('plugins_loaded', function (): void {
            RateLimiter::instance()?->late($_SERVER, is_user_logged_in());
        }, PHP_INT_MIN);

        // Last, so it follows the SEO plugin's rules.
        add_filter('robots_txt', function ($output) {
            $seconds = RateLimiter::instance()?->options->crawlDelay ?? 0;

            return $seconds > 0 ? CrawlDelay::append((string) $output, $seconds) : $output;
        }, PHP_INT_MAX);

        add_filter('cachetags/warm/request-headers', function ($headers) {
            $token = RateLimiter::instance()?->warmToken() ?? '';

            return $token === '' ? $headers : [...(array) $headers, RateLimiter::WARM_HEADER => $token];
        });

        // WordPress's requests to the site itself (loopbacks, cron spawning)
        // leave through the server's outbound address, shared on some hosts
        // and liable to change, so they're told apart by a token rather than
        // by address. Only to the site's own host (on a network, any of its
        // sites': they share the key), so the token stays there.
        add_filter('http_request_args', function ($args, $url) {
            $token = RateLimiter::instance()?->selfToken() ?? '';
            if ($token === '' || ! is_array($args) || ! self::isOwnHost((string) $url)) {
                return $args;
            }
            $headers = $args['headers'] ?? [];
            if (is_array($headers)) {
                $args['headers'] = [...$headers, RateLimiter::SELF_HEADER => $token];
            }

            return $args;
        }, 10, 2);

        if (defined('WP_CLI') && WP_CLI) {
            Cli::register();
        }
    }

    private static function isOwnHost(string $url): bool
    {
        $host = strtolower((string) wp_parse_url($url, PHP_URL_HOST));

        if ($host === '') {
            return false;
        }
        if (in_array($host, [
            strtolower((string) wp_parse_url(home_url(), PHP_URL_HOST)),
            strtolower((string) wp_parse_url(site_url(), PHP_URL_HOST)),
        ], true)) {
            return true;
        }

        return is_multisite() && get_sites([
            'domain' => $host,
            'network_id' => get_current_network_id(),
            'count' => true,
        ]) > 0;
    }
}
