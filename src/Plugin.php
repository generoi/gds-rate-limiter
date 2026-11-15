<?php

namespace GeneroWP\RateLimiter;

/**
 * The mu-plugin's part: the checks RateLimiter::boot() left for when
 * WordPress can tell a logged-in user, the WP-CLI command, and the header
 * sage-cachetags' warmer sends so the limiter knows its requests.
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

        if (defined('WP_CLI') && WP_CLI) {
            Cli::register();
        }
    }
}
