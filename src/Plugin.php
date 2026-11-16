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
            $limiter = RateLimiter::instance();
            if ($limiter === null) {
                return;
            }
            // Application passwords and WooCommerce keys authenticate only
            // once WordPress knows it's serving the REST API: the REST server
            // clears the user cached before then and authenticates again
            // just ahead of rest_authentication_errors. Check those requests
            // there, last. A valid credential passes like a logged-in user; a
            // wrong one is counted.
            if ($limiter->awaitsApiAuth() && self::isRestRequest()) {
                add_filter('rest_authentication_errors', function ($result) use ($limiter) {
                    $limiter->late($_SERVER, is_user_logged_in());

                    return $result;
                }, PHP_INT_MAX);
                // A REST-looking URL that WordPress didn't serve as REST.
                add_action('wp', fn () => $limiter->late($_SERVER, is_user_logged_in()), PHP_INT_MIN);

                return;
            }
            $limiter->late($_SERVER, is_user_logged_in());
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

    private static function isRestRequest(): bool
    {
        if (isset($_GET['rest_route'])) {
            return true;
        }
        $path = (string) wp_parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
        $home = rtrim((string) wp_parse_url(home_url('/'), PHP_URL_PATH), '/');

        return str_starts_with($path, $home.'/'.rest_get_url_prefix().'/');
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
