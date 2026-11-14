<?php

/**
 * End-to-end tests only, mapped into wp-env's site by .wp-env.json: boots
 * the limiter as a site's config/application.php would, with a low limit.
 * mu-plugins load before plugins, so the package's autoloader is loaded here.
 */

use GeneroWP\RateLimiter\ClientIp\RemoteAddr;
use GeneroWP\RateLimiter\RateLimiter;
use GeneroWP\RateLimiter\Store\CacheStore;

require_once WP_PLUGIN_DIR.'/gds-rate-limiter/vendor/autoload.php';

RateLimiter::boot([
    'limit' => 5,
    'ban' => 30,
    'subnet_limit' => 0,
    'store' => new CacheStore,
    // Docker's requests come from its private network.
    'client_ip' => new RemoteAddr(allowPrivate: true),
    'bypass_token' => 'e2e-bypass',
]);
