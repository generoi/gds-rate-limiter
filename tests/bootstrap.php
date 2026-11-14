<?php

/**
 * WordPress's test suite in wp-env, with the plugin loaded as a site loads
 * the mu-plugin.
 */
$autoload = dirname(__DIR__).'/vendor/autoload.php';

if (! file_exists($autoload)) {
    exit("Run `composer install` first.\n");
}

require_once $autoload;

$wpPhpunit = getenv('WP_PHPUNIT__DIR') ?: dirname(__DIR__).'/vendor/wp-phpunit/wp-phpunit';

require_once $wpPhpunit.'/includes/functions.php';

tests_add_filter('muplugins_loaded', function (): void {
    require dirname(__DIR__).'/gds-rate-limiter.php';
});

require $wpPhpunit.'/includes/bootstrap.php';
