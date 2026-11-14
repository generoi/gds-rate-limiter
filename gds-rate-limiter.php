<?php

/*
Plugin Name:  GDS Rate Limiter
Plugin URI:   https://github.com/generoi/gds-rate-limiter
Description:  Answers 429 to IPs that flood PHP with uncached requests, before WordPress loads; booted from config/application.php
Version:      1.0.0
Author:       Genero
Author URI:   https://genero.fi/
License:      MIT
*/

use GeneroWP\RateLimiter\Plugin;

if (! defined('ABSPATH')) {
    exit;
}

if (! class_exists(Plugin::class) && file_exists(__DIR__.'/vendor/autoload.php')) {
    require_once __DIR__.'/vendor/autoload.php';
}

Plugin::load();
