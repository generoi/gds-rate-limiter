# GDS Rate Limiter

Answers 429 to IPs that flood PHP with uncached requests, before WordPress
loads or connects to its database. Only cache misses reach PHP, so it counts
what costs the server, not what the page cache serves.

```sh
composer require generoi/gds-rate-limiter
```

It's a must-use plugin, but it does nothing until the site boots it with its
settings, in Bedrock's `config/application.php` after `Config::apply()`:

```php
use GeneroWP\RateLimiter\RateLimiter;
use GeneroWP\RateLimiter\Store\ApcuStore;

RateLimiter::boot([
    'disable' => env('DISABLE_RATE_LIMITING'),
    'limit' => 45,
    'store' => new ApcuStore,
    'allow' => ['192.0.2.10', '198.51.100.0/24'],
    'bypass_token' => env('RATE_LIMIT_BYPASS_TOKEN'),
]);
```

## How it decides

1. A request from an IP or subnet that's banned gets 429 straight away.
2. Over `limit` requests in a `window` bans the IP for `ban` seconds. Each
   further ban within `escalation_window` doubles it, up to `max_ban`; an IP
   that goes a whole `escalation_window` without one starts again.
3. Over `subnet_limit` requests from one /24 (IPv4) or /64 (IPv6) bans the
   subnet for `subnet_ban`: for a crawl spread over many addresses. It's more
   lenient and never doubled, as a subnet can hold real people.
4. With `edge` blocklists set, an IP's `edge_after`th ban within `edge_window`
   adds it to them, after its 429 has been sent. Only single addresses ever
   reach the edge, and they stay until `wp rate-limit unblock`.

The 429 has `Retry-After` and `Cache-Control: no-store, private`, and one line
goes to the PHP error log: `[Rate Limit] IP: … | Retry-After: …s | URI: … | Method: … | User-Agent: …`.

Never limited: logged-in users (a request with a login cookie waits until
WordPress can check it, then runs first on `plugins_loaded`), `allow`ed
addresses and ranges, a `rate_limit_bypass` cookie equal to `bypass_token`
(for e2e runs against production), WP-CLI, and private or reserved addresses.
A store that fails lets requests through, and so do options `boot()` can't
read (logged as `[Rate Limit] Not booted: …`).

Counted like any visitor: REST or admin-ajax clients without a login cookie
(an integration polling the site may need an `allow` entry), and WooCommerce
shoppers, whose session cookie skips the page cache.

## Options

| Option | Default | |
|---|---|---|
| `limit` | 45 | Requests per IP per window |
| `window` | 60 | Seconds |
| `ban` | 120 | The first ban, seconds |
| `max_ban` | 86400 | |
| `escalation_window` | 86400 | |
| `subnet_limit` | 150 | 0 turns it off |
| `subnet_ban` | 300 | |
| `allow` | `[]` | Addresses and CIDR ranges |
| `bypass_token` | `''` | |
| `store` | `ApcuStore` if APCu is on, else `CacheStore` | See below |
| `client_ip` | `RemoteAddr` | See below |
| `edge` | `[]` | `Fastly`, `Cloudflare` |
| `edge_after` | 3 | |
| `edge_window` | 1800 | |
| `disable` | `false` | |
| `log` | `error_log` | A callable taking the line |

An unknown option is an error, so a typo can't leave a default in place.

## Stores

- `ApcuStore`: the server's memory, shared by its PHP workers and every site
  of a network on them. The fastest; lost on a PHP restart, not shared across
  servers, and not visible to WP-CLI.
- `RedisStore(host, port, password, database, timeout, prefix)`: shared across
  servers. Connects on first use with a 0.5 s timeout. Sites sharing a Redis
  need their own `prefix`, or one site's `flush` empties the others'.
- `CacheStore`: WordPress's object cache when a drop-in makes it persistent,
  else transients. It needs WordPress, so every check waits for
  `plugins_loaded`; transient counts aren't atomic under a burst, and on a
  network they're per site, not shared.

## Client address

- `RemoteAddr`: `REMOTE_ADDR`, where the host already puts the visitor's
  address there and no header can change it (Kinsta, behind its Cloudflare).
- `VerifiedCdn(secret)`: the address Fastly (`Fastly-Client-IP`) or Cloudflare
  (`CF-Connecting-IP`) forwards, only when the request carries the shared
  secret in `X-Origin-Verify` or `X-Origin-Verify-Cloudflare`. Each CDN sets
  its own header, overwriting a client's, so each secret header unlocks only
  its own CDN's address header. Without a match (direct-to-origin traffic, or
  everything while the secret is unset) nothing is limited, so rolling it out
  in any order is safe.

  Fastly VCL, `recv`: `set req.http.X-Origin-Verify = "<secret>";`

Both take `allowPrivate: true` for local development.

## Edge blocklists

```php
use GeneroWP\RateLimiter\ClientIp\VerifiedCdn;
use GeneroWP\RateLimiter\Edge\Cloudflare;
use GeneroWP\RateLimiter\Edge\Fastly;

RateLimiter::boot([
    'client_ip' => new VerifiedCdn((string) env('RATE_LIMIT_ORIGIN_SECRET')),
    'edge' => array_filter([
        env('FASTLY_BLOCKLIST_DICTIONARY_ID') ? new Fastly(env('FASTLY_API_KEY'), env('FASTLY_SERVICE_ID'), env('FASTLY_BLOCKLIST_DICTIONARY_ID')) : null,
        env('CLOUDFLARE_BLOCKLIST_ID') ? new Cloudflare(env('CLOUDFLARE_API_TOKEN'), env('CLOUDFLARE_ACCOUNT_ID'), env('CLOUDFLARE_BLOCKLIST_ID')) : null,
    ]),
]);
```

- `Fastly`: an Edge Dictionary `blocked_ips`, refused in `recv`:
  `if (table.lookup(blocked_ips, client.ip, "0") == "1") { error 403 "Forbidden"; }`
- `Cloudflare`: an account IP list, blocked by a WAF custom rule
  `ip.src in $blocked_ips`. The token needs Account Filter Lists: Edit.

## WP-CLI

```sh
wp rate-limit status <ip>   # its count, bans and subnet
wp rate-limit flush         # empty the store
wp rate-limit block <ip>    # add to the edge blocklists
wp rate-limit unblock <ip>
wp rate-limit blocklist
```

`status` and `flush` see Redis and the object cache; APCu lives in the web
server's memory, which WP-CLI doesn't share.

## Development

```sh
composer install
composer test:unit    # the logic, without WordPress; the APCu and Redis tests where those are set up
npm install
npm run env:start
npm run test:php      # in wp-env: the cache store and the logged-in check
npm run test:e2e      # real requests to wp-env's site
composer lint
composer stan
```
