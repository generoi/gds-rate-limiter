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
5. With `site_limit` set, the requests let through from all IPs together are
   counted too: for a crawl spread over addresses in different networks, each
   under `limit`. Going over `site_limit` in a window starts a surge of
   `surge_for` seconds, during which each IP gets only `surge_limit` a window,
   about what one person browsing makes. Over that is a 429 until the window
   ends, not a ban: no doubling and no edge, so a real visitor caught in a surge
   loses at most a window. Set `site_limit` from the site's own traffic, under
   what its PHP workers can serve; refused requests don't count toward it, so a
   surge ends once the load does.
6. A prefetch the browser starts by itself (`Sec-Purpose: prefetch`, sent for
   WordPress core's speculation rules) never bans: refused, it costs the
   visitor nothing, as the browser loads the page itself on the click. On a
   phone every touch on a link while scrolling a product grid prefetches it,
   so a shopper can make 30–50 uncached requests a minute while clicking a
   few. Prefetches are counted apart, against the same `limit`, so they don't
   take the shopper's next click over; over it a prefetch gets a 429, and
   during a surge every one does. A client that fakes the header on everything
   gets `limit` prefetches a window and 429s after, just no ban.

The 429 has `Retry-After` and `Cache-Control: no-store, private`. A ban logs
one line to the PHP error log when it starts: `[Rate Limit] IP: … | Retry-After: …s | URI: … | Method: … | User-Agent: …`.
The requests refused while it lasts aren't logged one by one (a scanner can
make thousands a day): only the 10th, 100th, 1000th …, as `[Rate Limit] Still
banned: … | refused … times this ban | Retry-After: …s`.
A surge logs once when it starts, `[Rate Limit] Surge: … requests in …s over
the site limit of …; each IP gets … a window for …s`, and not per refusal.
Its count is the request that crossed `site_limit`, so it is always one over:
how big the surge got is in the line its end logs, `[Rate Limit] Surge ended:
peak … requests in …s, refused … requests from … IPs over …s`. That is the
most requests reaching PHP in one window while it lasted, and the requests
(prefetches too) and distinct IPs `surge_limit` refused. Nothing marks a
surge's end but its expiry, so the first request after it logs the line,
however much later. A peak just over `site_limit` with many refused IPs
suggests ordinary traffic tripped it, and `site_limit` is set too low.
Requests crossing at once in several workers start one surge and log each
line once: the start and the end are claimed with an atomic increment, which
APCu, Redis and an object cache have; on transients it's best effort, and a
burst may log a line twice.
Refused prefetches aren't logged.

Never limited: logged-in users (a request with a login cookie waits until
WordPress can check it, then runs first on `plugins_loaded`), REST requests
with a valid application password or WooCommerce key (checked last on
`rest_authentication_errors`, once the REST server has authenticated them;
wrong credentials are counted), `allow`ed addresses and ranges, a
`rate_limit_bypass` cookie equal to `bypass_token`
(for e2e runs against production), WP-CLI, WordPress's own requests to the
site (see below), and private or reserved addresses.
A store that fails lets requests through, and so do options `boot()` can't
read (logged as `[Rate Limit] Not booted: …`).

Counted like any visitor: REST or admin-ajax clients without a login cookie
or valid API credentials (an integration polling the site anonymously may
need an `allow` entry), and WooCommerce shoppers, whose session cookie skips
the page cache.

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
| `site_limit` | 0 | Requests from all IPs per window before a surge; 0 turns surges off |
| `surge_limit` | 6 | Requests per IP per window during a surge |
| `surge_for` | 300 | Seconds a surge lasts |
| `allow` | `[]` | Addresses and CIDR ranges |
| `bypass_token` | `''` | |
| `trust_api_credentials` | `true` | REST requests with a valid application password or WooCommerce key aren't limited; `false` counts them |
| `store` | `ApcuStore` if APCu is on, else `CacheStore` | See below |
| `client_ip` | `RemoteAddr` | See below |
| `edge` | `[]` | `Fastly`, `Cloudflare` |
| `edge_after` | 3 | |
| `edge_window` | 1800 | |
| `crawl_delay` | from `limit` | Seconds robots.txt asks known crawlers to wait; 0 turns it off |
| `disable` | `false` | |
| `log` | `error_log` | A callable taking every line |
| `log_file` | `null` | A file the routine lines are appended to instead of `error_log`; see below |

An unknown option is an error, so a typo can't leave a default in place.

### Log file

On hosts where PHP's error log is the FastCGI stderr stream (Kinsta), every
`error_log` line is recorded by nginx as `FastCGI sent in stderr` at `[error]`
level, and the host's fatal matcher flags it, though nothing is a PHP fatal.
Set `log_file` to a writable path outside the web root, and outside a release
directory if you deploy to `releases/<n>/` (a file inside one is gone with the
next deploy), and the routine lines
(`Surge`, `Surge ended`, `IP`, `Subnet limit`, `Escalated`) go there, one per line with a
timestamp. Failures (`Store error`, `Couldn't add … blocklist`, `Not booted`)
stay on `error_log`, as does everything if the file can't be written. `log`,
when set, takes every line and `log_file` is ignored.

```php
RateLimiter::boot([
    'log_file' => '/path/that/survives/deploys/rate-limit.log',
]);
```

Which directory is writable, and readable for you, is per host and not
verified here: on Kinsta check it before relying on it (the code runs from
`/www/<site>/public/releases/<n>/`, so not beside the code). The file is never
rotated or capped, so rotate it (logrotate, or the host's) on a busy site.

## Crawl delay

Declared crawlers such as ClaudeBot, GPTBot or bingbot rotate IPs, and each
one can go over a low `limit` by itself. So robots.txt asks them (the list is
`CrawlDelay::USER_AGENTS`) to wait `crawl_delay` seconds between requests: by
default enough to keep them at two thirds of `limit`, 5 s at 20 and 2 s at 45.
Googlebot ignores Crawl-delay; Bing and the AI crawlers honour it, so a long
delay slows how fast they pick up new pages.

A crawler follows only the group that names it, so the group repeats the
`User-agent: *` rules. It's added last on WordPress's `robots_txt` filter,
after Yoast or The SEO Framework, so a site's own crawl-delay code should go.
A physical `robots.txt` in the web root bypasses WordPress and this.

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
wp rate-limit token         # the header value for the site's own requests
```

`status` and `flush` see Redis and the object cache; APCu lives in the web
server's memory, which WP-CLI doesn't share.

## Cache warming

[sage-cachetags](https://github.com/generoi/sage-cachetags)' warmer
(`wp cachetags warm`) re-requests purged pages from the server itself. The
mu-plugin adds an `X-Cache-Warm` header to its requests through the
`cachetags/warm/request-headers` filter, carrying `bypass_token` when it's set
and otherwise a token derived from `AUTH_KEY`, so WP-CLI and the web server
agree on it without configuration.

A request with that token isn't counted, by IP or site-wide. While the site is
busy (surging, or past half of `site_limit`) it gets a 429 instead, which makes
the warmer stop its run until the next one. Without a `site_limit` the warmer is
never held back. Nothing else changes: sage-cachetags knows nothing about the
limiter, and a site without the warmer never sends the header.

## The site's own requests

WordPress requests its own site for loopbacks (Site Health, the plugin and
theme editors) and to spawn cron. Those leave through the server's outbound
address, which on Kinsta is shared with other sites and changes, so they're
told apart by a header rather than an `allow` entry: the mu-plugin adds
`X-Rate-Limit-Self` to every `wp_remote_*` request to the site's own host,
with a token derived from `bypass_token` when it's set and otherwise from
`AUTH_KEY`. A request carrying it is never limited.

A script that requests the site from the server can send it too:

```sh
curl -H "X-Rate-Limit-Self: $(wp rate-limit token)" https://example.com/sitemap_index.xml
```

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
