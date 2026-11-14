<?php

namespace GeneroWP\RateLimiter;

/**
 * Validating, grouping and matching client addresses.
 */
final class Ip
{
    /**
     * A usable client IP, or null: the first of a comma list, and not a
     * private or reserved address (loopback cron, health checks) unless
     * $allowPrivate, for local development where those are all there is.
     */
    public static function normalize(string $value, bool $allowPrivate = false): ?string
    {
        if ($value === '' || strlen($value) > 200) {
            return null;
        }
        $value = trim(explode(',', $value)[0]);

        $flags = $allowPrivate ? 0 : FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
        if (filter_var($value, FILTER_VALIDATE_IP, $flags) === false) {
            return null;
        }
        // One spelling per address: an IPv6 written two ways is one client.
        $packed = @inet_pton($value);

        return $packed === false ? null : (string) inet_ntop($packed);
    }

    /**
     * The network a crawl spread over many addresses shares: /24 for IPv4,
     * /64 for IPv6.
     */
    public static function subnet(string $ip): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $octets = explode('.', $ip);

            return "net4:{$octets[0]}.{$octets[1]}.{$octets[2]}";
        }
        $packed = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? @inet_pton($ip) : false;

        return $packed === false ? null : 'net6:'.bin2hex(substr($packed, 0, 8));
    }

    /**
     * Whether $ip is one of $list: addresses or CIDR ranges, IPv4 or IPv6.
     *
     * @param  list<string>  $list
     */
    public static function matches(string $ip, array $list): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }

        foreach ($list as $entry) {
            [$network, $bits] = array_pad(explode('/', trim($entry), 2), 2, null);
            $net = @inet_pton((string) $network);
            if ($net === false || strlen($net) !== strlen($packed)) {
                continue;
            }
            $bits = $bits === null ? strlen($packed) * 8 : max(0, min((int) $bits, strlen($packed) * 8));
            $bytes = intdiv($bits, 8);
            if (substr($packed, 0, $bytes) !== substr($net, 0, $bytes)) {
                continue;
            }
            $rest = $bits % 8;
            if ($rest === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $rest)) & 0xFF;
            if ((ord($packed[$bytes]) & $mask) === (ord($net[$bytes]) & $mask)) {
                return true;
            }
        }

        return false;
    }
}
