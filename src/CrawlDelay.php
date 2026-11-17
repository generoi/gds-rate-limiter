<?php

namespace GeneroWP\RateLimiter;

/**
 * Asks known crawlers in robots.txt to wait between requests, so they stay
 * under the limit instead of collecting 429s. Declared crawlers like ClaudeBot
 * or bingbot rotate IPs, and each one goes over a low `limit` on its own.
 *
 * A crawler follows only the group that names it, so the group repeats the
 * rules of the `User-agent: *` group: these crawlers still keep out of what the
 * site disallows for everyone. It's appended last on WordPress's robots_txt
 * filter, after Yoast or The SEO Framework, so it sees their rules and no loose
 * lines another plugin adds end up under it. A physical robots.txt in the web
 * root bypasses WordPress, and this, altogether.
 */
final class CrawlDelay
{
    /** Declared crawlers that honour Crawl-delay. Googlebot ignores it. */
    public const USER_AGENTS = [
        'AhrefsBot', 'AhrefsSiteAudit', 'DotBot', 'Amazonbot',
        'PetalBot', 'Barkrowler', 'YandexBot', 'Baiduspider',
        'bingbot', 'ClaudeBot', 'SemrushBot', 'MJ12bot',
        'Bytespider', 'OAI-SearchBot', 'GPTBot', 'ChatGPT-User',
        'Qwantbot', 'TikTokSpider', 'PerplexityBot', 'SeznamBot',
        'AwarioBot', 'AwarioRssBot', 'AwarioSmartBot',
        'KeenableBot', 'QlyzeBot', 'SERankingBacklinksBot', 'Claude-SearchBot',
        'Amzn-SearchBot', 'Kimi-SearchBot', 'ExaSearchBot',
    ];

    /**
     * Seconds between requests that keep a crawler at two thirds of `limit`.
     */
    public static function seconds(Options $options): int
    {
        return (int) ceil(1.5 * $options->window / max(1, $options->limit));
    }

    /**
     * $robots with a group for USER_AGENTS appended.
     */
    public static function append(string $robots, int $seconds): string
    {
        $group = '';
        foreach (self::USER_AGENTS as $agent) {
            $group .= "User-agent: {$agent}\n";
        }
        $group .= "Crawl-delay: {$seconds}\n";
        foreach (self::starRules($robots) as $rule) {
            $group .= "{$rule}\n";
        }

        return rtrim($robots, "\n")."\n\n".$group;
    }

    /**
     * The Allow and Disallow lines of the groups that include `User-agent: *`.
     * A group is its run of User-agent lines and every rule until the next
     * User-agent line; blank lines and comments don't end it.
     *
     * @return list<string>
     */
    private static function starRules(string $robots): array
    {
        $rules = [];
        $inStar = false;
        $readingAgents = false;
        foreach (preg_split('/\R/', $robots) ?: [] as $line) {
            $line = trim((string) preg_replace('/#.*/', '', $line));
            if (! preg_match('/^([a-z-]+)\s*:\s*(.*)$/i', $line, $m)) {
                continue;
            }
            $field = strtolower($m[1]);
            if ($field === 'user-agent') {
                // A User-agent line after rules starts a new group.
                if (! $readingAgents) {
                    $inStar = false;
                }
                $readingAgents = true;
                $inStar = $inStar || trim($m[2]) === '*';

                continue;
            }
            $readingAgents = false;
            if ($inStar && ($field === 'allow' || $field === 'disallow')) {
                $rules[] = rtrim(ucfirst($field).': '.trim($m[2]));
            }
        }

        return $rules;
    }
}
