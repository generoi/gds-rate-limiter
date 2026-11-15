<?php

namespace GeneroWP\RateLimiter\Tests\Unit;

use GeneroWP\RateLimiter\CrawlDelay;
use GeneroWP\RateLimiter\Options;
use PHPUnit\Framework\TestCase;

class CrawlDelayTest extends TestCase
{
    public function test_the_delay_keeps_crawlers_under_the_limit(): void
    {
        $this->assertSame(5, Options::from(['limit' => 20])->crawlDelay);
        $this->assertSame(2, Options::from(['limit' => 45])->crawlDelay);
        $this->assertSame(10, Options::from(['crawl_delay' => 10])->crawlDelay);
        $this->assertSame(0, Options::from(['crawl_delay' => 0])->crawlDelay);
    }

    public function test_the_group_repeats_the_star_rules(): void
    {
        // WordPress core's output with Yoast's sitemap block after it.
        $robots = "User-agent: *\nDisallow: /wp/wp-admin/\nAllow: /wp/wp-admin/admin-ajax.php\n\n"
            ."# START YOAST BLOCK\nSitemap: https://example.com/sitemap_index.xml\n# END YOAST BLOCK\n";

        $out = CrawlDelay::append($robots, 5);

        $this->assertStringStartsWith($robots, $out);
        $group = substr($out, strlen($robots));
        $this->assertStringContainsString("User-agent: ClaudeBot\n", $group);
        $this->assertStringContainsString("Crawl-delay: 5\nDisallow: /wp/wp-admin/\nAllow: /wp/wp-admin/admin-ajax.php\n", $group);
        $this->assertStringNotContainsString('Sitemap', $group);
    }

    public function test_blank_lines_and_comments_do_not_end_the_star_group(): void
    {
        // The SEO Framework prints older filters' lines after a blank line.
        $robots = "User-agent: *\nDisallow: /wp/wp-admin/\n\n# extra\nDisallow: /*?s=\n";

        $this->assertStringContainsString(
            "Crawl-delay: 5\nDisallow: /wp/wp-admin/\nDisallow: /*?s=\n",
            CrawlDelay::append($robots, 5),
        );
    }

    public function test_other_groups_rules_are_not_copied(): void
    {
        $robots = "User-agent: GPTBot\nUser-agent: CCBot\nDisallow: /\n\n"
            ."User-agent: Googlebot\nUser-agent: *\nDisallow: /private/\n\n"
            ."User-agent: Bingbot\nDisallow: /bing-only/\n";

        $out = CrawlDelay::append($robots, 5);
        $group = substr($out, strlen(rtrim($robots, "\n")));

        $this->assertStringContainsString("Crawl-delay: 5\nDisallow: /private/\n", $group);
        $this->assertStringNotContainsString('Disallow: /bing-only/', $group);
        $this->assertStringNotContainsString("Disallow: /\n", $group);
    }

    public function test_a_site_hidden_from_search_engines_stays_hidden(): void
    {
        $this->assertStringContainsString(
            "Crawl-delay: 5\nDisallow: /\n",
            CrawlDelay::append("User-agent: *\nDisallow: /\n", 5),
        );
    }
}
