import { execFileSync } from 'node:child_process';
import { expect, test, type APIRequestContext } from '@playwright/test';

/**
 * Real requests to wp-env's site, booted with a limit of 5 a minute and the
 * cache store (tests/e2e/mu-plugin.php): what a visitor, a logged-in user and
 * an e2e run with the bypass cookie get.
 */
test.describe.configure({ mode: 'serial' });

function wp(...args: string[]): string {
    return execFileSync('npx', ['wp-env', 'run', 'cli', 'wp', ...args], { encoding: 'utf8' });
}

test.beforeEach(() => {
    wp('rate-limit', 'flush');
});

async function statuses(request: APIRequestContext, n: number, headers: Record<string, string> = {}): Promise<number[]> {
    const out: number[] = [];
    for (let i = 0; i < n; i++) {
        out.push((await request.get('/?p=1', { headers, maxRedirects: 0 })).status());
    }
    return out;
}

test('the request over the limit gets a 429 that is never cached', async ({ request }) => {
    expect(await statuses(request, 5)).toEqual([200, 200, 200, 200, 200]);

    const refused = await request.get('/?p=1');
    expect(refused.status()).toBe(429);
    expect(refused.headers()['retry-after']).toBe('30');
    expect(refused.headers()['cache-control']).toContain('no-store');
    expect(await refused.text()).toBe('Rate limit exceeded. Please retry after 30 seconds.');

    // Banned: the next one too, until `wp rate-limit flush`.
    expect((await request.get('/?p=1')).status()).toBe(429);
    wp('rate-limit', 'flush');
    expect((await request.get('/?p=1')).status()).toBe(200);
});

test('the bypass cookie is never limited', async ({ request }) => {
    expect(await statuses(request, 10, { Cookie: 'rate_limit_bypass=e2e-bypass' })).not.toContain(429);
});

test('a logged-in user is never limited', async ({ request }) => {
    const login = await request.post('/wp-login.php', {
        form: { log: 'admin', pwd: 'password', 'wp-submit': 'Log In', testcookie: '1' },
        headers: { Cookie: 'wordpress_test_cookie=WP%20Cookie%20check' },
        maxRedirects: 0,
    });
    expect(login.status()).toBe(302);

    expect(await statuses(request, 10)).not.toContain(429);
});

test('a login cookie that is not a logged-in user is counted', async ({ request }) => {
    const statusesSeen = await statuses(request, 6, { Cookie: 'wordpress_logged_in_x=forged' });

    expect(statusesSeen).toEqual([200, 200, 200, 200, 200, 429]);
});
