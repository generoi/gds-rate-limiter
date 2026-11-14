<?php

namespace GeneroWP\RateLimiter\Tests\Support;

use GeneroWP\RateLimiter\Decision;
use GeneroWP\RateLimiter\Responder;

/**
 * Keeps the decisions it would have answered 429 for, without exiting, and
 * runs the work left for after the answer.
 */
final class RecordingResponder extends Responder
{
    /** @var list<Decision> */
    public array $rejected = [];

    public function reject(Decision $decision, ?callable $after = null): void
    {
        $this->rejected[] = $decision;
        if ($after !== null) {
            $after();
        }
    }
}
