import unittest

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.rate_limit import RateLimitExceeded, RateLimitPolicy, SlidingWindowRateLimiter


class Clock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class RateLimitTests(unittest.TestCase):
    def test_limit_and_window(self):
        clock = Clock()
        limiter = SlidingWindowRateLimiter(RateLimitPolicy(limit=2, window_seconds=10), clock=clock)
        limiter.check("tool")
        limiter.check("tool")
        with self.assertRaises(RateLimitExceeded):
            limiter.check("tool")
        clock.value = 11
        limiter.check("tool")

    def test_key_cardinality_is_bounded(self):
        clock = Clock()
        limiter = SlidingWindowRateLimiter(RateLimitPolicy(limit=1, window_seconds=10, max_keys=2), clock=clock)
        limiter.check("a")
        clock.value = 1
        limiter.check("b")
        clock.value = 2
        limiter.check("c")
        self.assertLessEqual(len(limiter._events), 2)


if __name__ == "__main__":
    unittest.main()
