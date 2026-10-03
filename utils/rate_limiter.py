"""
Token-bucket rate limiter for API compliance.
Thread-safe, monotonic-clock based.
"""
import threading
import time


class TokenBucket:
    """
    Simple token bucket for rate limiting HTTP calls.
    rate = tokens per second.
    """

    def __init__(self, rate: float, capacity: int = 1):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens < tokens:
                sleep_needed = (tokens - self.tokens) / self.rate
                time.sleep(sleep_needed)
                self.tokens = 0
                self.last_update = time.monotonic()
            else:
                self.tokens -= tokens
