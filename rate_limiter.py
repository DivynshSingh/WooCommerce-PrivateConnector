import time
import threading
from collections import deque
from typing import Dict, Tuple


class RateLimiter:
    """
    Sliding-window rate limiter per client identifier.
    Tracks timestamps of requests in a sliding window.
    """

    def __init__(self, max_requests: int = 50, window_seconds: int = 10):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._clients: Dict[str, deque] = {}
        self._lock = threading.Lock()

    def check_limit(self, client_id: str) -> Tuple[bool, int]:
        """
        Check if client_id is allowed to make a request.
        Returns:
            (allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        window_start = now - self.window_seconds

        with self._lock:
            # Periodic cleanup of idle clients if dictionary grows
            if len(self._clients) > 1000:
                self._cleanup_idle(window_start)

            if client_id not in self._clients:
                self._clients[client_id] = deque()

            req_times = self._clients[client_id]

            # Evict timestamps older than sliding window
            while req_times and req_times[0] <= window_start:
                req_times.popleft()

            if len(req_times) >= self.max_requests:
                # Exceeded rate limit: calculate retry-after based on oldest timestamp in window
                oldest = req_times[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return False, retry_after

            # Allowed: record request timestamp
            req_times.append(now)
            return True, 0

    def _cleanup_idle(self, cutoff_time: float) -> None:
        """Evict clients with no requests in current window."""
        idle_keys = [k for k, queue in self._clients.items() if not queue or queue[-1] <= cutoff_time]
        for k in idle_keys:
            del self._clients[k]

    def reset_for_test(self) -> None:
        """Helper for unit and integration testing."""
        with self._lock:
            self._clients.clear()
